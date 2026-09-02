"""
BatchWriter — the persistence stage's write path.

Everything here exists because the ORM's unit-of-work is the wrong tool for an
append-only firehose. Flushing one mapped object per packet costs an INSERT
round trip per row; at 10k packets/sec that is 10k round trips/sec and the
pipeline stalls behind the network, not behind PostgreSQL. So the models are
declared with the ORM (they give us migrations, constraints and typed reads)
and written through SQLAlchemy Core plus psycopg's binary ``COPY``.

One batch is one transaction, in this order:

  1. upsert hosts, in a single statement that both resolves surrogate IDs and
     folds this batch's counters in — RETURNING gives us the id map we need
     before any child row can be written
  2. COPY the packets
  3. upsert flows on the 5-tuple unique constraint
  4. upsert the per-minute protocol rollup
  5. insert alerts (RETURNING ids), their technique links, and the host
     threat-score updates they imply

If any step raises, the whole batch rolls back and the pipeline counts the
packets as failed rather than silently losing them: `packets_failed` is part
of the accounting identity the soak test asserts.
"""

import json
import logging
import time
from collections import defaultdict

from sqlalchemy import text

from netwatch import geoip
from netwatch.db import schema as schema_mod

log = logging.getLogger('netwatch.db.writer')

# Severity -> threat-score increment applied to the alerting host.
SCORE_WEIGHT = {'CRITICAL': 10.0, 'HIGH': 6.0, 'MEDIUM': 3.0, 'LOW': 1.0,
                'INFO': 0.0}

_HOST_UPSERT = text("""
INSERT INTO hosts (ip, first_seen, last_seen, is_internal, country,
                   latitude, longitude, packets_sent, packets_recv,
                   bytes_sent, bytes_recv)
SELECT * FROM unnest(
    CAST(:ips AS inet[]), CAST(:first_seen AS timestamptz[]),
    CAST(:last_seen AS timestamptz[]), CAST(:internal AS boolean[]),
    CAST(:country AS varchar[]), CAST(:lat AS double precision[]),
    CAST(:lon AS double precision[]), CAST(:sent AS bigint[]),
    CAST(:recv AS bigint[]), CAST(:bsent AS bigint[]),
    CAST(:brecv AS bigint[]))
ON CONFLICT (ip) DO UPDATE SET
    first_seen   = LEAST(hosts.first_seen, EXCLUDED.first_seen),
    last_seen    = GREATEST(hosts.last_seen, EXCLUDED.last_seen),
    packets_sent = hosts.packets_sent + EXCLUDED.packets_sent,
    packets_recv = hosts.packets_recv + EXCLUDED.packets_recv,
    bytes_sent   = hosts.bytes_sent + EXCLUDED.bytes_sent,
    bytes_recv   = hosts.bytes_recv + EXCLUDED.bytes_recv
RETURNING id, host(ip) AS ip
""")

_FLOW_UPSERT = text("""
INSERT INTO flows (src_host_id, dst_host_id, src_port, dst_port, protocol_id,
                   first_seen, last_seen, packets, bytes, flags_seen, state)
SELECT * FROM unnest(
    CAST(:src AS bigint[]), CAST(:dst AS bigint[]), CAST(:sport AS integer[]),
    CAST(:dport AS integer[]), CAST(:proto AS smallint[]),
    CAST(:first_seen AS timestamptz[]), CAST(:last_seen AS timestamptz[]),
    CAST(:packets AS bigint[]), CAST(:bytes AS bigint[]),
    CAST(:flags AS varchar[]), CAST(:state AS varchar[]))
ON CONFLICT ON CONSTRAINT uq_flow_tuple DO UPDATE SET
    first_seen = LEAST(flows.first_seen, EXCLUDED.first_seen),
    last_seen  = GREATEST(flows.last_seen, EXCLUDED.last_seen),
    packets    = flows.packets + EXCLUDED.packets,
    bytes      = flows.bytes + EXCLUDED.bytes,
    flags_seen = EXCLUDED.flags_seen
""")

_PSTAT_UPSERT = text("""
INSERT INTO protocol_stats (bucket, protocol_id, packets, bytes, alerts)
SELECT * FROM unnest(
    CAST(:bucket AS timestamptz[]), CAST(:proto AS smallint[]),
    CAST(:packets AS bigint[]), CAST(:bytes AS bigint[]),
    CAST(:alerts AS bigint[]))
ON CONFLICT (bucket, protocol_id) DO UPDATE SET
    packets = protocol_stats.packets + EXCLUDED.packets,
    bytes   = protocol_stats.bytes + EXCLUDED.bytes,
    alerts  = protocol_stats.alerts + EXCLUDED.alerts
""")

_HOST_SCORE_UPDATE = text("""
UPDATE hosts SET
    alert_count  = hosts.alert_count + v.n,
    threat_score = LEAST(100.0, hosts.threat_score + v.score)
FROM (SELECT * FROM unnest(CAST(:ids AS bigint[]), CAST(:n AS integer[]),
                           CAST(:score AS double precision[]))
        AS t(id, n, score)) AS v
WHERE hosts.id = v.id
""")

_PACKET_COLUMNS = ('ts', 'src_host_id', 'dst_host_id', 'src_port', 'dst_port',
                   'protocol_id', 'frame_len', 'payload_len', 'tcp_flags',
                   'entropy', 'is_malicious', 'l7')

# Application-layer field prefixes worth keeping in the packet's JSONB blob.
_L7_PREFIXES = ('dns_', 'http_', 'tls_', 'ssh_', 'ftp_', 'smtp_', 'pop3_',
                'imap_', 'snmp_', 'ntp_', 'smb_', 'rdp_', 'dhcp_', 'quic_',
                'arp_', 'telnet_', 'icmp_')


def l7_summary(pkt):
    """Compact dict of decoded application-layer fields, or None."""
    out = {}
    for key, value in pkt.items():
        if key.startswith(_L7_PREFIXES) and (
                value is None or isinstance(value, (str, int, float, bool))):
            out[key] = value
    return out or None


class BatchWriter:
    """Writes parsed packets and findings to PostgreSQL in batches.

    Not thread-safe by design: the persistence stage gives each writer thread
    its own instance so they never contend on the host-id cache, and each
    takes its own pooled connection.
    """

    #: Cap on the in-process ip -> host_id cache. A pipeline that has seen
    #: hundreds of thousands of distinct addresses must not hold them all.
    CACHE_LIMIT = 50_000

    def __init__(self, engine, protocol_ids=None, threat_type_ids=None):
        self.engine = engine
        if protocol_ids is None or threat_type_ids is None:
            protocol_ids, threat_type_ids = schema_mod.lookup_maps(engine)
        self.protocol_ids = protocol_ids
        self.threat_type_ids = threat_type_ids
        self._unknown_protocol = protocol_ids.get('UNKNOWN')
        self._host_ids = {}
        self._geo = {}
        self.batches_written = 0
        self.packets_written = 0
        self.alerts_written = 0
        self.write_seconds = 0.0

    # ── helpers ──────────────────────────────────────────────────────────────

    def _protocol_id(self, name):
        pid = self.protocol_ids.get(name)
        return pid if pid is not None else self._unknown_protocol

    def _threat_type_id(self, name):
        tid = self.threat_type_ids.get(name)
        if tid is None:
            # A detector emitting a threat type absent from the seeded catalog
            # is a bug, not a data condition — surface it rather than writing
            # a NULL FK and failing the whole batch on a constraint.
            raise KeyError('threat type %r is not in the threat_types catalog'
                           % name)
        return tid

    def _geo_lookup(self, ip):
        hit = self._geo.get(ip)
        if hit is None:
            hit = self._geo[ip] = geoip.lookup(ip)
            if len(self._geo) > self.CACHE_LIMIT:
                self._geo.clear()
        return hit

    # ── the write path ───────────────────────────────────────────────────────

    def write_batch(self, packets, findings):
        """Persist one batch atomically. Returns (packet_rows, alert_rows).

        `packets` is a list of parsed-packet dicts, `findings` a list of
        Finding objects produced by the rules stage for those same packets.
        """
        if not packets and not findings:
            return 0, 0
        started = time.perf_counter()
        malicious = {f.src_ip for f in findings if f.src_ip}

        with self.engine.begin() as conn:
            host_ids = self._upsert_hosts(conn, packets, findings)
            if packets:
                self._copy_packets(conn, packets, host_ids, malicious)
                self._upsert_flows(conn, packets, host_ids)
                self._upsert_protocol_stats(conn, packets, findings)
            n_alerts = self._insert_alerts(conn, findings, host_ids)

        self.batches_written += 1
        self.packets_written += len(packets)
        self.alerts_written += n_alerts
        self.write_seconds += time.perf_counter() - started
        return len(packets), n_alerts

    def _upsert_hosts(self, conn, packets, findings):
        """Fold this batch's per-host counters in and return an ip -> id map.

        One statement does both jobs. Splitting them would mean a SELECT to
        resolve IDs plus an UPDATE to apply counters — two round trips and a
        race between them.
        """
        agg = {}
        for pkt in packets:
            ts = pkt['dt']
            length = pkt.get('frame_len', 0)
            src, dst = pkt.get('src_ip'), pkt.get('dst_ip')
            if src:
                row = agg.get(src)
                if row is None:
                    row = agg[src] = [ts, ts, 0, 0, 0, 0]
                elif ts < row[0]:
                    row[0] = ts
                elif ts > row[1]:
                    row[1] = ts
                row[2] += 1
                row[4] += length
            if dst:
                row = agg.get(dst)
                if row is None:
                    row = agg[dst] = [ts, ts, 0, 0, 0, 0]
                elif ts < row[0]:
                    row[0] = ts
                elif ts > row[1]:
                    row[1] = ts
                row[3] += 1
                row[5] += length
        # An alert can name a host no packet in this batch mentioned (a
        # detector attributing behaviour to the other end of a flow), so its
        # addresses have to be resolvable too.
        for finding in findings:
            for ip in (finding.src_ip, finding.dst_ip):
                if ip and ip not in agg:
                    when = finding.dt
                    agg[ip] = [when, when, 0, 0, 0, 0]

        if not agg:
            return {}

        ips = list(agg)
        cols = list(zip(*(agg[ip] for ip in ips)))
        geo = [self._geo_lookup(ip) for ip in ips]
        rows = conn.execute(_HOST_UPSERT, {
            'ips': ips,
            'first_seen': list(cols[0]), 'last_seen': list(cols[1]),
            'internal': [g[0] == 'PRIVATE' for g in geo],
            'country': [g[0] for g in geo],
            'lat': [g[1] for g in geo], 'lon': [g[2] for g in geo],
            'sent': list(cols[2]), 'recv': list(cols[3]),
            'bsent': list(cols[4]), 'brecv': list(cols[5]),
        }).all()
        return {ip: hid for hid, ip in rows}

    def _copy_packets(self, conn, packets, host_ids, malicious):
        """Bulk-load the packet rows with COPY ... FROM STDIN.

        COPY is roughly an order of magnitude cheaper than multi-row INSERT
        here: one statement, one parse, no per-row parameter binding, and the
        server skips the executor entirely.
        """
        proto_id = self._protocol_id
        raw = conn.connection.driver_connection
        stmt = 'COPY packets (%s) FROM STDIN' % ', '.join(_PACKET_COLUMNS)
        with raw.cursor() as cur, cur.copy(stmt) as copy:
            copy.set_types(['timestamptz', 'int8', 'int8', 'int4', 'int4',
                            'int2', 'int4', 'int4', 'varchar', 'float8',
                            'bool', 'jsonb'])
            for pkt in packets:
                src, dst = pkt.get('src_ip'), pkt.get('dst_ip')
                summary = l7_summary(pkt)
                copy.write_row((
                    pkt['dt'],
                    host_ids.get(src), host_ids.get(dst),
                    pkt.get('src_port'), pkt.get('dst_port'),
                    proto_id(pkt.get('protocol', 'UNKNOWN')),
                    pkt.get('frame_len', 0), pkt.get('payload_len', 0),
                    pkt.get('flags') or None,
                    pkt.get('entropy', 0.0) or 0.0,
                    src in malicious,
                    json.dumps(summary, separators=(',', ':'))
                    if summary else None,
                ))

    def _upsert_flows(self, conn, packets, host_ids):
        flows = {}
        for pkt in packets:
            src_id = host_ids.get(pkt.get('src_ip'))
            dst_id = host_ids.get(pkt.get('dst_ip'))
            if src_id is None or dst_id is None:
                continue
            key = (src_id, dst_id, pkt.get('src_port') or 0,
                   pkt.get('dst_port') or 0,
                   self._protocol_id(pkt.get('protocol', 'UNKNOWN')))
            ts = pkt['dt']
            row = flows.get(key)
            if row is None:
                flows[key] = [ts, ts, 1, pkt.get('frame_len', 0),
                              {pkt.get('flags')} - {None, ''}]
            else:
                if ts < row[0]:
                    row[0] = ts
                elif ts > row[1]:
                    row[1] = ts
                row[2] += 1
                row[3] += pkt.get('frame_len', 0)
                if pkt.get('flags'):
                    row[4].add(pkt['flags'])
        if not flows:
            return
        keys = list(flows)
        vals = [flows[k] for k in keys]
        conn.execute(_FLOW_UPSERT, {
            'src': [k[0] for k in keys], 'dst': [k[1] for k in keys],
            'sport': [k[2] for k in keys], 'dport': [k[3] for k in keys],
            'proto': [k[4] for k in keys],
            'first_seen': [v[0] for v in vals],
            'last_seen': [v[1] for v in vals],
            'packets': [v[2] for v in vals], 'bytes': [v[3] for v in vals],
            'flags': [','.join(sorted(v[4]))[:64] for v in vals],
            'state': ['ACTIVE'] * len(keys),
        })

    def _upsert_protocol_stats(self, conn, packets, findings):
        buckets = defaultdict(lambda: [0, 0, 0])
        for pkt in packets:
            key = (pkt['minute'], self._protocol_id(
                pkt.get('protocol', 'UNKNOWN')))
            row = buckets[key]
            row[0] += 1
            row[1] += pkt.get('frame_len', 0)
        for finding in findings:
            key = (finding.dt.replace(second=0, microsecond=0),
                   self._protocol_id(finding.protocol or 'UNKNOWN'))
            buckets[key][2] += 1
        keys = list(buckets)
        conn.execute(_PSTAT_UPSERT, {
            'bucket': [k[0] for k in keys], 'proto': [k[1] for k in keys],
            'packets': [buckets[k][0] for k in keys],
            'bytes': [buckets[k][1] for k in keys],
            'alerts': [buckets[k][2] for k in keys],
        })

    def _insert_alerts(self, conn, findings, host_ids):
        if not findings:
            return 0
        rows = []
        for f in findings:
            rows.append({
                'ts': f.dt, 'severity': f.severity,
                'threat_type_id': self._threat_type_id(f.threat_type),
                'src_host_id': host_ids.get(f.src_ip),
                'dst_host_id': host_ids.get(f.dst_ip),
                'src_port': f.src_port, 'dst_port': f.dst_port,
                'protocol_id': (self._protocol_id(f.protocol)
                                if f.protocol else None),
                'confidence': f.confidence, 'description': f.reason,
                'evidence': json.dumps(f.evidence, default=str,
                                       separators=(',', ':')),
            })
        alert_ids = self._insert_many(conn, rows)

        links = []
        for alert_id, f in zip(alert_ids, findings):
            for tid in f.techniques:
                links.append({'alert_id': alert_id, 'technique_id': tid,
                              'confidence': f.confidence, 'ts': f.dt})
        if links:
            conn.execute(text("""
                INSERT INTO alert_techniques (alert_id, technique_id,
                                              confidence, ts)
                VALUES (:alert_id, :technique_id, :confidence, :ts)
                ON CONFLICT DO NOTHING
            """), links)

        scores = defaultdict(lambda: [0, 0.0])
        for f in findings:
            hid = host_ids.get(f.src_ip)
            if hid is None:
                continue
            entry = scores[hid]
            entry[0] += 1
            entry[1] += SCORE_WEIGHT[f.severity]
        if scores:
            ids = list(scores)
            conn.execute(_HOST_SCORE_UPDATE, {
                'ids': ids,
                'n': [scores[i][0] for i in ids],
                'score': [scores[i][1] for i in ids],
            })
        return len(alert_ids)

    @staticmethod
    def _insert_many(conn, rows):
        """Multi-row INSERT ... RETURNING, so alert IDs come back in order.

        executemany cannot return generated keys per row on every driver, and
        alert IDs are needed immediately to write the technique links.
        """
        values, params = [], {}
        for i, row in enumerate(rows):
            values.append(
                '(:ts%d, CAST(:sev%d AS severity_level), :tt%d, :sh%d, :dh%d,'
                ' :sp%d, :dp%d, :pr%d, :cf%d, :ds%d, CAST(:ev%d AS jsonb))'
                % ((i,) * 11))
            params.update({
                'ts%d' % i: row['ts'], 'sev%d' % i: row['severity'],
                'tt%d' % i: row['threat_type_id'],
                'sh%d' % i: row['src_host_id'],
                'dh%d' % i: row['dst_host_id'],
                'sp%d' % i: row['src_port'], 'dp%d' % i: row['dst_port'],
                'pr%d' % i: row['protocol_id'], 'cf%d' % i: row['confidence'],
                'ds%d' % i: row['description'], 'ev%d' % i: row['evidence'],
            })
        sql = ("""INSERT INTO alerts (ts, severity, threat_type_id,
                      src_host_id, dst_host_id, src_port, dst_port,
                      protocol_id, confidence, description, evidence)
                  VALUES %s RETURNING id""" % ', '.join(values))
        return conn.execute(text(sql), params).scalars().all()

    def stats(self):
        return {
            'batches_written': self.batches_written,
            'packets_written': self.packets_written,
            'alerts_written': self.alerts_written,
            'write_seconds': round(self.write_seconds, 4),
            'mean_batch_ms': round(
                self.write_seconds / self.batches_written * 1000, 3)
            if self.batches_written else 0.0,
            'host_cache_entries': len(self._host_ids),
        }
