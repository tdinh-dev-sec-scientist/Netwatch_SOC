"""
Repository — every read the REST API performs.

Two deliberate choices.

**Dynamic filters are built with SQLAlchemy Core, fixed aggregates with
``text()``.** Where a query's shape depends on which filters the caller sent,
composing ``select()`` is both safer and clearer than string-building. Where
the SQL is fixed — a GROUP BY rollup, a coverage matrix — the literal
statement is easier to read, easier to paste into ``EXPLAIN ANALYZE``, and
easier to keep honest against the index it was written for. Neither path ever
interpolates caller input; sort keys and orders are resolved against
allow-lists to fixed column objects before they reach SQL.

**Rows come back denormalized.** The schema stores ``src_host_id``; the API
returns ``src_ip``. Callers should not have to know about surrogate keys, and
the join that resolves them is exactly what the composite indexes exist to
make cheap.
"""

import datetime as dt
import decimal
import time

from sqlalchemy import Integer, and_, desc, func, select, text, update

from netwatch.db.models import (
    TABLES,
    Alert,
    AlertTechnique,
    Flow,
    Host,
    MitreTechnique,
    Packet,
    PipelineRun,
    Protocol,
    ProtocolStat,
    ThreatType,
)

UTC = dt.UTC


def _dt(epoch):
    return dt.datetime.fromtimestamp(epoch, UTC)


def _epoch(value):
    return value.timestamp() if isinstance(value, dt.datetime) else value


def _row(mapping):
    """Turn a Row into a plain dict, converting datetimes to epoch floats.

    The dashboard's charts and the detectors both speak epoch seconds; ISO
    strings are added alongside rather than instead, so a human reading the
    JSON does not have to convert in their head.
    """
    out = {}
    for key, value in mapping.items():
        if isinstance(value, dt.datetime):
            out[key] = value.timestamp()
            out[key + '_iso'] = value.isoformat()
        elif isinstance(value, decimal.Decimal):
            # SUM() over bigint returns numeric, which Flask serialises as a
            # string. Callers doing arithmetic on a count should not have to
            # know that.
            out[key] = int(value) if value == value.to_integral_value() \
                else float(value)
        else:
            out[key] = value
    return out


def _rows(result):
    return [_row(r) for r in result.mappings()]


#: Sort keys the alert list accepts, mapped to real columns. An allow-list,
#: not string interpolation — an unknown key is a 400, never a SQL fragment.
ALERT_SORTS = {'ts': Alert.ts, 'severity': Alert.severity,
               'confidence': Alert.confidence, 'id': Alert.id}
PACKET_SORTS = {'ts': Packet.ts, 'frame_len': Packet.frame_len,
                'entropy': Packet.entropy, 'id': Packet.id}
FLOW_SORTS = {'last_seen': Flow.last_seen, 'first_seen': Flow.first_seen,
              'bytes': Flow.bytes, 'packets': Flow.packets}
HOST_SORTS = {'packets_sent': Host.packets_sent,
              'packets_recv': Host.packets_recv,
              'bytes_sent': Host.bytes_sent, 'bytes_recv': Host.bytes_recv,
              'threat_score': Host.threat_score,
              'alert_count': Host.alert_count, 'last_seen': Host.last_seen}


class Repository:
    """Read-side data access. One instance per application, thread-safe.

    Holds no connection of its own: every call borrows one from the engine's
    pool for the duration of the query and returns it. That is what lets the
    API serve concurrent requests without either a connection per request or
    a lock around a shared one.
    """

    def __init__(self, engine):
        self.engine = engine

    # ── helpers ──────────────────────────────────────────────────────────────

    def _all(self, stmt, params=None):
        with self.engine.connect() as conn:
            return _rows(conn.execute(stmt, params or {}))

    def _one(self, stmt, params=None):
        with self.engine.connect() as conn:
            row = conn.execute(stmt, params or {}).mappings().first()
        return _row(row) if row else None

    def _scalar(self, stmt, params=None, default=0):
        with self.engine.connect() as conn:
            value = conn.execute(stmt, params or {}).scalar()
        return default if value is None else value

    @staticmethod
    def _page(rows, total, limit, offset):
        """The pagination envelope every collection endpoint returns."""
        return {
            'total': total,
            'count': len(rows),
            'limit': limit,
            'offset': offset,
            'has_more': offset + len(rows) < total,
            'next_offset': (offset + limit) if offset + len(rows) < total
            else None,
        }

    def _count(self, conn, stmt):
        return conn.execute(
            select(func.count()).select_from(stmt.subquery())).scalar() or 0

    # ── health / introspection ───────────────────────────────────────────────

    def health(self):
        started = time.perf_counter()
        counts = {}
        with self.engine.connect() as conn:
            for table in TABLES:
                counts[table] = conn.execute(
                    text('SELECT COUNT(*) FROM "%s"' % table)).scalar()
            version = conn.execute(text('SHOW server_version')).scalar()
            db_size = conn.execute(text(
                'SELECT pg_database_size(current_database())')).scalar()
            index_count = conn.execute(text(
                "SELECT COUNT(*) FROM pg_indexes WHERE schemaname = "
                "current_schema()")).scalar()
            sync = conn.execute(text('SHOW synchronous_commit')).scalar()
        pool = self.engine.pool
        return {
            'status': 'ok',
            'database': 'postgresql',
            'server_version': version,
            'db_size_bytes': db_size,
            'synchronous_commit': sync,
            'tables': counts,
            'table_count': len(counts),
            'index_count': index_count,
            'count_query_ms': round((time.perf_counter() - started) * 1000, 3),
            'pool': {
                'size': getattr(pool, 'size', lambda: None)(),
                'checked_out': getattr(pool, 'checkedout', lambda: None)(),
                'overflow': getattr(pool, 'overflow', lambda: None)(),
            },
        }

    # ── aggregate statistics ─────────────────────────────────────────────────

    #: The dashboard header needs "how many packets have we seen", and an
    #: exact COUNT(*) over the packets table is a full scan that gets slower
    #: every minute the pipeline runs — it measured at hundreds of
    #: milliseconds on a million rows and was the single slowest thing the API
    #: did. The answer is already maintained exactly, in `protocol_stats`:
    #: every batch writes its per-minute rollup in the same transaction as the
    #: packets themselves, so summing that table is the same number read from
    #: a few dozen rows instead of a few million. That is what the rollup is
    #: for, and it is why the counter is exact rather than estimated.
    _OVERVIEW_SQL = text("""
        SELECT
          (SELECT COALESCE(SUM(packets), 0) FROM protocol_stats)
                                                            AS total_packets,
          (SELECT COALESCE(SUM(packets), 0) FROM protocol_stats
             WHERE bucket > :hour)                          AS packets_last_hour,
          (SELECT COALESCE(AVG(pm), 0) FROM (
              SELECT SUM(packets) AS pm FROM protocol_stats
              WHERE bucket > :ten_min GROUP BY bucket) s)   AS packets_per_min,
          (SELECT COUNT(*) FROM alerts)                     AS total_alerts,
          (SELECT COUNT(*) FROM alerts WHERE ts > :day)     AS alerts_24h,
          (SELECT COUNT(*) FROM alerts
             WHERE severity = 'CRITICAL' AND NOT acknowledged)
                                                            AS critical_open,
          (SELECT COUNT(*) FROM alerts WHERE NOT acknowledged)
                                                            AS unacknowledged,
          (SELECT COUNT(*) FROM threat_types tt WHERE EXISTS (
              SELECT 1 FROM alerts a WHERE a.threat_type_id = tt.id))
                                                            AS distinct_threat_types,
          (SELECT COUNT(*) FROM mitre_techniques t WHERE EXISTS (
              SELECT 1 FROM alert_techniques at
               WHERE at.technique_id = t.technique_id))
                                                            AS techniques_observed,
          (SELECT COUNT(*) FROM hosts)                      AS hosts_tracked,
          (SELECT COUNT(*) FROM flows WHERE last_seen > :five_min)
                                                            AS active_flows,
          (SELECT COALESCE(AVG(confidence), 0) FROM alerts WHERE ts > :day)
                                                            AS mean_confidence
    """)

    def get_overview(self):
        """The dashboard header, in one round trip.

        Previously twelve separate scalar queries, each with its own round
        trip and its own scan. Folding them into correlated subqueries in a
        single statement lets PostgreSQL plan them together and cuts the
        network cost by a factor of twelve. `COUNT(DISTINCT ...)` over the
        alert and technique-link tables became `EXISTS` probes against the
        small catalog tables, which is the same answer read from the other
        side of the join — seventeen index probes instead of a scan of every
        alert.
        """
        now = time.time()
        row = self._one(self._OVERVIEW_SQL, {
            'hour': _dt(now - 3600), 'day': _dt(now - 86400),
            'ten_min': _dt(now - 600), 'five_min': _dt(now - 300)})
        # SUM() over a bigint column comes back as Decimal, which is not
        # JSON-serialisable; the rest are already ints.
        row['packets_per_min'] = round(float(row['packets_per_min']), 1)
        row['mean_confidence'] = round(float(row['mean_confidence']), 3)
        return row

    def get_throughput(self, minutes=60):
        stmt = (select(ProtocolStat.bucket.label('bucket'),
                       func.sum(ProtocolStat.packets).label('packets'),
                       func.sum(ProtocolStat.bytes).label('bytes'),
                       func.sum(ProtocolStat.alerts).label('alerts'))
                .where(ProtocolStat.bucket > _dt(time.time() - minutes * 60))
                .group_by(ProtocolStat.bucket)
                .order_by(ProtocolStat.bucket))
        return self._all(stmt)

    def get_protocol_distribution(self, minutes=1440):
        stmt = (select(Protocol.name.label('protocol'),
                       func.sum(ProtocolStat.packets).label('packets'),
                       func.sum(ProtocolStat.bytes).label('bytes'),
                       func.sum(ProtocolStat.alerts).label('alerts'))
                .join(Protocol, Protocol.id == ProtocolStat.protocol_id)
                .where(ProtocolStat.bucket > _dt(time.time() - minutes * 60))
                .group_by(Protocol.name)
                .order_by(desc('packets')))
        return self._all(stmt)

    def get_severity_breakdown(self, hours=24):
        stmt = (select(Alert.severity, func.count().label('count'),
                       func.avg(Alert.confidence).label('avg_conf'))
                .where(Alert.ts > _dt(time.time() - hours * 3600))
                .group_by(Alert.severity))
        return self._all(stmt)

    def get_alert_timeline(self, hours=24, bucket_s=3600):
        # to_timestamp(floor(epoch/bucket)*bucket) buckets on an arbitrary
        # width; date_trunc would only give fixed calendar units.
        stmt = text("""
            SELECT to_timestamp(FLOOR(EXTRACT(EPOCH FROM ts) / :b) * :b)
                       AS bucket,
                   severity, COUNT(*) AS count
            FROM alerts
            WHERE ts > :cutoff
            GROUP BY bucket, severity
            ORDER BY bucket""")
        return self._all(stmt, {'b': bucket_s,
                                'cutoff': _dt(time.time() - hours * 3600)})

    # ── alerts ───────────────────────────────────────────────────────────────

    def _alert_select(self):
        src = Host.__table__.alias('src')
        dst = Host.__table__.alias('dst')
        return (select(
            Alert.id, Alert.ts, Alert.severity,
            ThreatType.name.label('threat_type'),
            ThreatType.detector.label('detector'),
            func.host(src.c.ip).label('src_ip'),
            func.host(dst.c.ip).label('dst_ip'),
            Alert.src_port, Alert.dst_port,
            Protocol.name.label('protocol'),
            Alert.confidence, Alert.description, Alert.evidence,
            Alert.acknowledged, Alert.ack_ts)
            .join(ThreatType, ThreatType.id == Alert.threat_type_id)
            .outerjoin(src, src.c.id == Alert.src_host_id)
            .outerjoin(dst, dst.c.id == Alert.dst_host_id)
            .outerjoin(Protocol, Protocol.id == Alert.protocol_id))

    def get_alerts(self, limit=50, offset=0, severity=None, threat_type=None,
                   src_ip=None, dst_ip=None, acknowledged=None, since=None,
                   until=None, min_confidence=None, sort='ts', order='desc'):
        where = []
        if severity:
            where.append(Alert.severity == severity)
        if threat_type:
            where.append(Alert.threat_type_id == select(ThreatType.id)
                         .where(ThreatType.name == threat_type).scalar_subquery())
        if src_ip:
            where.append(Alert.src_host_id == select(Host.id)
                         .where(Host.ip == src_ip).scalar_subquery())
        if dst_ip:
            where.append(Alert.dst_host_id == select(Host.id)
                         .where(Host.ip == dst_ip).scalar_subquery())
        if acknowledged is not None:
            where.append(Alert.acknowledged.is_(bool(acknowledged)))
        if since is not None:
            where.append(Alert.ts > _dt(since))
        if until is not None:
            where.append(Alert.ts <= _dt(until))
        if min_confidence is not None:
            where.append(Alert.confidence >= min_confidence)

        column = ALERT_SORTS[sort]
        ordering = desc(column) if order == 'desc' else column
        stmt = self._alert_select().where(*where).order_by(
            ordering, desc(Alert.id)).limit(limit).offset(offset)
        count_stmt = select(func.count()).select_from(Alert).where(*where)

        with self.engine.connect() as conn:
            total = conn.execute(count_stmt).scalar() or 0
            rows = _rows(conn.execute(stmt))
        return {**self._page(rows, total, limit, offset), 'alerts': rows}

    def get_alert(self, alert_id):
        alert = self._one(self._alert_select().where(Alert.id == alert_id))
        if alert is None:
            return None
        alert['techniques'] = self._all(
            select(MitreTechnique.technique_id, MitreTechnique.name,
                   MitreTechnique.tactic, MitreTechnique.url,
                   MitreTechnique.rationale, AlertTechnique.confidence)
            .join(AlertTechnique,
                  AlertTechnique.technique_id == MitreTechnique.technique_id)
            .where(AlertTechnique.alert_id == alert_id))
        # Packets from the same source around the alert, for context.
        alert['related_packets'] = self._all(text("""
            SELECT p.id, p.ts, host(sh.ip) AS src_ip, host(dh.ip) AS dst_ip,
                   p.src_port, p.dst_port, pr.name AS protocol, p.frame_len,
                   p.tcp_flags, p.l7
            FROM packets p
            JOIN hosts sh ON sh.id = p.src_host_id
            JOIN hosts dh ON dh.id = p.dst_host_id
            JOIN protocols pr ON pr.id = p.protocol_id
            WHERE p.src_host_id = (SELECT id FROM hosts WHERE ip = :ip)
              AND p.ts BETWEEN :lo AND :hi
            ORDER BY p.ts DESC LIMIT 20"""),
            {'ip': alert['src_ip'], 'lo': _dt(alert['ts'] - 60),
             'hi': _dt(alert['ts'] + 5)}) if alert['src_ip'] else []
        return alert

    def acknowledge_alert(self, alert_id, acknowledged=True):
        with self.engine.begin() as conn:
            result = conn.execute(
                update(Alert).where(Alert.id == alert_id).values(
                    acknowledged=acknowledged,
                    ack_ts=_dt(time.time()) if acknowledged else None))
        return result.rowcount

    def acknowledge_alerts(self, alert_ids, acknowledged=True):
        """Bulk acknowledge. One statement, not one per id."""
        if not alert_ids:
            return 0
        with self.engine.begin() as conn:
            result = conn.execute(
                update(Alert).where(Alert.id.in_(list(alert_ids))).values(
                    acknowledged=acknowledged,
                    ack_ts=_dt(time.time()) if acknowledged else None))
        return result.rowcount

    def get_alert_stats_by_type(self, hours=24):
        stmt = (select(
            ThreatType.name.label('threat_type'),
            ThreatType.detector, func.count().label('count'),
            func.avg(Alert.confidence).label('avg_conf'),
            func.sum((Alert.severity == 'CRITICAL').cast(Integer))
            .label('critical'),
            func.sum((Alert.severity == 'HIGH').cast(Integer)).label('high'),
            func.max(Alert.ts).label('last_seen'))
            .join(ThreatType, ThreatType.id == Alert.threat_type_id)
            .where(Alert.ts > _dt(time.time() - hours * 3600))
            .group_by(ThreatType.name, ThreatType.detector)
            .order_by(desc('count')))
        return self._all(stmt)

    def get_threat_summary(self, hours=24, limit=50):
        """Active threats: alerts aggregated by (source host, threat type).

        Derived rather than stored — materialising it would be a denormalised
        copy of rows `alerts` already holds. `ix_alerts_ts_src_type` is what
        makes the window restrict the scan before the grouping happens.
        """
        return self._all(text("""
            SELECT host(h.ip) AS src_ip, tt.name AS threat_type,
                   COUNT(*) AS alert_count,
                   MIN(a.ts) AS first_seen, MAX(a.ts) AS last_seen,
                   MAX(a.confidence) AS max_confidence,
                   COUNT(*) FILTER (WHERE NOT a.acknowledged) AS open_alerts,
                   MIN(CASE a.severity WHEN 'CRITICAL' THEN 0
                                       WHEN 'HIGH' THEN 1
                                       WHEN 'MEDIUM' THEN 2
                                       WHEN 'LOW' THEN 3 ELSE 4 END)
                       AS sev_rank
            FROM alerts a
            JOIN threat_types tt ON tt.id = a.threat_type_id
            JOIN hosts h ON h.id = a.src_host_id
            WHERE a.ts > :cutoff
            GROUP BY h.ip, tt.name
            ORDER BY sev_rank ASC, alert_count DESC
            LIMIT :limit"""),
            {'cutoff': _dt(time.time() - hours * 3600), 'limit': limit})

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────

    def get_mitre_techniques(self, hours=None):
        cutoff = _dt(time.time() - hours * 3600) if hours else None
        join_cond = AlertTechnique.technique_id == MitreTechnique.technique_id
        if cutoff is not None:
            join_cond = and_(join_cond, AlertTechnique.ts > cutoff)
        stmt = (select(
            MitreTechnique.technique_id, MitreTechnique.name,
            MitreTechnique.tactic, MitreTechnique.url,
            MitreTechnique.rationale,
            func.count(AlertTechnique.alert_id).label('alert_count'),
            func.avg(AlertTechnique.confidence).label('avg_confidence'),
            func.max(AlertTechnique.ts).label('last_seen'))
            .outerjoin(AlertTechnique, join_cond)
            .group_by(MitreTechnique.technique_id)
            .order_by(desc('alert_count'), MitreTechnique.technique_id))
        return self._all(stmt)

    def get_mitre_technique(self, technique_id, limit=25):
        tech = self._one(select(MitreTechnique).where(
            MitreTechnique.technique_id == technique_id))
        if tech is None:
            return None
        tech['alert_count'] = self._scalar(
            select(func.count()).select_from(AlertTechnique)
            .where(AlertTechnique.technique_id == technique_id))
        tech['detectors'] = self._all(
            select(ThreatType.detector, ThreatType.name.label('threat_type'),
                   func.count().label('count'))
            .select_from(AlertTechnique)
            .join(Alert, Alert.id == AlertTechnique.alert_id)
            .join(ThreatType, ThreatType.id == Alert.threat_type_id)
            .where(AlertTechnique.technique_id == technique_id)
            .group_by(ThreatType.detector, ThreatType.name)
            .order_by(desc('count')))
        tech['recent_alerts'] = self._all(
            self._alert_select()
            .join(AlertTechnique, AlertTechnique.alert_id == Alert.id)
            .where(AlertTechnique.technique_id == technique_id)
            .order_by(desc(Alert.ts)).limit(limit))
        return tech

    def get_mitre_coverage(self):
        rows = self._all(
            select(MitreTechnique.tactic, MitreTechnique.technique_id,
                   MitreTechnique.name,
                   func.count(AlertTechnique.alert_id).label('alert_count'))
            .outerjoin(AlertTechnique,
                       AlertTechnique.technique_id
                       == MitreTechnique.technique_id)
            .group_by(MitreTechnique.technique_id)
            .order_by(MitreTechnique.tactic, MitreTechnique.technique_id))
        by_tactic = {}
        for row in rows:
            by_tactic.setdefault(row['tactic'], []).append(row)
        return [
            {'tactic': tactic, 'techniques': techs,
             'total_alerts': sum(t['alert_count'] for t in techs),
             'observed': sum(1 for t in techs if t['alert_count'] > 0),
             'catalogued': len(techs)}
            for tactic, techs in sorted(by_tactic.items())
        ]

    # ── hosts ────────────────────────────────────────────────────────────────

    def get_hosts(self, limit=25, offset=0, order='packets_sent',
                  country=None, internal=None, min_threat_score=None):
        where = []
        if country:
            where.append(Host.country == country)
        if internal is not None:
            where.append(Host.is_internal.is_(bool(internal)))
        if min_threat_score is not None:
            where.append(Host.threat_score >= min_threat_score)
        stmt = (select(func.host(Host.ip).label('ip'), Host.first_seen,
                       Host.last_seen, Host.is_internal, Host.country,
                       Host.latitude, Host.longitude, Host.packets_sent,
                       Host.packets_recv, Host.bytes_sent, Host.bytes_recv,
                       Host.alert_count, Host.threat_score)
                .where(*where)
                .order_by(desc(HOST_SORTS[order]))
                .limit(limit).offset(offset))
        with self.engine.connect() as conn:
            total = conn.execute(
                select(func.count()).select_from(Host).where(*where)).scalar()
            rows = _rows(conn.execute(stmt))
        return {**self._page(rows, total or 0, limit, offset), 'hosts': rows}

    def get_host(self, ip):
        host = self._one(
            select(func.host(Host.ip).label('ip'), Host.id, Host.first_seen,
                   Host.last_seen, Host.is_internal, Host.country,
                   Host.latitude, Host.longitude, Host.packets_sent,
                   Host.packets_recv, Host.bytes_sent, Host.bytes_recv,
                   Host.alert_count, Host.threat_score).where(Host.ip == ip))
        if host is None:
            return None
        host_id = host.pop('id')
        # Covered by ix_packets_src_proto_len: the aggregate never touches the
        # heap, which is the difference between a few ms and a few hundred.
        host['top_protocols'] = self._all(
            select(Protocol.name.label('protocol'),
                   func.count().label('packets'),
                   func.sum(Packet.frame_len).label('bytes'))
            .join(Protocol, Protocol.id == Packet.protocol_id)
            .where(Packet.src_host_id == host_id)
            .group_by(Protocol.name).order_by(desc('packets')).limit(10))
        host['recent_alerts'] = self._all(
            self._alert_select().where(Alert.src_host_id == host_id)
            .order_by(desc(Alert.ts)).limit(20))
        host['top_peers'] = self._all(
            select(func.host(Host.ip).label('peer'),
                   func.sum(Flow.packets).label('packets'),
                   func.sum(Flow.bytes).label('bytes'))
            .join(Host, Host.id == Flow.dst_host_id)
            .where(Flow.src_host_id == host_id)
            .group_by(Host.ip).order_by(desc('bytes')).limit(10))
        return host

    def get_geo_distribution(self):
        stmt = (select(Host.country, func.count().label('hosts'),
                       func.sum(Host.packets_sent).label('packets'),
                       func.sum(Host.bytes_sent).label('bytes'),
                       func.sum(Host.alert_count).label('alerts'),
                       func.avg(Host.latitude).label('latitude'),
                       func.avg(Host.longitude).label('longitude'))
                .where(Host.country != 'PRIVATE')
                .group_by(Host.country).order_by(desc('packets')))
        return self._all(stmt)

    # ── raw telemetry ────────────────────────────────────────────────────────

    def get_flows(self, limit=50, offset=0, order='last_seen', src_ip=None,
                  dst_ip=None, protocol=None, min_bytes=None):
        src = Host.__table__.alias('src')
        dst = Host.__table__.alias('dst')
        where = []
        if src_ip:
            where.append(src.c.ip == src_ip)
        if dst_ip:
            where.append(dst.c.ip == dst_ip)
        if protocol:
            where.append(Protocol.name == protocol)
        if min_bytes is not None:
            where.append(Flow.bytes >= min_bytes)
        base = (select(Flow.id, func.host(src.c.ip).label('src_ip'),
                       func.host(dst.c.ip).label('dst_ip'), Flow.src_port,
                       Flow.dst_port, Protocol.name.label('protocol'),
                       Flow.first_seen, Flow.last_seen, Flow.packets,
                       Flow.bytes, Flow.flags_seen, Flow.state)
                .join(src, src.c.id == Flow.src_host_id)
                .join(dst, dst.c.id == Flow.dst_host_id)
                .join(Protocol, Protocol.id == Flow.protocol_id)
                .where(*where))
        stmt = base.order_by(desc(FLOW_SORTS[order])).limit(limit).offset(offset)
        with self.engine.connect() as conn:
            total = self._count(conn, base)
            rows = _rows(conn.execute(stmt))
        return {**self._page(rows, total, limit, offset), 'flows': rows}

    def get_packets(self, limit=100, offset=0, protocol=None, src_ip=None,
                    dst_ip=None, malicious_only=False, since=None, until=None,
                    min_entropy=None, sort='ts', order='desc'):
        src = Host.__table__.alias('src')
        dst = Host.__table__.alias('dst')
        where = []
        if protocol:
            where.append(Packet.protocol_id == select(Protocol.id)
                         .where(Protocol.name == protocol).scalar_subquery())
        if src_ip:
            where.append(Packet.src_host_id == select(Host.id)
                         .where(Host.ip == src_ip).scalar_subquery())
        if dst_ip:
            where.append(Packet.dst_host_id == select(Host.id)
                         .where(Host.ip == dst_ip).scalar_subquery())
        if malicious_only:
            where.append(Packet.is_malicious.is_(True))
        if since is not None:
            where.append(Packet.ts > _dt(since))
        if until is not None:
            where.append(Packet.ts <= _dt(until))
        if min_entropy is not None:
            where.append(Packet.entropy >= min_entropy)

        column = PACKET_SORTS[sort]
        ordering = desc(column) if order == 'desc' else column
        stmt = (select(Packet.id, Packet.ts, func.host(src.c.ip).label('src_ip'),
                       func.host(dst.c.ip).label('dst_ip'), Packet.src_port,
                       Packet.dst_port, Protocol.name.label('protocol'),
                       Packet.frame_len, Packet.payload_len, Packet.tcp_flags,
                       Packet.entropy, Packet.is_malicious,
                       Packet.l7.label('l7'))
                .join(src, src.c.id == Packet.src_host_id)
                .join(dst, dst.c.id == Packet.dst_host_id)
                .join(Protocol, Protocol.id == Packet.protocol_id)
                .where(*where).order_by(ordering).limit(limit).offset(offset))
        count_stmt = select(func.count()).select_from(Packet).where(*where)
        with self.engine.connect() as conn:
            total = conn.execute(count_stmt).scalar() or 0
            rows = _rows(conn.execute(stmt))
        for row in rows:
            row['l7'] = row.get('l7') or {}
        return {**self._page(rows, total, limit, offset), 'packets': rows}

    # ── catalogs ─────────────────────────────────────────────────────────────

    def get_protocol_catalog(self):
        return self._all(
            select(Protocol.name.label('protocol'), Protocol.layer,
                   Protocol.risk, Protocol.is_encrypted,
                   func.coalesce(func.sum(ProtocolStat.packets), 0)
                   .label('packets_seen'))
            .outerjoin(ProtocolStat, ProtocolStat.protocol_id == Protocol.id)
            .group_by(Protocol.id).order_by(desc('packets_seen'),
                                            Protocol.name))

    def get_threat_types(self):
        return self._all(
            select(ThreatType.name.label('threat_type'), ThreatType.detector,
                   ThreatType.default_severity, ThreatType.description,
                   func.count(Alert.id).label('alert_count'),
                   func.avg(Alert.confidence).label('avg_confidence'),
                   func.max(Alert.ts).label('last_seen'))
            .outerjoin(Alert, Alert.threat_type_id == ThreatType.id)
            .group_by(ThreatType.id)
            .order_by(desc('alert_count'), ThreatType.name))

    # ── pipeline telemetry ───────────────────────────────────────────────────

    def record_pipeline_run(self, metrics):
        payload = {
            'source': 'engine', 'window_s': 0.0, 'packets_received': 0,
            'packets_parsed': 0, 'packets_persisted': 0, 'packets_dropped': 0,
            'packets_failed': 0, 'alerts_generated': 0, 'packets_per_s': 0.0,
            'latency_p50_ms': 0.0, 'latency_p95_ms': 0.0,
            'latency_p99_ms': 0.0, 'peak_rss_mb': 0.0, 'cpu_percent': 0.0,
            'stage_json': None, **metrics,
        }
        payload['window_s'] = max(payload['window_s'], 1e-6)
        with self.engine.begin() as conn:
            return conn.execute(
                PipelineRun.__table__.insert().returning(PipelineRun.id),
                payload).scalar()

    def get_pipeline_runs(self, limit=50, offset=0, source=None):
        where = [PipelineRun.source == source] if source else []
        stmt = (select(PipelineRun).where(*where)
                .order_by(desc(PipelineRun.ts)).limit(limit).offset(offset))
        with self.engine.connect() as conn:
            total = conn.execute(select(func.count()).select_from(PipelineRun)
                                 .where(*where)).scalar() or 0
            rows = _rows(conn.execute(stmt))
        return {**self._page(rows, total, limit, offset), 'runs': rows}

    # ── plan inspection (used by tests and the query benchmark) ──────────────

    def explain(self, stmt, params=None, analyze=False):
        """Return the planner's output for `stmt` as a list of text lines."""
        prefix = 'EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) ' if analyze \
            else 'EXPLAIN '
        if not isinstance(stmt, str):
            compiled = stmt.compile(
                self.engine, compile_kwargs={'literal_binds': True})
            stmt = str(compiled)
        with self.engine.connect() as conn:
            return [r[0] for r in conn.execute(text(prefix + stmt),
                                               params or {})]
