"""DNS abuse detectors: tunneling/exfiltration and reconnaissance-style misuse."""

from ProtocolAnalyzer import shannon_entropy

from .base import Detector, TimedCounter, TimedSet


def encoded_label_run(qname, zone, min_len, min_entropy):
    """Labels ahead of the zone that look like encoded payload.

    Splitting a payload across several medium-length labels keeps every one
    of them under an "oversized label" threshold while carrying just as much
    data — iodine and dnscat both do it. Returns (count, total_length).
    """
    labels = [l for l in (qname or '').split('.') if l]
    zone_labels = len([l for l in (zone or '').split('.') if l])
    if zone_labels:
        labels = labels[:-zone_labels]
    encoded = [l for l in labels
               if len(l) >= min_len
               and shannon_entropy(l.encode('ascii', 'ignore')) >= min_entropy]
    return len(encoded), sum(len(l) for l in encoded)


def registrable_zone(qname):
    """Best-effort 'domain.tld' for grouping queries by zone.

    Deliberately simple — no public-suffix list — because grouping only needs
    to be consistent, not registry-accurate.
    """
    parts = [p for p in (qname or '').split('.') if p]
    return '.'.join(parts[-2:]) if len(parts) >= 2 else (qname or '')


class DNSTunnelDetector(Detector):
    """DNS used as a data channel.

    Requires corroboration: a long, high-entropy label is suggestive, but the
    alert only fires when the encoding evidence is strong or the query volume
    to one zone is also abnormal. That keeps CDN and antivirus hostnames —
    which are legitimately long and random-looking — from alerting.
    """

    name = 'dns_tunnel'
    threat_type = 'dns_tunnel'
    description = ('Oversized high-entropy DNS labels, payload-bearing record '
                   'types, and elevated query volume to a single zone')
    techniques = ('T1071.004', 'T1048')

    def __init__(self, cfg):
        super().__init__(cfg)
        self._zone_queries = TimedCounter(cfg['window_s'])
        self._zone_bytes = TimedCounter(cfg['window_s'])

    def inspect(self, pkt):
        if pkt.get('protocol') != 'DNS' or pkt.get('dns_qr') != 0:
            return []
        qname = pkt.get('dns_qname')
        if not qname:
            return []
        self.packets_seen += 1
        ts = pkt['ts']
        zone = registrable_zone(qname)
        volume = self._zone_queries.add((pkt['src_ip'], zone), ts)

        max_label = pkt.get('dns_max_label_len', 0)
        entropy = pkt.get('dns_qname_entropy', 0.0)
        qtype = pkt.get('dns_qtype')

        # An oversized label is a necessary condition: tunneling has to stuff
        # payload into the name, and there is nowhere else to put it. Without
        # this gate, ordinary CDN hostnames — which are long, numerous and
        # random-looking — score highly on entropy and volume alone.
        oversized = max_label >= self.cfg['min_label_len']
        run_count, run_total = encoded_label_run(
            qname, zone, self.cfg.get('min_encoded_label_len', 12),
            self.cfg.get('min_encoded_label_entropy', 3.2))
        multi_label = (
            self.cfg.get('min_encoded_labels', 0)
            and run_count >= self.cfg['min_encoded_labels']
            and run_total >= self.cfg.get('min_encoded_total_len', 45))
        if self.cfg.get('require_oversized_label', True) \
                and not (oversized or multi_label):
            return []

        signals, score = [], 0.0
        if oversized:
            signals.append('label of %d chars' % max_label)
            score += 0.35
        elif multi_label:
            signals.append('%d encoded labels totalling %d chars'
                           % (run_count, run_total))
            score += 0.35
        if entropy >= self.cfg['min_entropy']:
            signals.append('encoded-label entropy %.2f bits/byte' % entropy)
            score += 0.35
        if len(qname) >= self.cfg['min_qname_len']:
            signals.append('qname length %d' % len(qname))
            score += 0.15
        if qtype in self.cfg['suspicious_qtypes']:
            signals.append('%s record (high payload capacity)'
                           % pkt.get('dns_qtype_name', qtype))
            score += 0.25
        if volume >= self.cfg['query_volume']:
            signals.append('%d queries to %s in %ds'
                           % (volume, zone, self.cfg['window_s']))
            score += 0.3

        # Independent corroborating signals: one alone is too weak.
        if (score < self.cfg.get('min_score', 0.6)
                or len(signals) < self.cfg.get('min_signals', 2)):
            return []
        if not self._cooled_down((pkt['src_ip'], zone), ts):
            return []

        severity = 'CRITICAL' if score >= 1.0 else 'HIGH'
        return [self._finding(
            pkt, severity, min(0.97, 0.55 + score * 0.35),
            'DNS tunneling indicators from %s to zone %s — %s'
            % (pkt['src_ip'], zone, '; '.join(signals)),
            ('T1071.004', 'T1048'),
            zone=zone, qname=qname[:200], max_label_len=max_label,
            entropy=entropy, qtype=pkt.get('dns_qtype_name'),
            query_volume=volume, signals=signals, score=round(score, 2),
            encoded_labels=run_count, encoded_total_len=run_total,
        )]

    def expire(self, now):
        super().expire(now)
        self._zone_queries.expire(now)
        self._zone_bytes.expire(now)


class SuspiciousDNSDetector(Detector):
    """NXDOMAIN storms and algorithmically-generated domain lookups.

    Malware resolving DGA domains produces a burst of failed lookups for
    random-looking names — distinct from tunneling, which succeeds.
    """

    name = 'suspicious_dns'
    threat_type = 'suspicious_dns'
    description = ('High NXDOMAIN response ratio and repeated lookups of '
                   'high-entropy algorithmically-generated names')
    techniques = ('T1071.004',)

    def __init__(self, cfg):
        super().__init__(cfg)
        self._nxdomain = TimedCounter(cfg['window_s'])
        self._responses = TimedCounter(cfg['window_s'])
        self._dga_names = TimedSet(cfg['window_s'])

    def inspect(self, pkt):
        if pkt.get('protocol') != 'DNS':
            return []
        self.packets_seen += 1
        ts = pkt['ts']
        findings = []

        # NXDOMAIN accounting keys on the client, which is the response's
        # destination.
        if pkt.get('dns_qr') == 1:
            client = pkt.get('dst_ip')
            total = self._responses.add(client, ts)
            if pkt.get('dns_rcode') == 3:
                nx = self._nxdomain.add(client, ts)
                ratio = nx / total if total else 0.0
                if (nx >= self.cfg['nxdomain_count']
                        and ratio >= self.cfg['nxdomain_ratio']
                        and self._cooled_down(('nx', client), ts)):
                    findings.append(self._finding(
                        pkt, 'HIGH', min(0.93, 0.55 + ratio * 0.4),
                        '%s received %d NXDOMAIN responses (%.0f%% of %d '
                        'lookups) in %ds — consistent with DGA resolution'
                        % (client, nx, ratio * 100, total,
                           self.cfg['window_s']),
                        ('T1071.004',),
                        pattern='nxdomain_storm', nxdomain_count=nx,
                        total_responses=total, nxdomain_ratio=round(ratio, 3),
                        window_s=self.cfg['window_s'],
                    ))
            return findings

        qname = pkt.get('dns_qname')
        if not qname:
            return findings
        labels = [l for l in qname.split('.') if l]
        if len(labels) < 2:
            return findings
        sld = labels[-2]
        if len(sld) < self.cfg['dga_min_len']:
            return findings
        entropy = shannon_entropy(sld.encode('ascii', 'ignore'))
        if entropy < self.cfg['dga_entropy']:
            return findings

        n = self._dga_names.add(pkt['src_ip'], registrable_zone(qname), ts)
        if n >= self.cfg['dga_count'] and self._cooled_down(
                ('dga', pkt['src_ip']), ts):
            findings.append(self._finding(
                pkt, 'MEDIUM', min(0.9, 0.5 + n / 40.0),
                '%s queried %d distinct high-entropy domains in %ds '
                '(e.g. %s, entropy %.2f) — DGA-like naming'
                % (pkt['src_ip'], n, self.cfg['window_s'], qname[:80],
                   entropy),
                ('T1071.004',),
                pattern='dga_lookup', distinct_domains=n,
                sample_domains=self._dga_names.members(pkt['src_ip'])[:10],
                sld_entropy=entropy, window_s=self.cfg['window_s'],
            ))
        return findings

    def expire(self, now):
        super().expire(now)
        self._nxdomain.expire(now)
        self._responses.expire(now)
        self._dga_names.expire(now)
