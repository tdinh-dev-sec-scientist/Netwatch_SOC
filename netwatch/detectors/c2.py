"""Command-and-control channel detectors."""

import math

from .base import Detector, TimedCounter


class C2BeaconDetector(Detector):
    """Periodic callbacks with low timing jitter.

    Human-driven and application traffic is bursty; implant check-ins are
    metronomic. The discriminator is the coefficient of variation of the
    inter-arrival times on one (src, dst, dport) channel.
    """

    name = 'c2_beacon'
    threat_type = 'c2_beacon'
    description = ('Low-jitter periodic callbacks on a single channel, scored '
                   'by coefficient of variation of inter-arrival times')
    techniques = ('T1071.001',)
    default_severity = 'CRITICAL'
    protocols = ('HTTP', 'TLS', 'QUIC', 'TCP')

    def __init__(self, cfg):
        super().__init__(cfg)
        self._channels = TimedCounter(cfg['window_s'])

    def inspect(self, pkt):
        if pkt.get('protocol') not in ('HTTP', 'TLS', 'QUIC', 'TCP'):
            return []
        dport = pkt.get('dst_port')
        if dport is None:
            return []
        # Only count session-initiating packets, otherwise every data packet
        # inside one transfer looks like a separate callback.
        flags = pkt.get('flags', '')
        if pkt.get('protocol') == 'TCP' and flags != 'SYN':
            return []
        self.packets_seen += 1
        ts = pkt['ts']
        key = (pkt['src_ip'], pkt['dst_ip'], dport)
        count = self._channels.add(key, ts)
        if count < self.cfg['min_callbacks']:
            return []

        stamps = list(self._channels.timestamps(key))
        intervals = [b - a for a, b in zip(stamps, stamps[1:])]
        if len(intervals) < self.cfg['min_callbacks'] - 1:
            return []

        mean = sum(intervals) / len(intervals)
        if not (self.cfg['min_interval_s'] <= mean <= self.cfg['max_interval_s']):
            return []
        variance = sum((i - mean) ** 2 for i in intervals) / len(intervals)
        stddev = math.sqrt(variance)
        jitter = stddev / mean if mean else 1.0
        if jitter > self.cfg['max_jitter_ratio']:
            return []
        if not self._cooled_down(key, ts):
            return []

        # Tighter periodicity over more samples means higher confidence.
        confidence = min(0.97, 0.7 + (self.cfg['max_jitter_ratio'] - jitter)
                         * 1.5 + len(intervals) / 200.0)
        severity = 'CRITICAL' if jitter < 0.05 else 'HIGH'
        return [self._finding(
            pkt, severity, confidence,
            'Beaconing from %s to %s:%d — %d callbacks averaging %.1fs '
            'with %.1f%% jitter'
            % (pkt['src_ip'], pkt['dst_ip'], dport, count, mean, jitter * 100),
            ('T1071.001',),
            callbacks=count, mean_interval_s=round(mean, 2),
            stddev_s=round(stddev, 3), jitter_ratio=round(jitter, 4),
            destination='%s:%d' % (pkt['dst_ip'], dport),
        )]

    def expire(self, now):
        super().expire(now)
        self._channels.expire(now)


class TLSAnomalyDetector(Detector):
    """Obsolete TLS versions, missing SNI and unusually narrow cipher lists.

    Each on its own is weak evidence, so they are scored together and only an
    accumulated score raises an alert.
    """

    name = 'tls_anomaly'
    threat_type = 'tls_anomaly'
    description = ('Deprecated TLS versions, absent SNI, or abnormally small '
                   'cipher suite lists in the ClientHello')
    techniques = ('T1573',)
    default_severity = 'HIGH'
    protocols = ('TLS',)

    def inspect(self, pkt):
        if pkt.get('protocol') != 'TLS':
            return []
        # Only a ClientHello carries the fields we score.
        if pkt.get('tls_handshake_type') != 1:
            return []
        self.packets_seen += 1
        ts = pkt['ts']
        reasons = []
        score = 0.0

        version = pkt.get('tls_client_version') or pkt.get('tls_version')
        if version in self.cfg['obsolete_versions']:
            reasons.append('obsolete protocol version %s' % version)
            score += 0.5

        if pkt.get('tls_has_sni') is False:
            reasons.append('no SNI extension (destination not declared)')
            score += 0.3

        ciphers = pkt.get('tls_cipher_count')
        if ciphers is not None and ciphers < self.cfg['min_cipher_count']:
            reasons.append('only %d cipher suite(s) offered — atypical for a '
                           'browser' % ciphers)
            score += 0.3

        if score < 0.5:
            return []
        key = (pkt['src_ip'], pkt['dst_ip'], pkt.get('dst_port'))
        if not self._cooled_down(key, ts):
            return []

        severity = 'HIGH' if score >= 0.8 else 'MEDIUM'
        return [self._finding(
            pkt, severity, min(0.93, 0.5 + score * 0.4),
            'Anomalous TLS ClientHello from %s to %s:%s — %s'
            % (pkt['src_ip'], pkt['dst_ip'], pkt.get('dst_port'),
               '; '.join(reasons)),
            ('T1573',),
            tls_version=version, cipher_count=ciphers,
            has_sni=pkt.get('tls_has_sni'), sni=pkt.get('tls_sni'),
            anomalies=reasons, score=round(score, 2),
        )]
