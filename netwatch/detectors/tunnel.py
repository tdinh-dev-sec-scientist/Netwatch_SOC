"""Protocol tunneling detectors: covert channels inside carrier protocols."""

from .base import Detector, TimedCounter


class ICMPTunnelDetector(Detector):
    """Data smuggled inside ICMP echo payloads.

    A normal ping carries a small, low-entropy, highly repetitive payload
    (often an incrementing byte pattern). Tunneled data is large and looks
    random.
    """

    name = 'icmp_tunnel'
    threat_type = 'icmp_tunnel'
    description = ('Oversized, high-entropy ICMP echo payloads repeated '
                   'between the same pair of hosts')
    techniques = ('T1572', 'T1048')
    default_severity = 'HIGH'
    protocols = ('ICMP',)

    def __init__(self, cfg):
        super().__init__(cfg)
        self._pairs = TimedCounter(cfg['window_s'])
        self._bytes = TimedCounter(cfg['window_s'])

    def inspect(self, pkt):
        if pkt.get('protocol') != 'ICMP':
            return []
        if pkt.get('icmp_type') not in (0, 8):
            return []
        payload_len = pkt.get('icmp_payload_len', 0)
        if payload_len < self.cfg['min_payload_len']:
            return []
        entropy = pkt.get('entropy', 0.0)
        if entropy < self.cfg['min_entropy']:
            return []
        self.packets_seen += 1
        ts = pkt['ts']

        key = (pkt['src_ip'], pkt['dst_ip'])
        count = self._pairs.add(key, ts)
        if count < self.cfg['volume']:
            return []
        if not self._cooled_down(key, ts):
            return []

        return [self._finding(
            pkt, 'HIGH', min(0.95, 0.6 + entropy / 20.0 + count / 200.0),
            'ICMP tunneling from %s to %s — %d echo packets carrying %d-byte '
            'payloads at %.2f bits/byte entropy (normal ping: 32-56 bytes, '
            'low entropy)'
            % (pkt['src_ip'], pkt['dst_ip'], count, payload_len, entropy),
            ('T1572', 'T1048'),
            payload_len=payload_len, entropy=entropy, packet_count=count,
            icmp_type=pkt.get('icmp_type'), window_s=self.cfg['window_s'],
        )]

    def expire(self, now):
        super().expire(now)
        self._pairs.expire(now)
        self._bytes.expire(now)


class ProtocolTunnelDetector(Detector):
    """A known L7 protocol positively identified on a non-standard port.

    The analyzer identifies protocols by signature, so this fires when the
    signature and the port disagree — e.g. SSH on 443 to slip past egress
    filtering.
    """

    name = 'protocol_tunnel'
    threat_type = 'protocol_tunnel'
    description = ('L7 protocol identified by byte signature on a port '
                   'normally reserved for a different protocol')
    techniques = ('T1572',)
    default_severity = 'MEDIUM'

    def __init__(self, cfg):
        super().__init__(cfg)
        self._seen = TimedCounter(cfg['window_s'])

    def inspect(self, pkt):
        if not pkt.get('nonstandard_port'):
            return []
        self.packets_seen += 1
        ts = pkt['ts']
        proto = pkt.get('protocol')
        dport = pkt.get('dst_port')
        key = (pkt['src_ip'], pkt['dst_ip'], dport, proto)
        count = self._seen.add(key, ts)
        if count < self.cfg['observations']:
            return []
        if not self._cooled_down(key, ts):
            return []

        return [self._finding(
            pkt, 'MEDIUM', min(0.92, 0.6 + count / 50.0),
            '%s traffic identified by signature on port %s between %s and %s '
            '(%d observations) — protocol/port mismatch suggests tunneling '
            'around egress controls'
            % (proto, dport, pkt['src_ip'], pkt['dst_ip'], count),
            ('T1572',),
            identified_protocol=proto, observed_port=dport,
            observations=count, window_s=self.cfg['window_s'],
        )]

    def expire(self, now):
        super().expire(now)
        self._seen.expire(now)
