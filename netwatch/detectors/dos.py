"""Denial-of-service and reflection/amplification detectors."""

from .base import Detector, TimedCounter, TimedSum


class SYNFloodDetector(Detector):
    """Half-open TCP connection flood against a destination service.

    Volume alone is not enough — a busy web server sees plenty of SYNs. The
    discriminator is the ratio of SYNs to completed handshakes: in a flood the
    SYN-ACKs are never acknowledged, so ACKs stay near zero.
    """

    name = 'syn_flood'
    threat_type = 'syn_flood'
    description = ('High SYN rate to one destination with an abnormally low '
                   'proportion of completed handshakes')
    techniques = ('T1498',)
    default_severity = 'CRITICAL'
    protocols = ('TCP', 'HTTP', 'TLS', 'SSH', 'SMB', 'RDP', 'FTP',
                 'SMTP', 'POP3', 'IMAP', 'TELNET')

    def __init__(self, cfg):
        super().__init__(cfg)
        self._syns = TimedCounter(cfg['window_s'])
        self._acks = TimedCounter(cfg['window_s'])

    def inspect(self, pkt):
        if pkt.get('protocol') not in ('TCP', 'HTTP', 'TLS', 'SSH', 'SMB',
                                       'RDP', 'FTP', 'SMTP', 'POP3', 'IMAP',
                                       'TELNET'):
            return []
        flags = pkt.get('flags', '')
        if not flags or flags == 'NONE':
            return []
        self.packets_seen += 1
        ts = pkt['ts']
        key = (pkt['dst_ip'], pkt.get('dst_port'))

        if flags == 'SYN':
            syns = self._syns.add(key, ts)
        else:
            if 'ACK' in flags and 'SYN' not in flags:
                self._acks.add(key, ts)
            return []

        if syns < self.cfg['syn_rate']:
            return []
        acks = self._acks.count(key, ts)
        ratio = syns / max(acks, 1)
        if ratio < self.cfg['min_syn_ack_ratio']:
            return []  # handshakes are completing — this is real load
        if not self._cooled_down(key, ts):
            return []

        rate = syns / self.cfg['window_s']
        return [self._finding(
            pkt, 'CRITICAL', min(0.97, 0.7 + syns / 5000.0),
            'SYN flood against %s:%s — %d SYNs in %ds (%.0f/s) with only %d '
            'completed handshakes (ratio %.1f:1)'
            % (pkt['dst_ip'], pkt.get('dst_port'), syns,
               self.cfg['window_s'], rate, acks, ratio),
            ('T1498',),
            syn_count=syns, ack_count=acks, syn_ack_ratio=round(ratio, 2),
            rate_per_s=round(rate, 1), window_s=self.cfg['window_s'],
            target='%s:%s' % (pkt['dst_ip'], pkt.get('dst_port')),
        )]

    def expire(self, now):
        super().expire(now)
        self._syns.expire(now)
        self._acks.expire(now)


class UDPFloodDetector(Detector):
    """Raw UDP packet-rate flood against a single destination."""

    name = 'udp_flood'
    threat_type = 'udp_flood'
    description = 'UDP packet rate to a single destination exceeding threshold'
    techniques = ('T1498',)
    default_severity = 'CRITICAL'

    def __init__(self, cfg):
        super().__init__(cfg)
        self._packets = TimedCounter(cfg['window_s'])
        self._bytes = TimedSum(cfg['window_s'])

    def inspect(self, pkt):
        # Match on the transport, not the decoded L7 name, so a flood of
        # malformed UDP still counts.
        if pkt.get('ip_proto') != 17:
            return []
        self.packets_seen += 1
        ts = pkt['ts']
        key = (pkt['dst_ip'], pkt.get('dst_port'))
        count = self._packets.add(key, ts)
        total, _ = self._bytes.add(key, pkt.get('frame_len', 0), ts)
        if count < self.cfg['packet_rate']:
            return []
        if not self._cooled_down(key, ts):
            return []

        rate = count / self.cfg['window_s']
        mbps = (total * 8) / self.cfg['window_s'] / 1_000_000.0
        return [self._finding(
            pkt, 'CRITICAL', min(0.96, 0.7 + count / 10000.0),
            'UDP flood against %s:%s — %d packets in %ds (%.0f pps, %.2f Mbps)'
            % (pkt['dst_ip'], pkt.get('dst_port'), count,
               self.cfg['window_s'], rate, mbps),
            ('T1498',),
            packet_count=count, byte_count=total, rate_per_s=round(rate, 1),
            mbps=round(mbps, 3), window_s=self.cfg['window_s'],
            target='%s:%s' % (pkt['dst_ip'], pkt.get('dst_port')),
        )]

    def expire(self, now):
        super().expire(now)
        self._packets.expire(now)
        self._bytes.expire(now)


class AmplificationDetector(Detector):
    """Reflection/amplification abuse of UDP services.

    Detects both halves: the small request that asks for a large answer
    (NTP monlist, DNS ANY, SNMP getbulk) and the oversized response that comes
    back. The bandwidth multiplier is what makes the host useful as a
    reflector.
    """

    name = 'amplification'
    threat_type = 'amplification'
    description = ('UDP services returning responses far larger than their '
                   'requests — NTP monlist, DNS ANY, SNMP get-bulk')
    techniques = ('T1498.002',)
    default_severity = 'HIGH'
    protocols = ('NTP', 'DNS', 'SNMP')

    def __init__(self, cfg):
        super().__init__(cfg)
        self._observations = TimedCounter(cfg['window_s'])
        self._req_bytes = {}

    def inspect(self, pkt):
        proto = pkt.get('protocol')
        if proto not in ('NTP', 'DNS', 'SNMP'):
            return []
        self.packets_seen += 1
        ts = pkt['ts']
        vector = self._vector(pkt)
        if vector is None:
            return []
        kind, detail, is_request = vector

        # Reflector is the service being abused; victim is the spoofed source.
        server = pkt['dst_ip'] if is_request else pkt['src_ip']
        client = pkt['src_ip'] if is_request else pkt['dst_ip']
        key = (client, server, kind)

        size = pkt.get('frame_len', 0)
        if is_request:
            self._req_bytes[key] = size
            return []

        if size < self.cfg['min_response_len']:
            return []
        req_size = self._req_bytes.get(key)
        if not req_size:
            return []
        ratio = size / req_size
        if ratio < self.cfg['response_ratio']:
            return []

        count = self._observations.add(key, ts)
        if count < self.cfg['observations']:
            return []
        if not self._cooled_down(key, ts):
            return []

        return [self._finding(
            pkt, 'HIGH', min(0.95, 0.6 + ratio / 100.0),
            '%s reflection/amplification — %s request of %d bytes to %s '
            'returned %d bytes (%.1fx amplification), %d times in %ds'
            % (kind, detail, req_size, server, size, ratio, count,
               self.cfg['window_s']),
            ('T1498.002',),
            vector=kind, detail=detail, request_bytes=req_size,
            response_bytes=size, amplification_factor=round(ratio, 2),
            observations=count, reflector=server, victim=client,
            window_s=self.cfg['window_s'],
        )]

    @staticmethod
    def _vector(pkt):
        proto = pkt.get('protocol')
        if proto == 'NTP':
            if pkt.get('ntp_mode') != 7:
                return None
            if pkt.get('ntp_response'):
                return 'NTP', 'MON_GETLIST reply', False
            if pkt.get('ntp_is_monlist'):
                return 'NTP', 'MON_GETLIST (mode 7)', True
            return None
        if proto == 'DNS':
            if pkt.get('dns_qr') == 0 and pkt.get('dns_qtype') == 255:
                return 'DNS', 'ANY query', True
            if pkt.get('dns_qr') == 1 and pkt.get('dns_qtype') == 255:
                return 'DNS', 'ANY response', False
            return None
        if proto == 'SNMP':
            pdu = pkt.get('snmp_pdu_type')
            if pdu == 'get-bulk':
                return 'SNMP', 'get-bulk', True
            if pdu == 'response':
                return 'SNMP', 'get-bulk response', False
        return None

    def expire(self, now):
        super().expire(now)
        self._observations.expire(now)
        if len(self._req_bytes) > 20000:
            self._req_bytes.clear()
