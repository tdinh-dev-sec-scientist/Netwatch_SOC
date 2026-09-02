"""Discovery and reconnaissance detectors."""

from .base import Detector, TimedSet


def is_service_response(pkt):
    """True when a packet flows from a service port back to an ephemeral one.

    Replies fan out across the client's ephemeral ports, so counting them as
    "ports contacted" makes every busy DNS resolver look like a port scanner.
    """
    sport = pkt.get('src_port')
    dport = pkt.get('dst_port')
    if sport is None or dport is None:
        return False
    return sport < 1024 <= dport


def subnet24(ip):
    """The /24 an address sits in, used to group sweep targets.

    A scan walks a contiguous range; ordinary client traffic is scattered
    across unrelated networks. Grouping by /24 is what separates the two.
    """
    if not ip or ':' in ip:
        return None
    parts = ip.rsplit('.', 1)
    return parts[0] if len(parts) == 2 else None


class PortScanDetector(Detector):
    """Vertical scan: one source touching many distinct ports on one host.

    Keyed per (src, dst) pair so a busy client talking to many services across
    the estate is not mistaken for a scanner enumerating a single target.
    """

    name = 'port_scan'
    threat_type = 'port_scan'
    description = ('Distinct destination ports contacted on a single host '
                   'within a sliding window')
    techniques = ('T1046',)
    default_severity = 'HIGH'

    def __init__(self, cfg):
        super().__init__(cfg)
        self._ports = TimedSet(cfg['window_s'])

    def inspect(self, pkt):
        port = pkt.get('dst_port')
        if port is None or pkt.get('protocol') == 'ARP':
            return []
        if is_service_response(pkt):
            return []
        self.packets_seen += 1
        ts = pkt['ts']
        key = (pkt['src_ip'], pkt['dst_ip'])

        # A RST/ACK reply back to the scanner is not itself scanning.
        flags = pkt.get('flags', '')
        if 'RST' in flags:
            return []

        count = self._ports.add(key, port, ts)
        if count < self.cfg['distinct_ports']:
            return []
        if not self._cooled_down(key, ts):
            return []

        ports = sorted(self._ports.members(key))
        # A SYN-only scan is far more conclusive than mixed conversational
        # traffic, so let the flag mix drive confidence.
        syn_only = flags == 'SYN'
        confidence = min(0.98, 0.6 + count / 100.0 + (0.15 if syn_only else 0))
        severity = 'HIGH' if count >= self.cfg['distinct_ports'] * 2 else 'MEDIUM'
        return [self._finding(
            pkt, severity, confidence,
            '%s probed %d distinct ports on %s in %ds (e.g. %s)' % (
                pkt['src_ip'], count, pkt['dst_ip'], self.cfg['window_s'],
                ', '.join(str(p) for p in ports[:8])),
            ('T1046',),
            distinct_ports=count, window_s=self.cfg['window_s'],
            sample_ports=ports[:24], syn_only=syn_only,
        )]

    def expire(self, now):
        super().expire(now)
        self._ports.expire(now)


class NetworkReconDetector(Detector):
    """Horizontal sweep: one source touching many hosts on very few ports.

    This is the mirror image of a port scan and maps to a different ATT&CK
    technique — the adversary is finding live hosts, not enumerating services.
    """

    name = 'network_recon'
    threat_type = 'network_recon'
    description = ('Host sweep across many destinations on a narrow port set, '
                   'or an ICMP echo sweep')
    techniques = ('T1595',)
    default_severity = 'MEDIUM'

    def __init__(self, cfg):
        super().__init__(cfg)
        self._hosts = TimedSet(cfg['window_s'])
        self._ports = TimedSet(cfg['window_s'])
        self._icmp_hosts = TimedSet(cfg['window_s'])

    def inspect(self, pkt):
        src, dst = pkt.get('src_ip'), pkt.get('dst_ip')
        if not src or not dst:
            return []
        if is_service_response(pkt):
            return []
        self.packets_seen += 1
        ts = pkt['ts']
        # Sweeps walk a contiguous range, so count distinct targets per /24.
        # Without this, a browser fetching many unrelated sites on :443 looks
        # identical to a horizontal scan.
        net = subnet24(dst)
        if net is None:
            return []

        if pkt.get('icmp_type') == 8:  # echo request
            n = self._icmp_hosts.add((src, net), dst, ts)
            if n >= self.cfg['icmp_sweep_hosts'] and self._cooled_down(
                    ('icmp', src, net), ts):
                return [self._finding(
                    pkt, 'MEDIUM', min(0.95, 0.55 + n / 100.0),
                    '%s sent ICMP echo requests to %d distinct hosts in '
                    '%s.0/24 within %ds'
                    % (src, n, net, self.cfg['window_s']),
                    ('T1595',),
                    sweep_type='icmp_echo', distinct_hosts=n, subnet=net,
                    window_s=self.cfg['window_s'],
                )]
            return []

        port = pkt.get('dst_port')
        if port is None:
            return []
        key = (src, net)
        hosts = self._hosts.add(key, dst, ts)
        ports = self._ports.add(key, port, ts)
        if hosts < self.cfg['distinct_hosts']:
            return []
        if ports > self.cfg['max_distinct_ports']:
            return []  # broad port spread is scanning, handled by port_scan
        if not self._cooled_down(('tcp', src, net), ts):
            return []

        return [self._finding(
            pkt, 'MEDIUM', min(0.95, 0.55 + hosts / 120.0),
            '%s contacted %d distinct hosts in %s.0/24 on only %d port(s) %s '
            'in %ds' % (src, hosts, net, ports,
                        sorted(self._ports.members(key)),
                        self.cfg['window_s']),
            ('T1595',),
            sweep_type='horizontal', distinct_hosts=hosts, subnet=net,
            distinct_ports=ports, target_ports=sorted(self._ports.members(key)),
            window_s=self.cfg['window_s'],
        )]

    def expire(self, now):
        super().expire(now)
        self._hosts.expire(now)
        self._ports.expire(now)
        self._icmp_hosts.expire(now)
