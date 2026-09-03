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

    def __init__(self, cfg):
        super().__init__(cfg)
        self._ports = TimedSet(cfg['window_s'])
        # Second, slower time scale. A scan spread thin enough never puts
        # enough ports inside the fast window, so the same evidence is
        # accumulated over a much longer one against a higher bar.
        self._slow_ports = TimedSet(cfg.get('long_window_s', 900))

    def inspect(self, pkt):
        port = pkt.get('dst_port')
        if port is None or pkt.get('protocol') == 'ARP':
            return []
        if self.cfg.get('ignore_service_responses', True) \
                and is_service_response(pkt):
            return []
        self.packets_seen += 1
        ts = pkt['ts']
        key = (pkt['src_ip'], pkt['dst_ip'])

        # A RST/ACK reply back to the scanner is not itself scanning.
        flags = pkt.get('flags', '')
        if self.cfg.get('ignore_rst', True) and 'RST' in flags:
            return []

        count = self._ports.add(key, port, ts)
        long_threshold = self.cfg.get('long_distinct_ports', 0)
        long_window = self.cfg.get('long_window_s', 900)
        slow_count = (self._slow_ports.add(key, port, ts)
                      if long_threshold else 0)

        if count >= self.cfg['distinct_ports']:
            window, observed, pace = self.cfg['window_s'], count, 'burst'
            source = self._ports
        elif long_threshold and slow_count >= long_threshold:
            window, observed, pace = long_window, slow_count, 'slow'
            source = self._slow_ports
        else:
            return []
        if not self._cooled_down((key, pace), ts):
            return []

        ports = sorted(source.members(key))
        # A SYN-only scan is far more conclusive than mixed conversational
        # traffic, so let the flag mix drive confidence.
        syn_only = flags == 'SYN'
        confidence = min(0.98, 0.6 + observed / 100.0
                         + (0.15 if syn_only else 0))
        if pace == 'slow':
            # Spread over 15 minutes, the same port count is weaker evidence.
            confidence = min(confidence, 0.85)
        severity = 'HIGH' if observed >= self.cfg['distinct_ports'] * 2 \
            else 'MEDIUM'
        return [self._finding(
            pkt, severity, confidence,
            '%s probed %d distinct ports on %s in %ds%s (e.g. %s)' % (
                pkt['src_ip'], observed, pkt['dst_ip'], window,
                ' — paced below the burst threshold' if pace == 'slow' else '',
                ', '.join(str(p) for p in ports[:8])),
            ('T1046',),
            distinct_ports=observed, window_s=window, pace=pace,
            sample_ports=ports[:24], syn_only=syn_only,
        )]

    def expire(self, now):
        super().expire(now)
        self._ports.expire(now)
        self._slow_ports.expire(now)


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

    def __init__(self, cfg):
        super().__init__(cfg)
        self._hosts = TimedSet(cfg['window_s'])
        self._ports = TimedSet(cfg['window_s'])
        self._icmp_hosts = TimedSet(cfg['window_s'])

    def inspect(self, pkt):
        src, dst = pkt.get('src_ip'), pkt.get('dst_ip')
        if not src or not dst:
            return []
        if self.cfg.get('ignore_service_responses', True) \
                and is_service_response(pkt):
            return []
        self.packets_seen += 1
        ts = pkt['ts']
        # Sweeps walk a contiguous range, so count distinct targets per /24.
        # Without this, a browser fetching many unrelated sites on :443 looks
        # identical to a horizontal scan.
        if self.cfg.get('group_by_subnet', True):
            net = subnet24(dst)
            if net is None:
                return []
        else:
            net = '*'          # ungrouped: every target counts against one key

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
