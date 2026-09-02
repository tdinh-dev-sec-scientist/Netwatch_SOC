"""Lateral movement detector."""

from .base import Detector, TimedSet, is_internal

SERVICE_NAMES = {
    445: 'SMB', 139: 'NetBIOS', 135: 'MS-RPC', 3389: 'RDP',
    5985: 'WinRM-HTTP', 5986: 'WinRM-HTTPS', 5900: 'VNC', 22: 'SSH',
}


class LateralMovementDetector(Detector):
    """Internal host fanning out to peers over remote administration services.

    A workstation legitimately talks to a file server; it does not normally
    open SMB/RDP/WinRM sessions to several *different* internal hosts in a
    short window. Fan-out is the discriminator, not the single connection.
    """

    name = 'lateral_movement'
    threat_type = 'lateral_movement'
    description = ('Internal-to-internal connections on remote admin services '
                   '(SMB/RDP/WinRM/VNC) fanning out to multiple hosts')
    techniques = ('T1021',)
    default_severity = 'CRITICAL'

    def __init__(self, cfg):
        super().__init__(cfg)
        self._targets = TimedSet(cfg['window_s'])
        self._services = TimedSet(cfg['window_s'])

    def inspect(self, pkt):
        dport = pkt.get('dst_port')
        if dport not in self.cfg['admin_ports']:
            return []
        src, dst = pkt.get('src_ip'), pkt.get('dst_ip')
        if not is_internal(src) or not is_internal(dst):
            return []
        # Count session initiations, not every packet in an established session.
        if (pkt.get('protocol') == 'TCP' and pkt.get('flags') != 'SYN'
                and pkt.get('protocol') not in ('SMB', 'RDP')):
            return []
        self.packets_seen += 1
        ts = pkt['ts']

        hosts = self._targets.add(src, dst, ts)
        self._services.add(src, dport, ts)
        if hosts < self.cfg['distinct_hosts']:
            return []
        if not self._cooled_down(src, ts):
            return []

        services = sorted(self._services.members(src))
        names = ', '.join('%s/%d' % (SERVICE_NAMES.get(p, '?'), p)
                          for p in services)
        severity = 'CRITICAL' if hosts >= self.cfg['distinct_hosts'] * 3 \
            else 'HIGH'
        return [self._finding(
            pkt, severity, min(0.95, 0.65 + hosts / 30.0),
            'Internal host %s opened remote admin sessions to %d distinct '
            'internal hosts in %ds via %s'
            % (src, hosts, self.cfg['window_s'], names),
            ('T1021',),
            distinct_targets=hosts,
            targets=self._targets.members(src)[:16],
            services=services, service_names=names,
            window_s=self.cfg['window_s'],
        )]

    def expire(self, now):
        super().expire(now)
        self._targets.expire(now)
        self._services.expire(now)
