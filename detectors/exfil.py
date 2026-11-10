"""Data exfiltration detector."""

from .base import OBSERVED_SIGNAL, Detector, TimedSum, is_internal


class DataExfiltrationDetector(Detector):
    """Sustained outbound volume from an internal host to one external peer.

    Direction matters: a large inbound download is a user fetching data, while
    a large *upload* from an internal host to a single external destination is
    an egress signal. Volume alone does not establish data theft, a non-C2
    protocol, or successful exfiltration.
    """

    name = 'data_exfil'
    threat_type = 'data_exfil'
    description = ('Observed outbound bytes from an internal source to a '
                   'single external destination exceeding a window threshold; '
                   'candidate egress, not confirmed exfiltration')
    techniques = ('T1048.003',)

    def __init__(self, cfg):
        super().__init__(cfg)
        self._volume = TimedSum(cfg['window_s'])

    def inspect(self, pkt):
        src, dst = pkt.get('src_ip'), pkt.get('dst_ip')
        if not src or not dst:
            return []
        # Internal -> external only.
        if not is_internal(src) or is_internal(dst):
            return []
        payload = pkt.get('payload_len') or 0
        if not payload:
            return []
        self.packets_seen += 1
        ts = pkt['ts']

        key = (src, dst)
        total, packets = self._volume.add(key, payload, ts)
        if total < self.cfg['bytes_threshold']:
            return []
        if packets < self.cfg['min_packets']:
            return []
        if not self._cooled_down(key, ts):
            return []

        # Reset so a continuing transfer re-arms rather than alerting on the
        # same accumulated bytes forever.
        self._volume.reset(key)
        mb = total / 1_000_000.0
        severity = 'CRITICAL' if total >= self.cfg['bytes_threshold'] * 4 \
            else 'HIGH'
        return [self._finding(
            pkt, severity, min(0.95, 0.65 + mb / 100.0),
            'Observed outbound egress of %.1f MB from internal host %s to '
            'external %s over %d packets in %ds via %s; this volume alone '
            'does not confirm exfiltration'
            % (mb, src, dst, packets, self.cfg['window_s'],
               pkt.get('protocol')),
            ('T1048.003',),
            evidence_level=OBSERVED_SIGNAL,
            activity='candidate_egress',
            bytes_out=total, megabytes=round(mb, 2), packet_count=packets,
            destination=dst, window_s=self.cfg['window_s'],
            transport=pkt.get('protocol'),
        )]

    def expire(self, now):
        super().expire(now)
        self._volume.expire(now)
