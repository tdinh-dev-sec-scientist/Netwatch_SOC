"""Data exfiltration detector."""

from .base import Detector, TimedSum, is_internal


class DataExfiltrationDetector(Detector):
    """Sustained outbound volume from an internal host to one external peer.

    Direction matters: a large inbound download is a user fetching data, while
    a large *upload* from an internal host to a single external destination is
    the exfiltration shape. Only bytes leaving the perimeter are counted.
    """

    name = 'data_exfil'
    threat_type = 'data_exfil'
    description = ('Outbound bytes from an internal source to a single '
                   'external destination exceeding a threshold in a window')
    techniques = ('T1041',)
    default_severity = 'CRITICAL'

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
            'Outbound transfer of %.1f MB from internal host %s to external '
            '%s over %d packets in %ds via %s'
            % (mb, src, dst, packets, self.cfg['window_s'],
               pkt.get('protocol')),
            ('T1041',),
            bytes_out=total, megabytes=round(mb, 2), packet_count=packets,
            destination=dst, window_s=self.cfg['window_s'],
            transport=pkt.get('protocol'),
        )]

    def expire(self, now):
        super().expire(now)
        self._volume.expire(now)
