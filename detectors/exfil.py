"""Data exfiltration detector."""

from .base import Detector, TimedSet, TimedSum, is_internal


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

    def __init__(self, cfg):
        super().__init__(cfg)
        self._volume = TimedSum(cfg['window_s'])
        # Splitting a transfer across peers keeps every flow under the
        # per-peer threshold while moving exactly as much data, so the same
        # bytes are also totalled per source across all of its peers.
        self._source_volume = TimedSum(cfg['window_s'])
        self._source_peers = TimedSet(cfg['window_s'])

    def inspect(self, pkt):
        src, dst = pkt.get('src_ip'), pkt.get('dst_ip')
        if not src or not dst:
            return []
        # Internal -> external only, unless the direction check is disabled.
        if self.cfg.get('outbound_only', True) \
                and (not is_internal(src) or is_internal(dst)):
            return []
        payload = pkt.get('payload_len') or 0
        if not payload:
            return []
        self.packets_seen += 1
        ts = pkt['ts']

        key = (src, dst)
        total, packets = self._volume.add(key, payload, ts)

        source_threshold = self.cfg.get('source_bytes_threshold', 0)
        if source_threshold:
            source_total, source_packets = self._source_volume.add(
                src, payload, ts)
            peers = self._source_peers.add(src, dst, ts)
        else:
            source_total = source_packets = peers = 0

        if (total >= self.cfg['bytes_threshold']
                and packets >= self.cfg['min_packets']):
            pattern, observed, count = 'single_destination', total, packets
            target, threshold = dst, self.cfg['bytes_threshold']
        elif (source_threshold and source_total >= source_threshold
              and peers >= self.cfg.get('source_min_peers', 3)
              and source_packets >= self.cfg['min_packets']):
            pattern = 'distributed'
            observed, count = source_total, source_packets
            target = '%d external peers' % peers
            threshold = source_threshold
        else:
            return []

        if not self._cooled_down((src, pattern), ts):
            return []

        # Reset so a continuing transfer re-arms rather than alerting on the
        # same accumulated bytes forever.
        if pattern == 'single_destination':
            self._volume.reset(key)
        else:
            self._source_volume.reset(src)

        mb = observed / 1_000_000.0
        severity = 'CRITICAL' if observed >= threshold * 4 else 'HIGH'
        return [self._finding(
            pkt, severity, min(0.95, 0.65 + mb / 100.0),
            'Outbound transfer of %.1f MB from internal host %s to %s over '
            '%d packets in %ds via %s'
            % (mb, src, target, count, self.cfg['window_s'],
               pkt.get('protocol')),
            ('T1041',),
            pattern=pattern, bytes_out=observed, megabytes=round(mb, 2),
            packet_count=count, destination=target,
            distinct_peers=peers or None, window_s=self.cfg['window_s'],
            transport=pkt.get('protocol'),
        )]

    def expire(self, now):
        super().expire(now)
        self._volume.expire(now)
        self._source_volume.expire(now)
        self._source_peers.expire(now)
