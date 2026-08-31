"""ARP cache poisoning detector."""

from .base import Detector, TimedCounter


class ARPSpoofDetector(Detector):
    """IP-to-MAC binding conflicts and gratuitous ARP floods.

    Two signals, both derived from parsed ARP payloads:

    1. Binding conflict — an IP previously seen at one MAC now announced by a
       different MAC. This is the definitive poisoning signature.
    2. Gratuitous flood — repeated unsolicited replies (sender IP == target
       IP), which is how an attacker keeps a poisoned entry alive against the
       legitimate host's own announcements.
    """

    name = 'arp_spoof'
    threat_type = 'arp_spoof'
    description = ('IP-to-MAC binding changes and bursts of gratuitous ARP '
                   'replies on the local segment')
    techniques = ('T1557.002',)

    def __init__(self, cfg):
        super().__init__(cfg)
        self._bindings = {}          # ip -> (mac, first_seen, last_seen)
        self._gratuitous = TimedCounter(cfg['window_s'])

    def inspect(self, pkt):
        if pkt.get('protocol') != 'ARP':
            return []
        sender_ip = pkt.get('arp_sender_ip')
        sender_mac = pkt.get('arp_sender_mac')
        if not sender_ip or not sender_mac:
            return []
        if sender_ip == '0.0.0.0' or sender_mac == '00:00:00:00:00:00':
            return []  # ARP probe / duplicate-address detection
        self.packets_seen += 1
        ts = pkt['ts']
        findings = []

        if self.cfg.get('alert_on_binding_conflict'):
            known = self._bindings.get(sender_ip)
            if known and known[0] != sender_mac:
                if self._cooled_down(('conflict', sender_ip), ts):
                    findings.append(self._finding(
                        pkt, 'CRITICAL', 0.93,
                        'ARP cache poisoning: %s was bound to %s but is now '
                        'claimed by %s (previous binding held for %.0fs)'
                        % (sender_ip, known[0], sender_mac, ts - known[1]),
                        ('T1557.002',),
                        pattern='binding_conflict', ip=sender_ip,
                        previous_mac=known[0], new_mac=sender_mac,
                        previous_binding_age_s=round(ts - known[1], 1),
                    ))
            self._bindings[sender_ip] = (
                sender_mac, known[1] if known and known[0] == sender_mac
                else ts, ts)

        # ARP replies (op 2) that are unsolicited.
        if pkt.get('arp_gratuitous') and pkt.get('arp_op') == 2:
            count = self._gratuitous.add(sender_mac, ts)
            if count >= self.cfg['gratuitous_rate'] and self._cooled_down(
                    ('gratuitous', sender_mac), ts):
                findings.append(self._finding(
                    pkt, 'HIGH', min(0.92, 0.6 + count / 50.0),
                    '%s sent %d gratuitous ARP replies for %s in %ds — '
                    'consistent with maintaining a poisoned cache entry'
                    % (sender_mac, count, sender_ip, self.cfg['window_s']),
                    ('T1557.002',),
                    pattern='gratuitous_flood', mac=sender_mac,
                    ip=sender_ip, reply_count=count,
                    window_s=self.cfg['window_s'],
                ))
        return findings

    def expire(self, now):
        super().expire(now)
        self._gratuitous.expire(now)
        ttl = self.cfg['window_s'] * 20
        for ip in [i for i, v in self._bindings.items() if now - v[2] > ttl]:
            del self._bindings[ip]
