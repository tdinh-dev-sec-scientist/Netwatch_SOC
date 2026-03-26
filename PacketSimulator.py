"""
PacketSimulator — High-fidelity network packet simulation engine
Generates 5,000+ packets/min with realistic traffic patterns, attack
scenarios, and geo-distributed sources. Replaces Scapy in demo mode.

In production: swap run() body for Scapy AsyncSniffer callback.
"""

import time
import random
import threading
from collections import defaultdict

PROTOCOLS = ['TCP','UDP','HTTP','HTTPS','DNS','ICMP','FTP','SSH',
             'SMTP','POP3','IMAP','SNMP','NTP','ARP','TLS','QUIC']
PROTO_WEIGHTS = [22,18,14,11,8,5,3,4,2,1,1,2,2,2,3,2]

ATTACK_PROFILES = [
    # (trigger_prob, src_ip_prefix, attack_protocol, description)
    (0.003, '185.220.',  'TCP',  'Tor exit node scanning'),
    (0.002, '10.0.',     'SSH',  'Internal brute force'),
    (0.004, '192.168.',  'HTTP', 'Internal HTTP flood'),
    (0.001, '45.33.',    'DNS',  'DNS tunneling C2'),
    (0.002, '198.51.',   'UDP',  'UDP amplification'),
    (0.001, '203.0.',    'ICMP', 'ICMP sweep'),
]

GEO_PROFILES = [
    ('US', 40.71, -74.00, 0.30),
    ('CN', 39.91, 116.39, 0.18),
    ('RU', 55.75,  37.62, 0.10),
    ('DE', 52.52,  13.40, 0.08),
    ('BR',-23.55, -46.63, 0.06),
    ('IN', 19.08,  72.88, 0.07),
    ('GB', 51.51,  -0.13, 0.05),
    ('JP', 35.69, 139.69, 0.05),
    ('KP', 39.02, 125.75, 0.03),
    ('IR', 35.69,  51.39, 0.04),
    ('AU',-33.87, 151.21, 0.04),
]
GEO_WEIGHTS = [g[3] for g in GEO_PROFILES]


class PacketSimulator:
    def __init__(self, db, threat_detector, protocol_analyzer):
        self.db = db
        self.td = threat_detector
        self.pa = protocol_analyzer
        self._running = True
        self._pkt_count = 0
        self._alert_count = 0
        self._lock = threading.Lock()

    def run(self):
        """Main simulation loop — 5,000-6,500 packets/min."""
        print("📡 PacketSimulator started")
        interval = 1 / (5500 / 60)  # ~91 packets/sec

        perf_ts = time.time()
        perf_pkts = 0
        perf_alerts = 0

        while self._running:
            try:
                pkt = self._generate_packet()
                self.db.insert_packet(pkt)
                perf_pkts += 1

                # Threat analysis
                findings = self.td.analyze(pkt)
                for finding in findings:
                    threat_type, severity, desc, mitre_key = finding
                    mitre = self.td.get_mitre_info(mitre_key)
                    alert = {
                        'ts':           pkt['ts'],
                        'severity':     severity,
                        'alert_type':   threat_type.replace('_', ' ').title(),
                        'src_ip':       pkt['src_ip'],
                        'dst_ip':       pkt['dst_ip'],
                        'protocol':     pkt['protocol'],
                        'description':  desc,
                        'mitre_id':     mitre[0],
                        'mitre_name':   mitre[1],
                        'raw_data':     '{}',
                    }
                    alert_id = self.db.insert_alert(alert)
                    self.db.insert_mitre_event({
                        'ts':             pkt['ts'],
                        'technique_id':   mitre[0],
                        'technique_name': mitre[1],
                        'tactic':         mitre[2],
                        'alert_id':       alert_id,
                        'confidence':     random.uniform(0.75, 0.99),
                    })
                    perf_alerts += 1
                    pkt['is_malicious'] = 1

                # Geo insert (sampled)
                if random.random() < 0.1:
                    geo_profile = random.choices(GEO_PROFILES, weights=GEO_WEIGHTS)[0]
                    self.db.insert_geo({
                        'ts':       pkt['ts'],
                        'src_ip':   pkt['src_ip'],
                        'country':  geo_profile[0],
                        'city':     '',
                        'lat':      geo_profile[1] + random.uniform(-2, 2),
                        'lon':      geo_profile[2] + random.uniform(-2, 2),
                        'is_threat': 1 if geo_profile[0] in ('KP','IR','RU') else 0,
                    })

                # Performance snapshot every 60s
                elapsed = time.time() - perf_ts
                if elapsed >= 60:
                    self._record_performance(perf_pkts, perf_alerts, elapsed)
                    perf_pkts = 0
                    perf_alerts = 0
                    perf_ts = time.time()

                time.sleep(interval * random.uniform(0.5, 1.5))

            except Exception as e:
                time.sleep(0.5)

    def _generate_packet(self):
        now = time.time()

        # Choose protocol with weighted distribution
        proto = random.choices(PROTOCOLS, weights=PROTO_WEIGHTS)[0]

        # Occasionally inject attack traffic
        is_attack = False
        src_ip = self._rand_ip()
        for (prob, prefix, ap, desc) in ATTACK_PROFILES:
            if random.random() < prob:
                src_ip = prefix + f"{random.randint(1,254)}.{random.randint(1,254)}"
                proto = ap
                is_attack = True
                break

        return {
            'ts':         now,
            'src_ip':     src_ip,
            'dst_ip':     self._rand_ip(),
            'src_port':   random.randint(1024, 65535),
            'dst_port':   self._common_port(proto),
            'protocol':   proto,
            'length':     self._realistic_length(proto),
            'flags':      self._tcp_flags() if proto == 'TCP' else '',
            'payload_hex':'',
            'is_malicious': 1 if is_attack else 0,
        }

    @staticmethod
    def _rand_ip():
        return '.'.join(str(random.randint(1, 254)) for _ in range(4))

    @staticmethod
    def _common_port(proto):
        port_map = {
            'HTTP':80,'HTTPS':443,'DNS':53,'SSH':22,'FTP':21,
            'SMTP':25,'POP3':110,'IMAP':143,'SNMP':161,'NTP':123,
            'TLS':443,'QUIC':443,'ARP':0,
        }
        return port_map.get(proto, random.randint(1024, 49151))

    @staticmethod
    def _realistic_length(proto):
        size_map = {
            'ICMP':   (64, 128),    'ARP':  (28, 60),
            'DNS':    (60, 512),    'NTP':  (48, 100),
            'SSH':    (100, 800),   'FTP':  (40, 200),
            'HTTP':   (200, 8000),  'HTTPS':(100, 4096),
            'SMTP':   (100, 500000),'TCP':  (40, 1500),
            'UDP':    (40, 1472),   'TLS':  (100, 2000),
            'QUIC':   (50, 1350),
        }
        lo, hi = size_map.get(proto, (40, 1500))
        return random.randint(lo, hi)

    @staticmethod
    def _tcp_flags():
        return random.choices(
            ['SYN','ACK','SYN|ACK','FIN|ACK','RST','PSH|ACK'],
            weights=[20, 40, 15, 10, 5, 10]
        )[0]

    def _record_performance(self, pkts, alerts, elapsed):
        try:
            import os
            ppm = int(pkts / elapsed * 60)
            self.db._conn().__enter__().execute("""
                INSERT INTO performance_metrics
                (timestamp,packets_pm,alerts_pm,db_query_ms,cpu_pct,mem_mb,drop_pct)
                VALUES(?,?,?,?,?,?,?)
            """, (time.time(), ppm, alerts,
                  random.uniform(10,45), random.uniform(20,60),
                  random.uniform(512,1200), random.uniform(0,0.5)))
        except Exception:
            pass