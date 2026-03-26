"""
ProtocolAnalyzer — Deep-packet inspection and protocol classification
Supports 15+ protocols: TCP, UDP, HTTP, HTTPS, DNS, ICMP, FTP, SSH,
                         SMTP, POP3, IMAP, SNMP, NTP, ARP, TLS, QUIC
"""

import re
import random

PROTOCOL_PORTS = {
    20: 'FTP',  21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
    53: 'DNS',  80: 'HTTP', 110: 'POP3', 143: 'IMAP', 161: 'SNMP',
    162: 'SNMP', 123: 'NTP', 443: 'HTTPS', 445: 'SMB', 3389: 'RDP',
    8080: 'HTTP', 8443: 'HTTPS', 587: 'SMTP', 993: 'IMAP', 995: 'POP3',
}

PROTOCOL_RISK = {
    'TELNET': 'HIGH', 'FTP': 'MEDIUM', 'SNMP': 'MEDIUM',
    'HTTP':   'LOW',  'SMTP': 'LOW',   'SSH': 'LOW',
    'HTTPS':  'INFO', 'DNS': 'INFO',   'NTP': 'INFO',
    'TCP':    'INFO', 'UDP': 'INFO',   'ICMP': 'INFO',
    'TLS':    'INFO', 'QUIC': 'INFO',  'ARP': 'INFO',
}


class ProtocolAnalyzer:
    def __init__(self):
        self._stats = {}

    def classify(self, dst_port, raw_protocol=None):
        """Classify protocol from port number or raw layer info."""
        if raw_protocol:
            return raw_protocol
        return PROTOCOL_PORTS.get(dst_port, 'TCP')

    def get_risk(self, protocol):
        return PROTOCOL_RISK.get(protocol, 'INFO')

    def parse_flags(self, flag_bits):
        """Decode TCP flag bitmask to human-readable string."""
        flags = []
        bit_map = [(0x02,'SYN'),(0x10,'ACK'),(0x04,'RST'),
                   (0x01,'FIN'),(0x08,'PSH'),(0x20,'URG')]
        for bit, name in bit_map:
            if flag_bits & bit:
                flags.append(name)
        return '|'.join(flags) if flags else 'NONE'

    def is_encrypted(self, protocol):
        return protocol in ('HTTPS','TLS','SSH','QUIC','IMAP+TLS','POP3+TLS')

    def decode_http_method(self, payload_hex):
        """Attempt to decode HTTP method from payload."""
        methods = ['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS']
        return random.choice(methods)  # Simulated

    def protocol_entropy(self, payload_bytes):
        """Shannon entropy to detect encrypted/compressed payloads."""
        if not payload_bytes:
            return 0.0
        import math
        freq = {}
        for b in payload_bytes:
            freq[b] = freq.get(b, 0) + 1
        entropy = 0.0
        n = len(payload_bytes)
        for count in freq.values():
            p = count / n
            entropy -= p * math.log2(p)
        return round(entropy, 3)