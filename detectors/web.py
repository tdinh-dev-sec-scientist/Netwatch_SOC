"""HTTP request anomaly detector (injection, traversal, scanner tooling)."""

import re
from urllib.parse import unquote_plus

from .base import Detector

# Patterns are matched against the URL-decoded request line and headers.
# Each carries its own weight so a single weak hit cannot alert on its own.
SIGNATURES = [
    (re.compile(r"(?i)\bunion\b\s+(all\s+)?\bselect\b"), 0.9, 'SQLi',
     'UNION SELECT'),
    (re.compile(r"(?i)\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+"), 0.7, 'SQLi',
     'always-true OR comparison'),
    (re.compile(r"(?i)'\s*(or|and)\s+'[^']*'\s*=\s*'"), 0.7, 'SQLi',
     'quoted always-true comparison'),
    (re.compile(r"(?i)\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\("),
     0.8, 'SQLi', 'time-based injection function'),
    (re.compile(r"(?i)\b(information_schema|sysobjects|pg_catalog)\b"), 0.8,
     'SQLi', 'schema enumeration'),
    (re.compile(r"(?i)\b(select|insert|update|delete)\b.{0,40}\bfrom\b"), 0.5,
     'SQLi', 'SQL statement fragment'),
    (re.compile(r"(\.\./){2,}|(\.\.\\){2,}"), 0.85, 'Traversal',
     'directory traversal sequence'),
    (re.compile(r"(?i)/etc/(passwd|shadow)|boot\.ini|win\.ini"), 0.9,
     'Traversal', 'sensitive file path'),
    (re.compile(r"(?i)<script[\s>]|javascript:|onerror\s*="), 0.75, 'XSS',
     'script injection'),
    (re.compile(r"(?i)(;|\||`|\$\()\s*(cat|wget|curl|nc|bash|sh|powershell)\b"),
     0.9, 'CmdInjection', 'shell command injection'),
    (re.compile(r"(?i)\$\{jndi:(ldap|rmi|dns)"), 0.95, 'JNDI',
     'JNDI lookup (Log4Shell)'),
]

# User agents belonging to well-known offensive tooling.
SCANNER_UA = re.compile(
    r"(?i)\b(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|"
    r"wpscan|havij|zgrab|metasploit|burpsuite)\b")


class HTTPAnomalyDetector(Detector):
    """Injection, traversal and scanner signatures in HTTP requests."""

    name = 'http_anomaly'
    threat_type = 'http_anomaly'
    description = ('SQL injection, path traversal, XSS, command injection and '
                   'JNDI patterns in the request line/headers, plus offensive '
                   'security tool user agents and oversized requests')
    techniques = ('T1190',)

    def inspect(self, pkt):
        if pkt.get('protocol') != 'HTTP':
            return []
        uri = pkt.get('http_uri')
        if uri is None:
            return []
        self.packets_seen += 1
        ts = pkt['ts']

        # Attackers URL-encode payloads to evade naive matching, so decode
        # twice before testing.
        decoded = unquote_plus(unquote_plus(uri))
        haystack = decoded
        if pkt.get('http_cookie_len'):
            haystack += ' cookie_len=%d' % pkt['http_cookie_len']

        hits, score, categories = [], 0.0, set()
        for pattern, weight, category, label in SIGNATURES:
            if pattern.search(haystack):
                hits.append(label)
                categories.add(category)
                score = max(score, weight)

        ua = pkt.get('http_user_agent') or ''
        scanner = SCANNER_UA.search(ua)
        if scanner:
            hits.append('scanner user-agent %r' % scanner.group(0))
            categories.add('Scanner')
            score = max(score, 0.85)

        if len(uri) > self.cfg['max_uri_len']:
            hits.append('URI length %d exceeds %d'
                        % (len(uri), self.cfg['max_uri_len']))
            categories.add('Oversized')
            score = max(score, 0.5)
        if pkt.get('http_header_len', 0) > self.cfg['max_header_len']:
            hits.append('header block %d bytes' % pkt['http_header_len'])
            categories.add('Oversized')
            score = max(score, 0.5)

        if not hits or score < self.cfg.get('min_score', 0.5):
            return []
        key = (pkt['src_ip'], pkt['dst_ip'], tuple(sorted(categories)))
        if not self._cooled_down(key, ts):
            return []

        severity = 'CRITICAL' if score >= 0.9 else (
            'HIGH' if score >= 0.7 else 'MEDIUM')
        return [self._finding(
            pkt, severity, min(0.97, score),
            '%s from %s to %s %s %s — %s' % (
                '/'.join(sorted(categories)), pkt['src_ip'], pkt['dst_ip'],
                pkt.get('http_method', ''), uri[:120], '; '.join(hits[:5])),
            ('T1190',),
            categories=sorted(categories), signatures=hits[:10],
            method=pkt.get('http_method'), uri=uri[:512],
            host=pkt.get('http_host'), user_agent=ua[:200],
            score=round(score, 2),
        )]
