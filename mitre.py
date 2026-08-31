"""
MITRE ATT&CK technique catalog for NetWatch SOC.

Every technique below is reachable from at least one detector in detectors/.
`rationale` records why the detector's network evidence corresponds to the
technique; it is surfaced in the API so an analyst can audit the mapping.
"""

from collections import namedtuple

Technique = namedtuple(
    'Technique',
    'id name tactic url rationale',
)

_B = 'https://attack.mitre.org/techniques/'

TECHNIQUES = {
    'T1046': Technique(
        'T1046', 'Network Service Discovery', 'Discovery', _B + 'T1046/',
        'A single source contacting many distinct destination ports on a host '
        'is the defining network signature of service enumeration.',
    ),
    'T1595': Technique(
        'T1595', 'Active Scanning', 'Reconnaissance', _B + 'T1595/',
        'Sweeping many distinct destination hosts on a small port set (or via '
        'ICMP echo) is host-discovery reconnaissance rather than per-host '
        'service enumeration.',
    ),
    'T1110': Technique(
        'T1110', 'Brute Force', 'Credential Access', _B + 'T1110/',
        'Repeated authentication failures observed in-protocol (SSH, FTP 530, '
        'SMTP 535, POP3/IMAP -ERR/NO, HTTP 401) against one service.',
    ),
    'T1078': Technique(
        'T1078', 'Valid Accounts', 'Defense Evasion', _B + 'T1078/',
        'Many distinct usernames tried from one source, or a success following '
        'a failure burst, indicates credential stuffing with valid accounts.',
    ),
    'T1071.004': Technique(
        'T1071.004', 'Application Layer Protocol: DNS', 'Command and Control',
        _B + 'T1071/004/',
        'High-entropy, oversized DNS labels carrying encoded payload over TXT/'
        'NULL records is DNS used as a C2 transport.',
    ),
    'T1071.001': Technique(
        'T1071.001', 'Application Layer Protocol: Web Protocols',
        'Command and Control', _B + 'T1071/001/',
        'Low-jitter periodic HTTP/HTTPS callbacks to a fixed destination are '
        'the canonical implant beaconing pattern.',
    ),
    'T1572': Technique(
        'T1572', 'Protocol Tunneling', 'Command and Control', _B + 'T1572/',
        'Payload encapsulated in a protocol that does not normally carry it '
        '(ICMP echo data, or a known L7 protocol on a non-standard port).',
    ),
    'T1573': Technique(
        'T1573', 'Encrypted Channel', 'Command and Control', _B + 'T1573/',
        'Obsolete TLS versions, absent SNI or self-signed certificates hide '
        'channel content from inspection.',
    ),
    'T1041': Technique(
        'T1041', 'Exfiltration Over C2 Channel', 'Exfiltration', _B + 'T1041/',
        'Sustained high-volume outbound transfer from an internal host to a '
        'single external destination on its established channel.',
    ),
    'T1048': Technique(
        'T1048', 'Exfiltration Over Alternative Protocol', 'Exfiltration',
        _B + 'T1048/',
        'Data leaving over a protocol not used for normal C2 — DNS label '
        'encoding or ICMP payload padding.',
    ),
    'T1021': Technique(
        'T1021', 'Remote Services', 'Lateral Movement', _B + 'T1021/',
        'Internal-to-internal connections on remote administration services '
        '(SMB 445, RDP 3389, WinRM 5985/5986, VNC 5900) with host fan-out.',
    ),
    'T1557.002': Technique(
        'T1557.002', 'Adversary-in-the-Middle: ARP Cache Poisoning',
        'Credential Access', _B + 'T1557/002/',
        'One MAC claiming an IP already bound to a different MAC, or a burst '
        'of gratuitous ARP replies, poisons peer ARP caches.',
    ),
    'T1498': Technique(
        'T1498', 'Network Denial of Service', 'Impact', _B + 'T1498/',
        'Half-open TCP SYN volume or raw UDP packet rate against one target '
        'exhausts its connection table or link capacity.',
    ),
    'T1498.002': Technique(
        'T1498.002', 'Network Denial of Service: Reflection Amplification',
        'Impact', _B + 'T1498/002/',
        'Small requests to NTP monlist / DNS ANY / SNMP getbulk returning much '
        'larger responses, indicating use as a reflector.',
    ),
    'T1190': Technique(
        'T1190', 'Exploit Public-Facing Application', 'Initial Access',
        _B + 'T1190/',
        'SQL injection, traversal or command-injection patterns in HTTP '
        'request lines and headers targeting an exposed service.',
    ),
}


def get(technique_id):
    return TECHNIQUES.get(technique_id)


def all_techniques():
    return list(TECHNIQUES.values())


def technique_count():
    return len(TECHNIQUES)


def tactics():
    """Distinct tactics covered, in ATT&CK kill-chain order where known."""
    order = [
        'Reconnaissance', 'Initial Access', 'Execution', 'Persistence',
        'Privilege Escalation', 'Defense Evasion', 'Credential Access',
        'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
        'Exfiltration', 'Impact',
    ]
    present = {t.tactic for t in TECHNIQUES.values()}
    return [t for t in order if t in present]
