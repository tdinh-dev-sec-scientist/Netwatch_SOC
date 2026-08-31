"""
Detection thresholds and engine tuning for NetWatch SOC.

Every threshold a detector uses lives here so it can be tuned without touching
detection logic. Overrides are layered on top of the defaults from a JSON file
pointed at by the NETWATCH_CONFIG environment variable:

    NETWATCH_CONFIG=/etc/netwatch/thresholds.json python App.py

The JSON is a partial, nested override — only the keys you name are replaced:

    {"port_scan": {"distinct_ports": 30}, "engine": {"packet_batch": 500}}
"""

import copy
import json
import os

DEFAULTS = {
    # ── engine ───────────────────────────────────────────────────────────────
    'engine': {
        'packet_batch': 400,        # packets buffered before a bulk INSERT
        'flush_interval_s': 2.0,    # max seconds a batch may sit unwritten
        'state_ttl_s': 900,         # drop per-key detector state after idle
        'gc_interval_s': 60,        # how often to sweep expired state
        'store_packets': True,      # persist every packet row
    },

    # ── reconnaissance / discovery ───────────────────────────────────────────
    'port_scan': {
        'distinct_ports': 20,       # distinct dst ports on one host
        'window_s': 60,
        'cooldown_s': 120,
    },
    'network_recon': {
        'distinct_hosts': 25,       # distinct dst IPs from one source
        'window_s': 60,
        'max_distinct_ports': 3,    # a sweep hits few ports on many hosts
        'icmp_sweep_hosts': 15,
        'cooldown_s': 120,
    },

    # ── credential access ────────────────────────────────────────────────────
    'brute_force': {
        'failures': 5,              # in-protocol auth failures per service
        'window_s': 120,
        'cooldown_s': 120,
    },
    'credential_attack': {
        'distinct_users': 8,        # distinct usernames from one source
        'window_s': 300,
        'cooldown_s': 300,
        'alert_on_cleartext': True, # Telnet/FTP/HTTP-Basic credentials
    },

    # ── command and control ──────────────────────────────────────────────────
    'c2_beacon': {
        # With only a handful of samples, ordinary chatty traffic can look
        # regular by chance, so require a longer run of callbacks and tighter
        # jitter than a first pass suggests. min_interval_s excludes rapid
        # request/response chatter, which is periodic but not a beacon.
        'min_callbacks': 8,         # samples needed before judging regularity
        'window_s': 1800,
        'max_jitter_ratio': 0.12,   # stddev/mean of inter-arrival times
        'min_interval_s': 15,
        'max_interval_s': 900,
        'cooldown_s': 600,
    },
    'dns_tunnel': {
        'min_label_len': 40,        # oversized single label
        'min_entropy': 3.8,         # bits/byte over the encoded labels
        'min_qname_len': 60,
        'suspicious_qtypes': [10, 16, 255],   # NULL, TXT, ANY
        'query_volume': 40,         # queries to one zone in the window
        'window_s': 300,
        'cooldown_s': 300,
    },
    'icmp_tunnel': {
        'min_payload_len': 128,     # normal ping payloads are 32-56 bytes
        'min_entropy': 5.5,
        'volume': 10,
        'window_s': 120,
        'cooldown_s': 300,
    },
    'protocol_tunnel': {
        'observations': 3,          # L7 protocol seen on a non-standard port
        'window_s': 300,
        'cooldown_s': 600,
    },
    'tls_anomaly': {
        'obsolete_versions': ['SSLv3', 'TLS1.0', 'TLS1.1'],
        'min_cipher_count': 3,      # unusually short cipher lists
        'cooldown_s': 300,
    },

    # ── exfiltration ─────────────────────────────────────────────────────────
    'data_exfil': {
        'bytes_threshold': 5_000_000,   # internal -> external, per window
        'window_s': 300,
        'min_packets': 20,
        'cooldown_s': 600,
    },

    # ── lateral movement ─────────────────────────────────────────────────────
    'lateral_movement': {
        'admin_ports': [445, 3389, 5985, 5986, 5900, 135, 139],
        'distinct_hosts': 3,        # internal fan-out on admin services
        'window_s': 300,
        'cooldown_s': 300,
    },

    # ── impact / denial of service ───────────────────────────────────────────
    'syn_flood': {
        'syn_rate': 200,            # SYNs to one destination in the window
        'window_s': 10,
        'min_syn_ack_ratio': 5.0,   # SYNs per completed handshake
        'cooldown_s': 60,
    },
    'udp_flood': {
        'packet_rate': 400,         # UDP packets to one destination
        'window_s': 10,
        'cooldown_s': 60,
    },
    'amplification': {
        'response_ratio': 5.0,      # response bytes / request bytes
        'min_response_len': 400,
        'observations': 3,
        'window_s': 60,
        'cooldown_s': 300,
    },

    # ── initial access ───────────────────────────────────────────────────────
    'http_anomaly': {
        'max_uri_len': 2048,
        'max_header_len': 8192,
        'cooldown_s': 60,
    },

    # ── ARP ──────────────────────────────────────────────────────────────────
    'arp_spoof': {
        'gratuitous_rate': 5,       # gratuitous replies in the window
        'window_s': 60,
        'cooldown_s': 120,
        'alert_on_binding_conflict': True,
    },

    # ── suspicious DNS (non-tunneling) ───────────────────────────────────────
    'suspicious_dns': {
        'nxdomain_count': 15,       # NXDOMAIN responses to one client
        'nxdomain_ratio': 0.4,
        'window_s': 300,
        'dga_entropy': 3.6,         # entropy of the second-level label
        'dga_min_len': 12,
        'dga_count': 5,
        'cooldown_s': 300,
    },
}

_INTERNAL_NETS = [
    ('10.0.0.0', 8), ('172.16.0.0', 12), ('192.168.0.0', 16),
    ('127.0.0.0', 8), ('169.254.0.0', 16),
]


def _deep_merge(base, override):
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load(path=None):
    """Return the effective threshold config (defaults + optional overrides)."""
    path = path or os.environ.get('NETWATCH_CONFIG')
    if not path:
        return copy.deepcopy(DEFAULTS)
    with open(path, 'r', encoding='utf-8') as fh:
        return _deep_merge(DEFAULTS, json.load(fh))
