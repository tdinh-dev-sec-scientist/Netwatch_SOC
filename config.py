"""
Detection thresholds and engine tuning for NetWatch SOC.

Every threshold a detector uses lives here so it can be tuned without touching
detection logic. Three layers compose, in order:

  1. DEFAULTS      the shipped, tuned posture
  2. a profile     PROFILES[name], applied on top (see UNTUNED below)
  3. a JSON file   NETWATCH_CONFIG, a partial nested override

    NETWATCH_CONFIG=/etc/netwatch/thresholds.json python App.py
    {"port_scan": {"distinct_ports": 30}, "engine": {"packet_batch": 500}}

The `untuned` profile is not a strawman — it is the posture this detector set
actually started from, and it is what tools/noise_experiment.py measures
against. Every difference between it and DEFAULTS is one of three kinds of
decision, each annotated inline:

  * a textbook threshold that a benign baseline showed was too tight
  * a corroborating signal that a first pass did not require
  * alert deduplication, which a first pass has none of

Both profiles run the same detection code down the same paths, so the
difference in alert volume between them is a property of the configuration
and nothing else.
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
        # A service reply fans out across the *client's* ephemeral ports, so
        # counting replies makes every busy resolver look like a scanner.
        'ignore_service_responses': True,
        'ignore_rst': True,         # a RST back to the scanner is not scanning
        # Second, slower time scale. A scan paced at one port every 12s never
        # puts enough ports inside a 60s window, but it is still a scan. The
        # threshold is higher because 900s of ordinary traffic legitimately
        # touches more ports than 60s of it does.
        'long_window_s': 900,
        'long_distinct_ports': 30,
    },
    'network_recon': {
        'distinct_hosts': 25,       # distinct dst IPs from one source
        'window_s': 60,
        'max_distinct_ports': 3,    # a sweep hits few ports on many hosts
        'icmp_sweep_hosts': 15,
        'cooldown_s': 120,
        # A sweep walks one contiguous range; ordinary browsing is scattered
        # across unrelated networks. Grouping targets per /24 separates them.
        'group_by_subnet': True,
        'ignore_service_responses': True,
    },

    # ── credential access ────────────────────────────────────────────────────
    'brute_force': {
        'failures': 5,              # in-protocol auth failures per service
        'window_s': 120,
        'cooldown_s': 120,
        # SSH auth happens inside the encrypted channel, so only session
        # bursts are observable — noisier evidence, so it needs more of it.
        'ssh_threshold_multiplier': 2,
        'ssh_min_threshold': 10,
        # Second time scale, for guessing paced below the per-window rate.
        'long_window_s': 900,
        'long_failures': 10,
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
        # Tunnelling must stuff payload into the name, so an oversized label
        # is a necessary condition. Without it, CDN and antivirus hostnames —
        # legitimately long, numerous and random-looking — score highly on
        # entropy and volume alone.
        'require_oversized_label': True,
        'min_signals': 2,           # one indicator alone is too weak
        'min_score': 0.6,
        # ...but payload can also be split across several medium labels
        # (iodine and dnscat both do this), so a run of them satisfies the
        # same necessary condition. Three labels of 12+ chars in one name is
        # not a shape ordinary hostnames take.
        'min_encoded_labels': 3,
        'min_encoded_label_len': 12,
        'min_encoded_total_len': 45,
        # Shannon entropy is bounded by log2(label length), so a 12-character
        # label cannot exceed 3.58 bits/byte however random it is. The
        # per-label floor has to be lower than the whole-name one for that
        # reason, not because the bar is being relaxed.
        'min_encoded_label_entropy': 3.2,
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
        'min_score': 0.5,           # accumulated weight of the anomalies seen
    },

    # ── exfiltration ─────────────────────────────────────────────────────────
    'data_exfil': {
        'bytes_threshold': 5_000_000,   # internal -> external, per window
        'window_s': 300,
        'min_packets': 20,
        'cooldown_s': 600,
        # A large *inbound* transfer is a user downloading something. Only
        # bytes leaving the perimeter have the exfiltration shape.
        'outbound_only': True,
        # Splitting a transfer across several destinations keeps every flow
        # under the per-peer threshold, so the same volume is also totalled
        # per source across all of its external peers.
        'source_bytes_threshold': 5_000_000,
        'source_min_peers': 3,
    },

    # ── lateral movement ─────────────────────────────────────────────────────
    'lateral_movement': {
        'admin_ports': [445, 3389, 5985, 5986, 5900, 135, 139],
        'distinct_hosts': 3,        # internal fan-out on admin services
        'window_s': 300,
        'cooldown_s': 300,
        # Lateral movement is internal->internal by definition; a client
        # reaching an external SMB share is a different problem.
        'internal_only': True,
    },

    # ── impact / denial of service ───────────────────────────────────────────
    'syn_flood': {
        'syn_rate': 200,            # SYNs to one destination in the window
        'window_s': 10,
        'min_syn_ack_ratio': 5.0,   # SYNs per completed handshake
        'cooldown_s': 60,
        # Second time scale: a flood throttled below the 10s rate still
        # exhausts a connection table over a minute.
        'long_window_s': 60,
        'long_syn_rate': 600,
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
        # Signature weights are graded; a weak fragment match alone is not
        # enough to alert.
        'min_score': 0.5,
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

# ── the pre-tuning profile ───────────────────────────────────────────────────
#
# This is the first-pass detection posture, before any of it was measured
# against a benign baseline. It differs from DEFAULTS in exactly three ways,
# marked [T] threshold, [C] corroborating signal, [D] deduplication:
#
#   [T]  textbook thresholds, taken from what the technique looks like in
#        isolation rather than from what benign traffic actually does
#   [C]  single-signal rules — each detector alerts on its primary indicator
#        without requiring a second, independent one
#   [D]  no per-rule cooldown, so one sustained event alerts once per packet
#        that crosses the threshold instead of once per event
#
# tools/noise_experiment.py replays the same corpus under this profile and
# under DEFAULTS and reports the difference. Both run identical code.
UNTUNED = {
    'port_scan': {
        'distinct_ports': 10,               # [T] "10 ports = a scan"
        'ignore_service_responses': False,  # [C]
        'ignore_rst': False,                # [C]
        'long_distinct_ports': 0,           # [C] no slow-scan time scale
        'cooldown_s': 0,                    # [D]
    },
    'network_recon': {
        'distinct_hosts': 10,               # [T]
        'max_distinct_ports': 65535,        # [C] no narrow-port-set check
        'icmp_sweep_hosts': 5,              # [T]
        'group_by_subnet': False,           # [C] any hosts, not one /24
        'ignore_service_responses': False,  # [C]
        'cooldown_s': 0,                    # [D]
    },
    'brute_force': {
        'failures': 3,                      # [T] "three strikes"
        'ssh_threshold_multiplier': 1,      # [C] SSH treated like a 530
        'ssh_min_threshold': 3,             # [C]
        'long_failures': 0,                 # [C] no slow-guessing time scale
        'cooldown_s': 0,                    # [D]
    },
    'credential_attack': {
        'distinct_users': 3,                # [T]
        'cooldown_s': 0,                    # [D]
    },
    'c2_beacon': {
        'min_callbacks': 4,                 # [T] four points look periodic
        'max_jitter_ratio': 0.35,           # [T]
        'min_interval_s': 0,                # [C] no floor, so request/response
        'cooldown_s': 0,                    # [D]  chatter counts as beaconing
    },
    'dns_tunnel': {
        'min_label_len': 20,                # [T]
        'min_entropy': 3.0,                 # [T]
        'require_oversized_label': False,   # [C] entropy alone is enough
        'min_signals': 1,                   # [C]
        'min_score': 0.3,                   # [C]
        'min_encoded_labels': 0,            # [C] no multi-label encoding check
        'query_volume': 10,                 # [T]
        'cooldown_s': 0,                    # [D]
    },
    'suspicious_dns': {
        'nxdomain_count': 5,                # [T]
        'nxdomain_ratio': 0.0,              # [C] count without a ratio check
        'dga_entropy': 3.0,                 # [T]
        'dga_min_len': 8,                   # [T]
        'dga_count': 2,                     # [T]
        'cooldown_s': 0,                    # [D]
    },
    'icmp_tunnel': {
        'min_payload_len': 64,              # [T]
        'min_entropy': 0.0,                 # [C] size alone is enough
        'volume': 1,                        # [T]
        'cooldown_s': 0,                    # [D]
    },
    'protocol_tunnel': {
        'observations': 1,                  # [T] one mismatch is enough
        'cooldown_s': 0,                    # [D]
    },
    'tls_anomaly': {
        'min_cipher_count': 8,              # [T]
        'min_score': 0.25,                  # [C] any single anomaly alerts
        'cooldown_s': 0,                    # [D]
    },
    'data_exfil': {
        'bytes_threshold': 1_000_000,       # [T] "1 MB is a lot"
        'min_packets': 1,                   # [T]
        'outbound_only': False,             # [C] direction not checked
        'source_bytes_threshold': 0,        # [C] no per-source aggregation
        'cooldown_s': 0,                    # [D]
    },
    'lateral_movement': {
        'distinct_hosts': 1,                # [T] one admin session alerts
        'internal_only': False,             # [C]
        'cooldown_s': 0,                    # [D]
    },
    'syn_flood': {
        'syn_rate': 50,                     # [T]
        'min_syn_ack_ratio': 0.0,           # [C] rate without the handshake
        'long_syn_rate': 0,                 # [C]  completion ratio; and no
        'cooldown_s': 0,                    # [D]  slower time scale either
    },
    'udp_flood': {
        'packet_rate': 100,                 # [T]
        'cooldown_s': 0,                    # [D]
    },
    'amplification': {
        'response_ratio': 2.0,              # [T]
        'min_response_len': 100,            # [T]
        'observations': 1,                  # [C] one exchange is enough
        'cooldown_s': 0,                    # [D]
    },
    'http_anomaly': {
        'max_uri_len': 512,                 # [T]
        'min_score': 0.25,                  # [C] weak fragment matches alert
        'cooldown_s': 0,                    # [D]
    },
    'arp_spoof': {
        'gratuitous_rate': 1,               # [T] one gratuitous reply alerts
        'cooldown_s': 0,                    # [D]
    },
}

PROFILES = {
    'tuned': {},        # DEFAULTS as-is: what ships and what the API runs
    'untuned': UNTUNED,
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


def load(path=None, profile=None):
    """Return the effective threshold config.

    Layers, in order: DEFAULTS, the named profile, then the JSON override at
    `path` (or NETWATCH_CONFIG). `profile` defaults to NETWATCH_PROFILE, and
    then to 'tuned', which is DEFAULTS unchanged.
    """
    profile = profile or os.environ.get('NETWATCH_PROFILE') or 'tuned'
    if profile not in PROFILES:
        raise ValueError('unknown profile %r; choose from %s'
                         % (profile, ', '.join(sorted(PROFILES))))
    cfg = _deep_merge(DEFAULTS, PROFILES[profile])

    path = path or os.environ.get('NETWATCH_CONFIG')
    if not path:
        return cfg
    with open(path, 'r', encoding='utf-8') as fh:
        return _deep_merge(cfg, json.load(fh))


def profile_diff(profile):
    """(section, key, untuned_value, tuned_value) for every difference.

    Used by the noise-reduction report so the two postures can be compared
    line by line rather than taken on trust.
    """
    rows = []
    for section, overrides in sorted(PROFILES[profile].items()):
        for key, value in sorted(overrides.items()):
            rows.append((section, key, value, DEFAULTS[section][key]))
    return rows
