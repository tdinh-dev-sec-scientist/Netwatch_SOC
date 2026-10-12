"""Regressions found by replaying CSE-CIC-IDS2018 (see eval/cicids2018/).

Each test reproduces, in synthetic frames, one pattern that real traffic
exposed and the synthetic generator never produced. Also covers replay.py,
the pcap front end that made the run possible.
"""

import json
import struct

import frames as F
import replay
from ThreatDetector import ThreatDetector

from conftest import BASE_TS

INTERNAL = '172.31.69.10'
EXTERNAL = '18.219.211.138'


def _run(engine, analyzer, stamped_frames):
    findings = []
    for ts, frame in stamped_frames:
        pkt = analyzer.safe_parse(frame, ts)
        if pkt is not None:
            findings.extend(engine.analyze(pkt))
    return findings


def _types(findings):
    return {f.threat_type for f in findings}


# ── protocol_tunnel: TLS on RDP ──────────────────────────────────────────────

def test_tls_inside_rdp_is_not_a_tunnel(engine, analyzer):
    """RDP's standard security layer is a TLS handshake on 3389.

    Was 48,904 false alerts — 83% of all false positives — on the replay.
    """
    out, ts = [], BASE_TS
    for i in range(20):
        out.append((ts, F.tcp_frame(F.tls_client_hello(None), '5.101.40.105',
                                    INTERNAL, 50000 + i, 3389)))
        out.append((ts + 0.05, F.tcp_frame(F.tls_application_data(),
                                           INTERNAL, '5.101.40.105', 3389,
                                           50000 + i)))
        ts += 2.0
    assert 'protocol_tunnel' not in _types(_run(engine, analyzer, out))


def test_ssh_on_443_is_still_a_tunnel(engine, analyzer):
    """The exemption is for TLS on TLS-upgrading ports, nothing wider."""
    out = [(BASE_TS + i, F.tcp_frame(F.ssh_banner(), INTERNAL, EXTERNAL,
                                     51000 + i, 443)) for i in range(6)]
    assert 'protocol_tunnel' in _types(_run(engine, analyzer, out))


# ── tls_anomaly: direction ───────────────────────────────────────────────────

def test_legacy_tls_from_the_internet_is_not_our_encrypted_channel(
        engine, analyzer):
    hello = F.tls_client_hello(None, version=0x0301, cipher_count=2)
    inbound = [(BASE_TS + 5 * i, F.tcp_frame(hello, '212.92.116.6', INTERNAL,
                                             52000 + i, 3389))
               for i in range(6)]
    assert 'tls_anomaly' not in _types(_run(engine, analyzer, inbound))


def test_legacy_tls_from_an_internal_client_still_alerts(engine, analyzer):
    hello = F.tls_client_hello(None, version=0x0301, cipher_count=2)
    outbound = [(BASE_TS + 5 * i, F.tcp_frame(hello, INTERNAL, EXTERNAL,
                                              52000 + i, 443))
                for i in range(6)]
    assert 'tls_anomaly' in _types(_run(engine, analyzer, outbound))


# ── port_scan: replies from a high service port ──────────────────────────────

def test_replies_from_a_high_port_service_are_not_a_scan(engine, analyzer):
    """A busy HTTP server on 8080 answering a client's many connections.

    The botnet C2 on 8080 was reported as port-scanning its own victims,
    because the old reply test only recognised source ports below 1024.
    """
    out, ts = [], BASE_TS
    for i in range(60):
        port = 50700 + i
        out.append((ts, F.tcp_frame(b'', INTERNAL, EXTERNAL, port, 8080,
                                    'SYN')))
        out.append((ts + 0.01, F.tcp_frame(b'', EXTERNAL, INTERNAL, 8080,
                                           port, 'SYN|ACK')))
        out.append((ts + 0.02, F.tcp_frame(F.http_response(), EXTERNAL,
                                           INTERNAL, 8080, port, 'PSH|ACK')))
        ts += 0.5
    assert 'port_scan' not in _types(_run(engine, analyzer, out))


def test_fin_scan_still_counts_as_a_scan(engine, analyzer):
    out = [(BASE_TS + 0.05 * i, F.tcp_frame(b'', '185.220.101.44', INTERNAL,
                                            40000, 1 + i, 'FIN'))
           for i in range(40)]
    assert 'port_scan' in _types(_run(engine, analyzer, out))


# ── ECN-setup SYNs ───────────────────────────────────────────────────────────

def test_ecn_syns_are_counted_as_syns(engine, analyzer):
    """Windows opens connections with SYN|ECE|CWR; it is still a SYN."""
    out = [(BASE_TS + 0.02 * i, F.tcp_frame(b'', '203.0.113.%d' % (i % 250),
                                            INTERNAL, 40000 + i, 80,
                                            0xC2))   # SYN|ECE|CWR
           for i in range(400)]
    assert 'syn_flood' in _types(_run(engine, analyzer, out))


# ── c2_beacon: direction and cost ────────────────────────────────────────────

def test_keepalives_on_one_tls_session_are_not_a_beacon(engine, analyzer):
    """One long-lived connection with a 60 s keep-alive in each direction.

    Windows push and telemetry services do exactly this; it was reported as
    beaconing both from the client and, reversed, from the server.
    """
    out, ts = [], BASE_TS
    for _ in range(30):
        out.append((ts, F.tcp_frame(F.tls_application_data(64), INTERNAL,
                                    '13.89.184.96', 49671, 443)))
        out.append((ts + 0.1, F.tcp_frame(F.tls_application_data(64),
                                          '13.89.184.96', INTERNAL, 443,
                                          49671)))
        ts += 60.0
    assert 'c2_beacon' not in _types(_run(engine, analyzer, out))


def test_periodic_new_tls_sessions_are_still_a_beacon(engine, analyzer):
    hello = F.tls_client_hello('cdn.updates.top')
    out = [(BASE_TS + 60.0 * i, F.tcp_frame(hello, INTERNAL, EXTERNAL,
                                            49000 + i, 443))
           for i in range(14)]
    assert 'c2_beacon' in _types(_run(engine, analyzer, out))


def test_beacon_cost_does_not_grow_with_a_flood(analyzer, cfg):
    """A sustained SYN storm on one channel must stay cheap per packet.

    Before the O(1) range check every SYN copied the whole 30-minute window
    to compute its intervals. Counts window traversals rather than seconds,
    so it cannot flake on a slow machine.
    """
    engine = ThreatDetector(cfg=cfg)
    channels = engine.get('c2_beacon')._channels
    original = channels.timestamps
    walks = []

    class Watched:
        def __init__(self, dq):
            self._dq = dq

        def __len__(self):
            return len(self._dq)

        def __getitem__(self, i):
            return self._dq[i]

        def __iter__(self):
            walks.append(len(self._dq))
            return iter(self._dq)

    channels.timestamps = lambda key: Watched(original(key))
    for i in range(3000):
        pkt = analyzer.safe_parse(F.tcp_frame(
            b'', '18.221.219.4', '172.31.69.25', 30000 + i, 21, 'SYN'),
            BASE_TS + i * 0.03)
        engine.analyze(pkt)
    assert len(channels) == 1 and len(original(next(iter(
        channels._events)))) == 3000   # the window really did fill
    assert not walks


# ── replay.py ────────────────────────────────────────────────────────────────

def _write_pcap(path, records, linktype=1, nanos=False):
    magic = 0xa1b23c4d if nanos else 0xa1b2c3d4
    with open(path, 'wb') as fh:
        fh.write(struct.pack('<IHHiIII', magic, 2, 4, 0, 0, 65535, linktype))
        for ts, data in records:
            sec = int(ts)
            frac = int(round((ts - sec) * (1e9 if nanos else 1e6)))
            fh.write(struct.pack('<IIII', sec, frac, len(data), len(data)))
            fh.write(data)


def test_replay_reads_pcap_and_reports_findings(tmp_path):
    frames = [(BASE_TS + 0.05 * i, F.tcp_frame(b'', '185.220.101.44',
                                               INTERNAL, 40000, 1 + i * 3,
                                               'SYN'))
              for i in range(40)]
    path = tmp_path / 'scan.pcap'
    _write_pcap(path, frames)
    alerts = []
    summary = replay.replay([str(path)], on_finding=alerts.append)
    assert summary['packets'] == 40 and summary['parse_errors'] == 0
    assert summary['alerts_by_type'].get('port_scan')
    assert abs(alerts[0]['ts'] - frames[19][0]) < 1e-3   # capture clock
    json.dumps(alerts)                                    # serialisable


def test_replay_handles_nanosecond_and_raw_ip_captures(tmp_path):
    frame = F.tcp_frame(b'', INTERNAL, EXTERNAL, 40000, 443, 'SYN')
    path = tmp_path / 'raw.pcap'
    _write_pcap(path, [(BASE_TS + 0.123456789, frame[14:])],
                linktype=replay.LINKTYPE_RAW, nanos=True)
    (ts, eth), = list(replay.read_pcap(str(path)))
    assert abs(ts - (BASE_TS + 0.123456789)) < 1e-6
    assert eth[12:14] == b'\x08\x00' and eth[14:] == frame[14:]


def test_replay_rejects_pcapng(tmp_path):
    path = tmp_path / 'capture.pcapng'
    path.write_bytes(b'\x0a\x0d\x0d\x0a' + b'\x00' * 28)
    try:
        list(replay.read_pcap(str(path)))
    except ValueError as exc:
        assert 'pcapng' in str(exc)
    else:
        raise AssertionError('pcapng accepted')


def test_replay_persists_through_the_live_write_path(db, tmp_path):
    """--persist writes the same rows live capture does, on the capture clock
    shifted by --rebase-now's offset."""
    frames = [(1000.0 + 0.05 * i, F.tcp_frame(b'', '185.220.101.44',
                                              INTERNAL, 40000, 1 + i * 3,
                                              'SYN'))
              for i in range(40)]
    path = tmp_path / 'scan.pcap'
    _write_pcap(path, frames)
    shift = BASE_TS - replay.last_timestamp(str(path))
    summary = replay.replay([str(path)], db=db, shift_s=shift)

    overview = db.get_overview()
    assert overview['total_packets'] == summary['packets'] == 40
    alerts = db.get_alerts(threat_type='port_scan')['alerts']
    assert alerts and alerts[0]['src_ip'] == '185.220.101.44'
    assert abs(alerts[0]['ts'] - (frames[19][0] + shift)) < 1e-3
