"""Capture-layer tests: PCAP round trip, streaming, and the corpus manifest."""

import os

import pytest

import frames as F
import pcap_io
from PacketSimulator import TrafficGenerator
from ProtocolAnalyzer import ProtocolAnalyzer
from tools import make_pcaps

from conftest import BASE_TS


@pytest.fixture
def sample_frames():
    gen = TrafficGenerator(seed=4242)
    return gen.background(200, start_ts=BASE_TS)


def test_scapy_is_available():
    assert pcap_io.scapy_version(), 'scapy is a hard dependency of replay'


def test_round_trip_is_byte_identical(tmp_path, sample_frames):
    """A capture written and read back must be the same bytes.

    This is what lets the corpus double as ground truth: the analyzer sees
    exactly the frames the generator produced, with no dissect/rebuild step
    in between.
    """
    path = str(tmp_path / 'rt.pcap')
    written = pcap_io.write_pcap(path, sample_frames)
    assert written == len(sample_frames)

    back = pcap_io.read_pcap(path)
    assert len(back) == len(sample_frames)
    for (ts_in, frame_in), (ts_out, frame_out) in zip(sample_frames, back):
        assert frame_in == frame_out
        # PCAP stores microseconds, so timestamps survive to 1 us.
        assert abs(ts_in - ts_out) < 1e-5


def test_written_file_is_a_real_pcap(tmp_path, sample_frames):
    path = str(tmp_path / 'magic.pcap')
    pcap_io.write_pcap(path, sample_frames)
    with open(path, 'rb') as fh:
        magic = fh.read(4)
    # libpcap magic, either endianness.
    assert magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4')


def test_iter_pcap_streams_and_respects_limit(tmp_path, sample_frames):
    path = str(tmp_path / 'stream.pcap')
    pcap_io.write_pcap(path, sample_frames)
    stream = pcap_io.iter_pcap(path)
    assert not isinstance(stream, list)
    assert len(list(pcap_io.iter_pcap(path, limit=10))) == 10


def test_summary_reports_packets_span_and_digest(tmp_path, sample_frames):
    path = str(tmp_path / 'summary.pcap')
    pcap_io.write_pcap(path, sample_frames)
    summary = pcap_io.pcap_summary(path)
    assert summary['packets'] == len(sample_frames)
    assert summary['duration_s'] > 0
    assert len(summary['sha256']) == 64
    assert summary['file_bytes'] > summary['bytes']   # per-record headers


def test_replayed_frames_parse_the_same_as_direct_frames(tmp_path,
                                                         sample_frames):
    """Going through a PCAP must not change what the analyzer decodes."""
    path = str(tmp_path / 'parse.pcap')
    pcap_io.write_pcap(path, sample_frames)

    direct = ProtocolAnalyzer()
    replayed = ProtocolAnalyzer()
    for (ts, frame), (rts, rframe) in zip(sample_frames,
                                          pcap_io.read_pcap(path)):
        a = direct.safe_parse(frame, ts)
        b = replayed.safe_parse(rframe, rts)
        assert (a is None) == (b is None)
        if a is not None:
            assert a['protocol'] == b['protocol']
            assert a['src_ip'] == b['src_ip']
            assert a['dst_ip'] == b['dst_ip']
    assert direct.stats == replayed.stats


def test_write_creates_missing_directories(tmp_path):
    path = str(tmp_path / 'deep' / 'nested' / 'x.pcap')
    pcap_io.write_pcap(path, [(BASE_TS, F.tcp_frame(
        b'x', '10.0.0.1', '10.0.0.2', 1000, 80))])
    assert os.path.exists(path)


def test_empty_capture_round_trips(tmp_path):
    path = str(tmp_path / 'empty.pcap')
    assert pcap_io.write_pcap(path, []) == 0
    assert pcap_io.read_pcap(path) == []


def test_live_sniffer_is_constructible_without_capturing():
    """The live-capture seam exists and is wired to process(frame, ts).

    It is built but never started: starting it needs CAP_NET_RAW and a real
    interface, neither of which a test run has.
    """
    seen = []
    sniffer = pcap_io.live_sniffer(lambda frame, ts: seen.append((frame, ts)),
                                   bpf_filter='ip')
    assert sniffer is not None
    assert not seen


# ── corpus manifest ──────────────────────────────────────────────────────────

def test_generated_corpus_is_reproducible(tmp_path):
    """Two independent generations must produce identical bytes."""
    first = make_pcaps.build_attack('port_scan', seed=7)
    second = make_pcaps.build_attack('port_scan', seed=7)
    assert first == second

    path_a = str(tmp_path / 'a.pcap')
    path_b = str(tmp_path / 'b.pcap')
    pcap_io.write_pcap(path_a, first)
    pcap_io.write_pcap(path_b, second)
    assert (pcap_io.pcap_summary(path_a)['sha256']
            == pcap_io.pcap_summary(path_b)['sha256'])


def test_attack_capture_contains_background_and_attack():
    """Attack captures embed the attack in benign traffic, not in isolation."""
    frames = make_pcaps.build_attack('port_scan', seed=7)
    assert len(frames) > make_pcaps.ATTACK_BACKGROUND_PACKETS
    timestamps = [ts for ts, _f in frames]
    assert timestamps == sorted(timestamps), 'capture is not chronological'


def test_every_scenario_has_ground_truth():
    for name in TrafficGenerator.SCENARIOS:
        expected = TrafficGenerator.expected_threats(name)
        assert expected, '%s has no expected threat type' % name
