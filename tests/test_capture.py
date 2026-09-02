"""Frame sources: the seam a real capture backend plugs into."""

import time

import pytest
from conftest import SEED

from netwatch.capture.generator import TrafficGenerator
from netwatch.capture.source import (
    WORKLOAD_SCENARIOS,
    FrameSource,
    ListSource,
    SyntheticSource,
    fixed_workload,
)


def test_frame_source_is_abstract():
    with pytest.raises(NotImplementedError):
        list(FrameSource().frames())


def test_list_source_replays_exactly_once():
    pairs = [(1.0, b'a'), (2.0, b'b')]
    source = ListSource(pairs)
    assert list(source.frames()) == pairs
    assert len(source) == 2


def test_list_source_can_restamp_to_the_wall_clock():
    """Benchmarks measure latency against real ingress, not synthetic time."""
    before = time.time()
    stamped = list(ListSource([(0.0, b'a'), (0.0, b'b')],
                              stamp_now=True).frames())
    assert all(ts >= before for ts, _frame in stamped)


def test_list_source_preserves_timestamps_by_default():
    pairs = [(1234.5, b'a')]
    assert list(ListSource(pairs).frames())[0][0] == 1234.5


def test_synthetic_source_respects_a_count_limit():
    frames = list(SyntheticSource(seed=SEED, count=25, scenario_every_s=0
                                  ).frames())
    assert len(frames) == 25
    assert all(isinstance(frame, (bytes, bytearray)) for _ts, frame in frames)


def test_synthetic_source_stops_when_asked():
    source = SyntheticSource(seed=SEED, scenario_every_s=0)
    frames = []
    for pair in source.frames():
        frames.append(pair)
        if len(frames) == 10:
            source.stop()
    assert len(frames) == 10


def test_synthetic_source_respects_a_duration():
    started = time.time()
    frames = list(SyntheticSource(seed=SEED, duration_s=0.2,
                                  scenario_every_s=0).frames())
    assert time.time() - started < 5.0
    assert frames


def test_synthetic_source_paces_to_a_target_rate():
    started = time.perf_counter()
    frames = list(SyntheticSource(seed=SEED, rate_pps=200, count=60,
                                  scenario_every_s=0).frames())
    elapsed = time.perf_counter() - started
    assert len(frames) == 60
    # 60 frames at 200/s is 0.3s; allow generous slack for a loaded machine.
    assert 0.15 < elapsed < 3.0


def test_synthetic_source_injects_attack_scenarios():
    source = SyntheticSource(seed=SEED, count=400, scenario_every_s=0.0001,
                             scenarios=['port_scan'])
    frames = list(source.frames())
    assert len(frames) == 400


def test_generated_traffic_is_reproducible_from_a_seed():
    first = list(SyntheticSource(seed=99, count=50, scenario_every_s=0
                                 ).frames())
    second = list(SyntheticSource(seed=99, count=50, scenario_every_s=0
                                  ).frames())
    assert [f for _t, f in first] == [f for _t, f in second]


def test_different_seeds_produce_different_traffic():
    first = [f for _t, f in SyntheticSource(seed=1, count=50,
                                            scenario_every_s=0).frames()]
    second = [f for _t, f in SyntheticSource(seed=2, count=50,
                                             scenario_every_s=0).frames()]
    assert first != second


def test_fixed_workload_is_ordered_and_contains_every_scenario():
    frames = fixed_workload(500, seed=SEED, start_ts=0.0)
    stamps = [ts for ts, _f in frames]
    assert stamps == sorted(stamps)
    assert len(frames) > 500, 'attack scenarios were not layered on'


def test_fixed_workload_is_byte_identical_for_a_seed():
    first = fixed_workload(200, seed=5, start_ts=0.0)
    second = fixed_workload(200, seed=5, start_ts=0.0)
    assert first == second


def test_workload_scenarios_are_all_known_to_the_generator():
    assert set(WORKLOAD_SCENARIOS) <= set(TrafficGenerator.SCENARIOS)
