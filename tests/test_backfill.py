"""Warm-start history: a fresh demo shows detections without waiting for them."""

import time

import pytest

from App import _simulate
from PacketSimulator import TrafficGenerator

from conftest import SEED


def test_history_stays_inside_its_window():
    gen = TrafficGenerator(seed=SEED)
    start, end = 10_000.0, 10_000.0 + 900
    frames = gen.history(start, end, rate_pps=5)
    stamps = [ts for ts, _frame in frames]
    assert stamps == sorted(stamps)
    assert min(stamps) >= start and max(stamps) <= end


def test_history_skips_scenarios_longer_than_the_window():
    gen = TrafficGenerator(seed=SEED)
    frames = gen.history(0.0, 60.0, rate_pps=5)     # c2_beacon runs ~11 min
    assert frames and max(ts for ts, _f in frames) <= 60.0


def test_empty_window_yields_nothing():
    assert TrafficGenerator(seed=SEED).history(5.0, 5.0) == []


def test_backfill_populates_recent_history(simulator, db):
    before = time.time()
    findings = simulator.backfill(15, rate_pps=5)
    after = time.time()

    threat_types = {f.threat_type for f in findings}
    assert len(threat_types) >= 12, sorted(threat_types)

    oldest = db._scalar('SELECT MIN(ts) FROM packets')
    newest = db._scalar('SELECT MAX(ts) FROM packets')
    assert oldest >= before - 15 * 60 - 1
    assert newest <= after, 'backfill wrote packets in the future'
    assert db.get_overview()['total_alerts'] == len(findings)


def test_backfill_of_zero_minutes_does_nothing(simulator, db):
    assert simulator.backfill(0) == []
    assert db.health()['tables']['packets'] == 0


def test_simulate_backfills_before_going_live(monkeypatch):
    calls = []

    class Recorder:
        def backfill(self, minutes):
            calls.append(('backfill', minutes))

        def run(self, rate_pps):
            calls.append(('run', rate_pps))

    monkeypatch.setenv('NETWATCH_BACKFILL_MIN', '10')
    monkeypatch.setenv('NETWATCH_RATE_PPS', '40')
    _simulate(Recorder())
    assert calls == [('backfill', 10.0), ('run', 40.0)]


def test_simulate_skips_backfill_by_default(monkeypatch):
    calls = []

    class Recorder:
        def backfill(self, minutes):
            calls.append('backfill')

        def run(self, rate_pps):
            calls.append(('run', rate_pps))

    monkeypatch.delenv('NETWATCH_BACKFILL_MIN', raising=False)
    monkeypatch.delenv('NETWATCH_RATE_PPS', raising=False)
    _simulate(Recorder())
    assert calls == [('run', 95.0)]


@pytest.mark.parametrize('raw', ['soon', '-1'])
def test_simulate_rejects_bad_settings(monkeypatch, raw):
    monkeypatch.setenv('NETWATCH_BACKFILL_MIN', raw)
    with pytest.raises(ValueError):
        _simulate(object())
