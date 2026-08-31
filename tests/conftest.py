"""Shared fixtures. All tests use deterministic seeds and temporary databases."""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config as config_module            # noqa: E402
from DB_Manager import DatabaseManager     # noqa: E402
from PacketSimulator import PacketSimulator, TrafficGenerator  # noqa: E402
from ProtocolAnalyzer import ProtocolAnalyzer  # noqa: E402
from ThreatDetector import ThreatDetector  # noqa: E402

SEED = 20240301
# Fixture traffic must land in the recent past: the API's queries are all
# time-windowed, so a fixed historical timestamp would be filtered out of
# every result and mask real failures.
BASE_TS = time.time() - 1800.0


@pytest.fixture
def cfg():
    return config_module.load()


@pytest.fixture
def analyzer():
    return ProtocolAnalyzer()


@pytest.fixture
def engine(cfg):
    return ThreatDetector(cfg=cfg)


@pytest.fixture
def gen():
    return TrafficGenerator(seed=SEED)


@pytest.fixture
def db(tmp_path):
    manager = DatabaseManager(str(tmp_path / 'netwatch_test.db'))
    yield manager
    manager.close()


@pytest.fixture
def simulator(db, engine, analyzer):
    return PacketSimulator(db, engine, analyzer, seed=SEED)


@pytest.fixture(scope='session')
def populated_db(tmp_path_factory):
    """A database filled by the real pipeline — background plus every attack.

    Session-scoped: running every scenario writes ~9k packets, which is slow
    to repeat per test. Nothing here depends on mutation isolation; the one
    test that acknowledges an alert picks its own target.
    """
    path = tmp_path_factory.mktemp('netwatch') / 'populated.db'
    manager = DatabaseManager(str(path))
    engine = ThreatDetector(cfg=config_module.load())
    sim = PacketSimulator(manager, engine, ProtocolAnalyzer(), seed=SEED)

    generator = TrafficGenerator(seed=SEED)
    frames = generator.background(3000, start_ts=BASE_TS)
    span = frames[-1][0] - frames[0][0]
    step = span / (len(TrafficGenerator.SCENARIOS) + 1)
    for i, name in enumerate(TrafficGenerator.SCENARIOS):
        frames.extend(generator.scenario(
            name, start_ts=BASE_TS + step * (i + 1)))
    frames.sort(key=lambda pair: pair[0])
    sim.run_frames(frames)

    manager.engine_for_tests = engine
    yield manager
    manager.close()


@pytest.fixture
def client(populated_db):
    from App import create_app
    app = create_app(db=populated_db, engine=populated_db.engine_for_tests,
                     start_simulation=False)
    app.config['TESTING'] = True
    with app.test_client() as test_client:
        yield test_client


def run_scenario(engine, analyzer, generator, name, start_ts=BASE_TS,
                 **kwargs):
    """Push one scenario through parse + detect, returning the findings."""
    findings = []
    for ts, frame in generator.scenario(name, start_ts=start_ts, **kwargs):
        pkt = analyzer.safe_parse(frame, ts)
        if pkt is not None:
            findings.extend(engine.analyze(pkt))
    return findings
