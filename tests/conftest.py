"""Shared fixtures. All tests use deterministic seeds and disposable databases.

By default every fixture gets its own SQLite file under pytest's tmp_path. Set
NETWATCH_TEST_DB_URL to a postgresql:// URL and the identical suite runs
against PostgreSQL instead, with each fixture isolated in its own schema:

    NETWATCH_TEST_DB_URL=postgresql://netwatch:netwatch@127.0.0.1/netwatch \
        pytest -q
"""

import itertools
import os
import sys
import time
import uuid

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


TEST_DB_URL = os.environ.get('NETWATCH_TEST_DB_URL')
BACKEND = 'postgresql' if TEST_DB_URL else 'sqlite'
_schema_counter = itertools.count()


def make_db(tmp_path, name='netwatch_test'):
    """A disposable DatabaseManager on whichever backend is under test."""
    if TEST_DB_URL:
        schema = 'nw_%s_%d' % (uuid.uuid4().hex[:8], next(_schema_counter))
        return DatabaseManager(url=TEST_DB_URL, schema=schema)
    return DatabaseManager(str(tmp_path / (name + '.db')))


def clone_manager(manager):
    """A second DatabaseManager pointed at the same store as `manager`.

    Used to prove that committed rows are visible on another connection. On
    PostgreSQL that means the same URL *and* the same isolated schema.
    """
    if TEST_DB_URL:
        return DatabaseManager(url=TEST_DB_URL,
                               schema=manager.dialect.schema)
    return DatabaseManager(manager.db_path)


def dispose(manager):
    manager.drop_schema()
    manager.close()


@pytest.fixture
def db(tmp_path):
    manager = make_db(tmp_path)
    yield manager
    dispose(manager)


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
    manager = make_db(tmp_path_factory.mktemp('netwatch'), 'populated')
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
    dispose(manager)


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
