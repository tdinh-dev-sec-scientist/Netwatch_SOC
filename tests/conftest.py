"""Shared fixtures. All tests use deterministic seeds and throwaway databases.

The suite runs against a real PostgreSQL server by default, because that is
what production runs and because most of what differs between the two backends
— strict typing, JSONB, boolean columns, the query planner's choices — is
invisible to a test that only ever sees SQLite. Point it at a server with:

    TEST_DATABASE_URL=postgresql://netwatch:netwatch@localhost:5432/netwatch

or start one with `docker compose up -d postgres`, whose defaults this file
already matches. DATABASE_URL is used if TEST_DATABASE_URL is unset.

Databases are created and dropped by these fixtures; nothing runs against the
database named in the URL itself, so pointing this at a development database
cannot destroy its contents.

    DB_BACKEND=sqlite pytest          # the dev fallback, temporary files

Isolation. Two scratch databases per session:

  * `db` — empty at the start of every test. Truncated rather than recreated,
    because CREATE DATABASE costs far more than TRUNCATE and the suite asks
    for an empty database a few hundred times.
  * `populated_db` — filled once by the real pipeline and then read by many
    tests. It has its own database so per-test truncation cannot touch it.
"""

import os
import sys
import time
import uuid

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config as config_module            # noqa: E402
import db_backends                         # noqa: E402
from DB_Manager import TABLES, DatabaseManager  # noqa: E402
from PacketSimulator import PacketSimulator, TrafficGenerator  # noqa: E402
from ProtocolAnalyzer import ProtocolAnalyzer  # noqa: E402
from ThreatDetector import ThreatDetector  # noqa: E402

SEED = 20240301
# Fixture traffic must land in the recent past: the API's queries are all
# time-windowed, so a fixed historical timestamp would be filtered out of
# every result and mask real failures.
BASE_TS = time.time() - 1800.0

DEFAULT_TEST_URL = 'postgresql://netwatch:netwatch@localhost:5432/netwatch'

# Unique per pytest session so parallel runs, and a run that starts while an
# earlier one is still shutting down, cannot collide on a database name.
_RUN_ID = uuid.uuid4().hex[:8]


def backend_name():
    """The backend this session is exercising."""
    return db_backends.resolve_settings(
        target=_configured_url() if not _sqlite_requested() else None).backend


def _sqlite_requested():
    return (os.environ.get('DB_BACKEND') or '').lower() == 'sqlite'


def _configured_url():
    return (os.environ.get('TEST_DATABASE_URL')
            or os.environ.get('DATABASE_URL')
            or DEFAULT_TEST_URL)


requires_postgres = pytest.mark.skipif(
    _sqlite_requested(),
    reason='PostgreSQL-specific behaviour; running with DB_BACKEND=sqlite')

requires_sqlite = pytest.mark.skipif(
    not _sqlite_requested(),
    reason='SQLite-specific behaviour; running against PostgreSQL')


# ── scratch databases ────────────────────────────────────────────────────────

class _Scratch:
    """Creates, hands out and destroys databases for the session."""

    def __init__(self, tmp_path_factory):
        self._tmp = tmp_path_factory
        self._created = []
        self._sqlite = _sqlite_requested()
        if not self._sqlite:
            self._base = db_backends.resolve_settings(
                target=_configured_url()).dsn

    def target(self, label):
        """A fresh, migrated-on-first-use database target for `label`."""
        if self._sqlite:
            return str(self._tmp.mktemp('netwatch') / ('%s.db' % label))
        name = 'netwatch_test_%s_%s' % (label, _RUN_ID)
        dsn = db_backends.with_database(self._base, name)
        db_backends.drop_database(dsn)
        db_backends.create_database(dsn, exists_ok=False)
        self._created.append(dsn)
        return dsn

    def manager(self, label):
        return DatabaseManager(self.target(label))

    def destroy(self):
        for dsn in self._created:
            try:
                db_backends.drop_database(dsn)
            except Exception:                     # never mask a test failure
                pass
        self._created = []


@pytest.fixture(scope='session')
def scratch(tmp_path_factory):
    try:
        pool = _Scratch(tmp_path_factory)
    except db_backends.ConfigError as exc:
        pytest.skip('no test database available: %s' % exc)
    yield pool
    pool.destroy()


@pytest.fixture(scope='session')
def _unit_db(scratch):
    """One database reused by every test that wants an empty one."""
    manager = scratch.manager('unit')
    yield manager
    manager.close()


@pytest.fixture
def db(_unit_db):
    """An empty database. Emptied before the test rather than after, so a
    failing test leaves its rows behind to be inspected."""
    _unit_db._backend.truncate(_unit_db._backend.writer(), TABLES)
    _unit_db.seed_technique_catalog()
    return _unit_db


@pytest.fixture
def second_manager(scratch):
    """A second DatabaseManager on the same database as `db`.

    Used to prove that a connection other than the writer's observes committed
    rows. Closed by the fixture so the PostgreSQL pool is not left open.
    """
    made = []

    def factory(existing):
        manager = DatabaseManager(existing.dsn, auto_migrate=False)
        made.append(manager)
        return manager

    yield factory
    for manager in made:
        manager.close()


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
def simulator(db, engine, analyzer):
    return PacketSimulator(db, engine, analyzer, seed=SEED)


@pytest.fixture(scope='session')
def populated_db(scratch):
    """A database filled by the real pipeline — background plus every attack.

    Session-scoped: running every scenario writes ~9k packets, which is slow
    to repeat per test. Nothing here depends on mutation isolation; the one
    test that acknowledges an alert picks its own target.
    """
    manager = scratch.manager('populated')
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
    # Without statistics the planner has no idea how big these tables are, and
    # the query-plan tests would be judging guesses rather than decisions.
    manager.analyze()

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
