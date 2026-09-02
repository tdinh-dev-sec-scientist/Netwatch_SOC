"""
Shared fixtures.

Database isolation uses two PostgreSQL schemas inside one database rather
than two databases:

    nw_shared    built once per session by running real traffic through the
                 real pipeline. Read-only for tests; anything that mutates it
                 picks its own target row.
    nw_scratch   truncated before every test that asks for it.

Two namespaces are needed because a per-test truncate and a session-scoped
fixture cannot share a schema — the first test to truncate would empty the
populated one. Schemas are cheaper than databases and closer to how a
deployment separates tenants.

Set NETWATCH_TEST_DATABASE_URL to point at another server; the default is a
local `netwatch_test` database.
"""

import os
import sys
import time

import pytest
from sqlalchemy import text

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netwatch import config as config_module  # noqa: E402
from netwatch.analysis.protocol import ProtocolAnalyzer  # noqa: E402
from netwatch.analysis.rules import RulesEngine, ThreatDetector  # noqa: E402
from netwatch.capture.generator import TrafficGenerator  # noqa: E402
from netwatch.capture.source import ListSource  # noqa: E402
from netwatch.db import schema as schema_mod  # noqa: E402
from netwatch.db import session as session_mod  # noqa: E402
from netwatch.db.repository import Repository  # noqa: E402
from netwatch.db.writer import BatchWriter  # noqa: E402
from netwatch.pipeline import Pipeline, PipelineConfig  # noqa: E402

SEED = 20240301
# Fixture traffic must land in the recent past: the API's queries are all
# time-windowed, so a fixed historical timestamp would be filtered out of
# every result and mask real failures.
BASE_TS = time.time() - 1800.0

SHARED_SCHEMA = 'nw_shared'
SCRATCH_SCHEMA = 'nw_scratch'

DEFAULT_TEST_URL = ('postgresql+psycopg://netwatch:netwatch'
                    '@localhost:5432/netwatch_test')

#: Tables the scratch fixture clears between tests. The three reference
#: tables are seeded once and left alone — re-seeding them per test would be
#: several hundred pointless round trips.
OBSERVATION_TABLES = ('alert_techniques', 'alerts', 'packets', 'flows',
                      'protocol_stats', 'pipeline_runs', 'hosts')


def test_database_url():
    return (os.environ.get('NETWATCH_TEST_DATABASE_URL')
            or os.environ.get('NETWATCH_DATABASE_URL')
            or DEFAULT_TEST_URL)


def _build_schema(name):
    url = test_database_url()
    bootstrap = session_mod.get_engine(url)
    with bootstrap.begin() as conn:
        conn.execute(text('CREATE SCHEMA IF NOT EXISTS %s' % name))
    engine = session_mod.get_engine(url, schema=name)
    schema_mod.drop_all(engine)
    schema_mod.create_all(engine)
    schema_mod.seed_reference_data(engine)
    return engine


@pytest.fixture(scope='session')
def scratch_engine():
    """An engine over an empty schema, truncated per test by `repo`."""
    engine = _build_schema(SCRATCH_SCHEMA)
    yield engine
    engine.dispose()


@pytest.fixture
def db_engine(scratch_engine):
    """Truncate the observation tables so each test starts from empty."""
    with scratch_engine.begin() as conn:
        conn.execute(text('TRUNCATE %s RESTART IDENTITY CASCADE'
                          % ', '.join(OBSERVATION_TABLES)))
    return scratch_engine


@pytest.fixture
def scratch_url(db_engine):
    """The scratch schema as a connection URL.

    The benchmark entry points take a URL, not an engine, so the schema has to
    travel inside it: libpq's `options` parameter sets search_path on connect.
    """
    url = db_engine.url.render_as_string(hide_password=False)
    separator = '&' if '?' in url else '?'
    return '%s%soptions=-csearch_path%%3D%s' % (url, separator, SCRATCH_SCHEMA)


@pytest.fixture
def repo(db_engine):
    return Repository(db_engine)


@pytest.fixture
def lookups(db_engine):
    return schema_mod.lookup_maps(db_engine)


@pytest.fixture
def writer(db_engine, lookups):
    protocol_ids, threat_ids = lookups
    instance = BatchWriter(db_engine, protocol_ids, threat_ids)
    yield instance
    instance.close()


@pytest.fixture
def cfg():
    return config_module.load()


@pytest.fixture
def analyzer():
    return ProtocolAnalyzer()


@pytest.fixture
def engine(cfg):
    """The rules engine. Named `engine` for historical reasons in the
    detector tests; `rules_engine` is the same object."""
    return ThreatDetector(cfg=cfg)


@pytest.fixture
def rules_engine(cfg):
    return RulesEngine(cfg=cfg)


@pytest.fixture
def gen():
    return TrafficGenerator(seed=SEED)


def build_workload(generator, background=3000, start_ts=BASE_TS):
    """Benign background plus every attack scenario, interleaved by time."""
    frames = generator.background(background, start_ts=start_ts)
    span = frames[-1][0] - frames[0][0]
    step = span / (len(TrafficGenerator.SCENARIOS) + 1)
    for i, name in enumerate(TrafficGenerator.SCENARIOS):
        frames.extend(generator.scenario(name, start_ts=start_ts
                                         + step * (i + 1)))
    frames.sort(key=lambda pair: pair[0])
    return frames


def run_pipeline(engine_, frames, cfg=None, **config_kwargs):
    """Push frames through the real five-stage pipeline. Returns the report.

    Used by the fixtures and by the pipeline tests, so what the API tests
    query is exactly what the pipeline writes — no test-only write path.
    """
    protocol_ids, threat_ids = schema_mod.lookup_maps(engine_)
    rules = RulesEngine(cfg=cfg or config_module.load())
    pipeline = Pipeline(
        ListSource(frames), rules,
        lambda: BatchWriter(engine_, protocol_ids, threat_ids),
        config=PipelineConfig(sample_resources=False, **config_kwargs))
    report = pipeline.run_to_completion(timeout=300)
    report['rules_engine'] = rules
    return report


@pytest.fixture(scope='session')
def populated_engine():
    """A database filled by the real pipeline — background plus every attack.

    Session-scoped: running every scenario writes thousands of packets, which
    is slow to repeat per test.
    """
    engine_ = _build_schema(SHARED_SCHEMA)
    report = run_pipeline(engine_, build_workload(TrafficGenerator(seed=SEED)))
    engine_.netwatch_report = report
    yield engine_
    engine_.dispose()


@pytest.fixture
def populated_repo(populated_engine):
    return Repository(populated_engine)


@pytest.fixture
def client(populated_engine):
    from netwatch.api import create_app
    app = create_app(engine=populated_engine,
                     rules_engine=populated_engine.netwatch_report[
                         'rules_engine'],
                     run_pipeline=False, create_schema=False)
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
