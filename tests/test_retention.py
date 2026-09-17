"""Time-based retention: old telemetry goes, recent telemetry and the catalog stay."""

import time

import pytest

import config as config_module
from PacketSimulator import TrafficGenerator

from conftest import SEED


@pytest.fixture
def aged_db(db, simulator):
    """Two hours ago: background plus attacks. One minute ago: the same again."""
    now = time.time()
    gen = TrafficGenerator(seed=SEED)
    frames = []
    for start in (now - 7200, now - 60):
        frames.extend(gen.background(600, start_ts=start, rate_pps=50))
        frames.extend(gen.scenario('port_scan', start_ts=start + 1))
        frames.extend(gen.scenario('http_attack', start_ts=start + 2))
    frames.sort(key=lambda pair: pair[0])
    simulator.run_frames(frames)
    return db, now


def oldest(db, table, column):
    return db._scalar('SELECT MIN(%s) FROM %s' % (column, table), (), None)


def test_prune_removes_only_expired_rows(aged_db):
    db, now = aged_db
    cutoff = now - 3600
    before = db.health()['tables']
    assert oldest(db, 'packets', 'ts') < cutoff, 'fixture should include old rows'
    assert oldest(db, 'alerts', 'ts') < cutoff, 'fixture should include old alerts'

    deleted = db.prune(cutoff)

    assert deleted['packets'] > 0 and deleted['alerts'] > 0
    for table, column in (('packets', 'ts'), ('alerts', 'ts'),
                          ('connections', 'last_seen'), ('hosts', 'last_seen'),
                          ('alert_techniques', 'ts')):
        remaining = oldest(db, table, column)
        assert remaining is None or remaining >= cutoff, table
    assert db._scalar('SELECT MIN(bucket) FROM protocol_stats') >= \
        int(cutoff // 60) * 60

    after = db.health()['tables']
    assert 0 < after['packets'] < before['packets']
    assert 0 < after['alerts'] < before['alerts']
    assert after['mitre_techniques'] == before['mitre_techniques']


def test_prune_leaves_no_orphaned_technique_links(aged_db):
    db, now = aged_db
    db.prune(now - 3600)
    orphans = db._scalar(
        'SELECT COUNT(*) FROM alert_techniques at '
        'LEFT JOIN alerts a ON a.id = at.alert_id WHERE a.id IS NULL')
    assert orphans == 0


def test_prune_with_a_past_cutoff_deletes_nothing(aged_db):
    db, now = aged_db
    assert sum(db.prune(now - 86400).values()) == 0


def test_live_loop_prunes_when_retention_is_set(simulator, monkeypatch):
    calls = []
    monkeypatch.setitem(simulator.cfg, 'retention_s', 300)
    monkeypatch.setitem(simulator.cfg, 'prune_interval_s', 0.1)
    monkeypatch.setattr(simulator, 'FIRST_SCENARIO_DELAY_S', 3600)
    monkeypatch.setattr(simulator.db, 'prune',
                        lambda before: calls.append(before) or {'packets': 1})
    started = time.time()
    simulator.run(rate_pps=200, duration_s=0.6)
    assert calls, 'retention was configured but the loop never pruned'
    assert all(started - 301 < c < time.time() - 299 for c in calls)
    assert simulator.stats()['rows_pruned'] == len(calls)


def test_live_loop_never_prunes_by_default(simulator, monkeypatch):
    monkeypatch.setattr(simulator, 'FIRST_SCENARIO_DELAY_S', 3600)
    monkeypatch.setattr(simulator.db, 'prune',
                        lambda before: pytest.fail('pruned with retention off'))
    simulator.run(rate_pps=200, duration_s=0.3)


def test_retention_env_var_overrides_config(monkeypatch):
    monkeypatch.setenv('NETWATCH_RETENTION_S', '7200')
    assert config_module.load()['engine']['retention_s'] == 7200


@pytest.mark.parametrize('raw', ['two hours', '-5'])
def test_retention_env_var_is_validated(monkeypatch, raw):
    monkeypatch.setenv('NETWATCH_RETENTION_S', raw)
    with pytest.raises(ValueError):
        config_module.load()
