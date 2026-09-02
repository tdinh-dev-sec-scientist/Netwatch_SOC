"""Schema shape and the constraints the database is expected to enforce.

These assert on the live PostgreSQL catalog, not on the model declarations —
a constraint that exists only in Python is not a constraint.
"""

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from netwatch.db import schema as schema_mod
from netwatch.db.models import (
    COMPOSITE_INDEXES,
    SEVERITIES,
    TABLE_COUNT,
    TABLES,
)

EXPECTED_TABLES = {
    'protocols', 'threat_types', 'mitre_techniques',      # reference
    'hosts', 'packets', 'flows', 'alerts', 'alert_techniques',   # observation
    'protocol_stats', 'pipeline_runs',                    # derived / ops
}


def test_schema_declares_the_expected_tables():
    assert set(TABLES) == EXPECTED_TABLES
    assert len(EXPECTED_TABLES) == TABLE_COUNT


def test_every_declared_table_exists_in_the_database(db_engine):
    present = set(inspect(db_engine).get_table_names())
    assert present >= EXPECTED_TABLES


def test_every_table_has_a_primary_key(db_engine):
    inspector = inspect(db_engine)
    for table in TABLES:
        pk = inspector.get_pk_constraint(table)
        assert pk['constrained_columns'], '%s has no primary key' % table


def test_reference_tables_are_seeded(repo):
    counts = repo.health()['tables']
    assert counts['protocols'] >= 20
    assert counts['threat_types'] == 17
    assert counts['mitre_techniques'] >= 15


@pytest.mark.parametrize('table,column,target', [
    ('packets', 'src_host_id', 'hosts'),
    ('packets', 'dst_host_id', 'hosts'),
    ('packets', 'protocol_id', 'protocols'),
    ('flows', 'src_host_id', 'hosts'),
    ('flows', 'protocol_id', 'protocols'),
    ('alerts', 'threat_type_id', 'threat_types'),
    ('alerts', 'src_host_id', 'hosts'),
    ('alert_techniques', 'alert_id', 'alerts'),
    ('alert_techniques', 'technique_id', 'mitre_techniques'),
])
def test_foreign_keys_are_declared(db_engine, table, column, target):
    fks = inspect(db_engine).get_foreign_keys(table)
    match = [fk for fk in fks
             if column in fk['constrained_columns']
             and fk['referred_table'] == target]
    assert match, '%s.%s does not reference %s' % (table, column, target)


def test_foreign_keys_are_enforced(db_engine):
    with pytest.raises(IntegrityError):
        with db_engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO alerts (ts, severity, threat_type_id, confidence,
                                    description)
                VALUES (now(), 'HIGH', 9999, 0.5, 'orphan')"""))


def test_severity_enum_rejects_unknown_values(db_engine):
    with pytest.raises(Exception) as excinfo:
        with db_engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO alerts (ts, severity, threat_type_id, confidence,
                                    description)
                VALUES (now(), 'CATASTROPHIC',
                        (SELECT id FROM threat_types LIMIT 1), 0.5, 'x')"""))
    assert 'severity_level' in str(excinfo.value)


def test_severity_enum_holds_exactly_the_documented_values(db_engine):
    with db_engine.connect() as conn:
        labels = conn.execute(text(
            "SELECT unnest(enum_range(NULL::severity_level))::text")).scalars(
            ).all()
    assert set(labels) == set(SEVERITIES)


def test_confidence_check_constraint(db_engine):
    with pytest.raises(IntegrityError):
        with db_engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO alerts (ts, severity, threat_type_id, confidence,
                                    description)
                VALUES (now(), 'HIGH',
                        (SELECT id FROM threat_types LIMIT 1), 4.2, 'x')"""))


def test_flow_tuple_is_unique(db_engine):
    uniques = inspect(db_engine).get_unique_constraints('flows')
    names = {u['name'] for u in uniques}
    assert 'uq_flow_tuple' in names
    columns = next(u['column_names'] for u in uniques
                   if u['name'] == 'uq_flow_tuple')
    assert set(columns) == {'src_host_id', 'dst_host_id', 'src_port',
                            'dst_port', 'protocol_id'}


def test_host_ip_is_unique(db_engine):
    with db_engine.begin() as conn:
        conn.execute(text("INSERT INTO hosts (ip, first_seen, last_seen) "
                          "VALUES ('10.9.9.9', now(), now())"))
    with pytest.raises(IntegrityError):
        with db_engine.begin() as conn:
            conn.execute(text("INSERT INTO hosts (ip, first_seen, last_seen) "
                              "VALUES ('10.9.9.9', now(), now())"))


def test_alert_techniques_cascade_on_alert_delete(db_engine, writer, lookups):
    with db_engine.begin() as conn:
        conn.execute(text("INSERT INTO hosts (ip, first_seen, last_seen) "
                          "VALUES ('10.4.4.4', now(), now())"))
        alert_id = conn.execute(text("""
            INSERT INTO alerts (ts, severity, threat_type_id, confidence,
                                description)
            VALUES (now(), 'HIGH', (SELECT id FROM threat_types LIMIT 1),
                    0.9, 'cascade probe') RETURNING id""")).scalar()
        conn.execute(text("""
            INSERT INTO alert_techniques (alert_id, technique_id, confidence,
                                          ts)
            VALUES (:a, (SELECT technique_id FROM mitre_techniques LIMIT 1),
                    0.9, now())"""), {'a': alert_id})
    with db_engine.begin() as conn:
        conn.execute(text('DELETE FROM alerts WHERE id = :a'),
                     {'a': alert_id})
        remaining = conn.execute(text(
            'SELECT COUNT(*) FROM alert_techniques WHERE alert_id = :a'),
            {'a': alert_id}).scalar()
    assert remaining == 0


def test_composite_indexes_exist_by_name(db_engine):
    present = schema_mod.existing_index_names(db_engine)
    missing = set(COMPOSITE_INDEXES) - present
    assert not missing, 'missing composite indexes: %s' % sorted(missing)


def test_composite_indexes_can_be_dropped_and_recreated(db_engine):
    """The query benchmark depends on this round trip working exactly."""
    dropped = schema_mod.drop_composite_indexes(db_engine)
    assert set(dropped) == set(COMPOSITE_INDEXES)
    assert not (set(COMPOSITE_INDEXES)
                & schema_mod.existing_index_names(db_engine))
    created = schema_mod.create_composite_indexes(db_engine)
    assert set(created) == set(COMPOSITE_INDEXES)
    assert set(COMPOSITE_INDEXES) <= schema_mod.existing_index_names(db_engine)


def test_lookup_maps_cover_every_protocol_and_threat_type(db_engine):
    from netwatch import detectors
    from netwatch.analysis.protocol import SUPPORTED_PROTOCOLS
    protocol_ids, threat_ids = schema_mod.lookup_maps(db_engine)
    assert set(SUPPORTED_PROTOCOLS) <= set(protocol_ids)
    assert 'UNKNOWN' in protocol_ids
    assert set(detectors.THREAT_TYPES) == set(threat_ids)


def test_health_reports_postgres_and_a_complete_schema(repo):
    health = repo.health()
    assert health['status'] == 'ok'
    assert health['database'] == 'postgresql'
    assert health['table_count'] == TABLE_COUNT
    assert health['index_count'] > 20
    assert health['server_version']
