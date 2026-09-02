"""
Schema creation, reference-data seeding, and index management.

Alembic owns migrations for a deployed database (``alembic upgrade head``).
These helpers exist for the two cases where a migration is the wrong tool:
building a throwaway schema for a test, and the benchmark that drops and
recreates the composite indexes to measure what they are worth.
"""

import logging

from sqlalchemy import inspect, select, text

from netwatch import mitre
from netwatch.analysis.protocol import (
    ENCRYPTED_PROTOCOLS,
    PROTOCOL_RISK,
    SUPPORTED_PROTOCOLS,
)
from netwatch.db.models import (
    COMPOSITE_INDEXES,
    Base,
    MitreTechnique,
    Protocol,
    ThreatType,
)

log = logging.getLogger('netwatch.db.schema')

# Protocols the pipeline can record but that are not application protocols the
# analyzer decodes; UNKNOWN is the fallback for a frame that parsed at L3/L4
# but whose payload matched no L7 decoder.
EXTRA_PROTOCOLS = ('UNKNOWN',)

L4_PROTOCOLS = {'TCP', 'UDP', 'ICMP'}
L3_PROTOCOLS = {'IPv4', 'IPv6'}
L2_PROTOCOLS = {'ARP'}


def _layer(name):
    if name in L2_PROTOCOLS:
        return 'L2'
    if name in L3_PROTOCOLS:
        return 'L3'
    if name in L4_PROTOCOLS:
        return 'L4'
    return 'L7'


def create_all(engine):
    """Create every table and index. Idempotent."""
    Base.metadata.create_all(engine)
    # Same reason as drop_all: connections opened before the enum existed
    # hold no adapter for it.
    engine.dispose()


def drop_all(engine):
    """Drop everything this application owns, including the severity enum.

    Disposes the pool afterwards. psycopg caches the OID of a user-defined
    type (here `severity_level`) per connection; a pooled connection that
    outlived a DROP TYPE would keep sending the stale OID and fail with
    "cache lookup failed for type N" on the next insert. Dropping the schema
    is rare enough that throwing the pool away with it costs nothing.
    """
    Base.metadata.drop_all(engine)
    with engine.begin() as conn:
        conn.execute(text('DROP TYPE IF EXISTS severity_level'))
    engine.dispose()


def seed_reference_data(engine, threat_type_rows=None):
    """Populate the three lookup tables. Safe to call on every start."""
    from sqlalchemy.dialects.postgresql import insert

    protocols = [
        {'name': name, 'layer': _layer(name),
         'risk': PROTOCOL_RISK.get(name, 'INFO'),
         'is_encrypted': name in ENCRYPTED_PROTOCOLS}
        for name in tuple(SUPPORTED_PROTOCOLS) + EXTRA_PROTOCOLS
    ]
    techniques = [
        {'technique_id': t.id, 'name': t.name, 'tactic': t.tactic,
         'url': t.url, 'rationale': t.rationale}
        for t in mitre.all_techniques()
    ]
    if threat_type_rows is None:
        from netwatch import detectors
        threat_type_rows = [
            {'name': entry['threat_type'], 'detector': entry['name'],
             'default_severity': entry['severity'],
             'description': entry.get('description', '')}
            for entry in detectors.catalog()
        ]

    with engine.begin() as conn:
        stmt = insert(Protocol).values(protocols)
        conn.execute(stmt.on_conflict_do_update(
            index_elements=[Protocol.name],
            set_={'layer': stmt.excluded.layer, 'risk': stmt.excluded.risk,
                  'is_encrypted': stmt.excluded.is_encrypted}))

        stmt = insert(MitreTechnique).values(techniques)
        conn.execute(stmt.on_conflict_do_update(
            index_elements=[MitreTechnique.technique_id],
            set_={'name': stmt.excluded.name, 'tactic': stmt.excluded.tactic,
                  'url': stmt.excluded.url,
                  'rationale': stmt.excluded.rationale}))

        if threat_type_rows:
            stmt = insert(ThreatType).values(threat_type_rows)
            conn.execute(stmt.on_conflict_do_update(
                index_elements=[ThreatType.name],
                set_={'detector': stmt.excluded.detector,
                      'default_severity': stmt.excluded.default_severity,
                      'description': stmt.excluded.description}))


def lookup_maps(engine):
    """Return ``(protocol name -> id, threat type name -> id)``.

    Read once at writer construction and cached for the process lifetime: the
    lookup tables are seeded at start-up and only change when a detector or a
    protocol decoder is added, which is a deploy, not a runtime event.
    """
    with engine.connect() as conn:
        protocols = dict(conn.execute(select(Protocol.name, Protocol.id)).all())
        threats = dict(conn.execute(
            select(ThreatType.name, ThreatType.id)).all())
    return protocols, threats


# ── composite index management (used by the query benchmark) ─────────────────

def composite_index_names():
    return sorted(COMPOSITE_INDEXES)


def existing_index_names(engine):
    inspector = inspect(engine)
    names = set()
    for table in Base.metadata.tables:
        for idx in inspector.get_indexes(table):
            names.add(idx['name'])
    return names


def drop_composite_indexes(engine):
    """Drop exactly the indexes in COMPOSITE_INDEXES; leave PK/FK/unique."""
    dropped = []
    with engine.begin() as conn:
        for name in composite_index_names():
            conn.execute(text('DROP INDEX IF EXISTS %s' % name))
            dropped.append(name)
    return dropped


def create_composite_indexes(engine):
    """Recreate them, then ANALYZE so the planner has fresh statistics."""
    created = []
    with engine.begin() as conn:
        for name, index in sorted(COMPOSITE_INDEXES.items()):
            index.create(bind=conn, checkfirst=True)
            created.append(name)
    with engine.begin() as conn:
        conn.execute(text('ANALYZE'))
    return created


def analyze(engine):
    with engine.begin() as conn:
        conn.execute(text('ANALYZE'))
