"""
Copy an existing SQLite netwatch.db into PostgreSQL.

All of this project's data is synthetic — PacketSimulator generates it and the
public demo starts from an empty database on every cold start — so nothing in
the repository needs migrating and most people will never run this. It exists
for the one case that does matter: a local or self-hosted instance that has
been running long enough for its netwatch.db to be worth keeping.

    python migrate_sqlite_to_postgres.py --sqlite ./netwatch.db
    python migrate_sqlite_to_postgres.py --sqlite ./netwatch.db \
        --database-url postgresql://netwatch:secret@localhost:5432/netwatch
    python migrate_sqlite_to_postgres.py --sqlite ./netwatch.db --dry-run

What it does, table by table in dependency order:

  * reads rows from SQLite in batches, so a database larger than memory is fine
  * converts the types PostgreSQL is strict about: 0/1 to BOOLEAN, JSON text to
    jsonb, and NULL where SQLite stored an empty string in a NOT NULL column
  * inserts with ON CONFLICT DO NOTHING against each table's natural or primary
    key, which is what makes a re-run safe: rows already copied are skipped
  * verifies the destination count against the source count after each table
  * resets the identity sequences afterwards, so new rows do not collide with
    copied ids

Idempotence and resumption. Re-running copies only what is missing, so an
interrupted run can simply be repeated. Each table is one transaction: a table
either lands completely or not at all.

Two caveats worth knowing before you run it:

  * `packets` and `alerts` are copied with their original ids, because
    alert_techniques references alerts(id). If the destination already contains
    *different* rows at those ids — for instance because the engine has been
    running against PostgreSQL already — the conflicting rows are skipped and
    the count check will report the shortfall rather than silently merging two
    histories. Migrate into an empty database.
  * The source is only read. Nothing is deleted or altered in the SQLite file,
    so it remains a fallback until you are satisfied.
"""

import argparse
import json
import os
import sqlite3
import sys
import time

import db_backends
import migrate
from db_backends import Json

# Dependency order: alerts before alert_techniques, mitre_techniques before it
# too. `packets` is first because it is by far the largest and a failure there
# is the one worth hitting early.
PLAN = [
    # table, columns, conflict target, boolean columns, json columns
    ('packets',
     ('id', 'ts', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
      'frame_len', 'payload_len', 'flags', 'entropy', 'is_malicious',
      'l7_summary'),
     '(id)', ('is_malicious',), ('l7_summary',)),
    ('connections',
     ('id', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
      'first_seen', 'last_seen', 'packets', 'bytes', 'flags_seen', 'state'),
     '(id)', (), ()),
    ('hosts',
     ('ip', 'first_seen', 'last_seen', 'is_internal', 'country', 'latitude',
      'longitude', 'packets_sent', 'packets_recv', 'bytes_sent', 'bytes_recv',
      'alert_count', 'threat_score'),
     '(ip)', ('is_internal',), ()),
    ('mitre_techniques',
     ('technique_id', 'name', 'tactic', 'url', 'rationale'),
     '(technique_id)', (), ()),
    ('alerts',
     ('id', 'ts', 'severity', 'threat_type', 'detector', 'src_ip', 'dst_ip',
      'src_port', 'dst_port', 'protocol', 'confidence', 'description',
      'evidence', 'acknowledged', 'ack_ts'),
     '(id)', ('acknowledged',), ('evidence',)),
    ('alert_techniques',
     ('alert_id', 'technique_id', 'confidence', 'ts'),
     '(alert_id, technique_id)', (), ()),
    ('protocol_stats',
     ('bucket', 'protocol', 'packets', 'bytes', 'alerts'),
     '(bucket, protocol)', (), ()),
    ('performance_metrics',
     ('id', 'ts', 'source', 'window_s', 'packets_processed',
      'packets_per_min', 'alerts_generated', 'parse_errors', 'parse_us_avg',
      'detect_us_avg', 'db_write_ms', 'query_p50_ms', 'query_p95_ms'),
     '(id)', (), ()),
]

# Tables whose id column is GENERATED ALWAYS AS IDENTITY. Copying rows with
# their original ids needs OVERRIDING SYSTEM VALUE, and afterwards the sequence
# has to be advanced past those ids or the next insert collides with them.
IDENTITY_TABLES = ('packets', 'connections', 'alerts', 'performance_metrics')

# Columns declared NOT NULL in PostgreSQL that SQLite may hold NULL in, because
# its dynamic typing let an earlier schema version omit them.
NOT_NULL_DEFAULTS = {
    ('packets', 'payload_len'): 0,
    ('packets', 'entropy'): 0.0,
    ('packets', 'is_malicious'): False,
    ('connections', 'packets'): 0,
    ('connections', 'bytes'): 0,
    ('connections', 'flags_seen'): '',
    ('connections', 'state'): 'ACTIVE',
    ('hosts', 'is_internal'): False,
    ('hosts', 'country'): 'UNKNOWN',
    ('hosts', 'packets_sent'): 0,
    ('hosts', 'packets_recv'): 0,
    ('hosts', 'bytes_sent'): 0,
    ('hosts', 'bytes_recv'): 0,
    ('hosts', 'alert_count'): 0,
    ('hosts', 'threat_score'): 0.0,
    ('alerts', 'acknowledged'): False,
    ('protocol_stats', 'packets'): 0,
    ('protocol_stats', 'bytes'): 0,
    ('protocol_stats', 'alerts'): 0,
}


class MigrationFailed(RuntimeError):
    pass


def _convert(table, columns, booleans, jsons, row):
    """One SQLite row as PostgreSQL parameters."""
    out = []
    for name, value in zip(columns, row):
        if value is None:
            value = NOT_NULL_DEFAULTS.get((table, name))
        elif name in booleans:
            # SQLite stored these as 0/1; an older file may hold '0'/'1'.
            value = bool(int(value))
        elif name in jsons:
            # TEXT holding json.dumps() output becomes jsonb. Anything
            # unparseable is kept verbatim as a JSON string rather than
            # dropped, so no evidence is lost to a malformed row.
            if isinstance(value, (bytes, bytearray)):
                value = value.decode('utf-8', 'replace')
            try:
                value = Json(json.loads(value)) if value != '' else Json(None)
            except (ValueError, TypeError):
                value = Json({'_unparsed': str(value)})
        out.append(value)
    return tuple(out)


def _copy_table(source, backend, conn, spec, batch_size, dry_run, log,
                destination_tables):
    table, columns, conflict, booleans, jsons = spec
    column_list = ', '.join(columns)
    source_count = source.execute(
        'SELECT COUNT(*) FROM "%s"' % table).fetchone()[0]

    if table not in destination_tables:
        # Only reachable under --dry-run; a real run applies the migrations
        # first, so the tables always exist by this point.
        log('  %-20s %8d in sqlite, destination table not created yet'
            % (table, source_count))
        return source_count, 0, 0

    before = backend.execute(conn, 'SELECT COUNT(*) FROM "%s"' % table).scalar(0)

    if dry_run:
        log('  %-20s %8d in sqlite, %8d already in postgres'
            % (table, source_count, before))
        return source_count, before, before

    # The id columns are GENERATED ALWAYS, which is right for the application
    # — it cannot accidentally supply one — but this is the one caller with a
    # legitimate reason to, because alert_techniques references alerts(id) and
    # those references have to survive the copy.
    override = ('OVERRIDING SYSTEM VALUE '
                if table in IDENTITY_TABLES else '')
    sql = 'INSERT INTO "%s" (%s) %sVALUES (%s) ON CONFLICT %s DO NOTHING' % (
        table, column_list, override, ','.join('?' * len(columns)), conflict)

    cursor = source.execute('SELECT %s FROM "%s"' % (column_list, table))
    copied = 0
    backend.begin(conn)
    try:
        while True:
            rows = cursor.fetchmany(batch_size)
            if not rows:
                break
            backend.executemany(
                conn, sql,
                [_convert(table, columns, booleans, jsons, r) for r in rows])
            copied += len(rows)
        backend.commit(conn)
    except Exception:
        backend.rollback(conn)
        raise
    after = backend.execute(conn, 'SELECT COUNT(*) FROM "%s"' % table).scalar(0)
    log('  %-20s %8d read, %8d rows now present (was %d)'
        % (table, copied, after, before))
    return source_count, before, after


def _reset_sequences(backend, conn, log):
    """Advance each identity sequence past the highest copied id."""
    for table in IDENTITY_TABLES:
        highest = backend.execute(
            conn, 'SELECT MAX(id) FROM "%s"' % table).scalar(0) or 0
        backend.execute(
            conn,
            "SELECT setval(pg_get_serial_sequence(?, 'id'), ?, true)",
            (table, max(highest, 1)))
        backend.commit(conn)
    log('  identity sequences advanced past the copied ids')


def run(sqlite_path, target=None, batch_size=5000, dry_run=False,
        log=print):
    if not os.path.exists(sqlite_path):
        raise MigrationFailed('no such SQLite database: %s' % sqlite_path)

    settings = db_backends.resolve_settings(target=target,
                                            backend=db_backends.POSTGRESQL)
    backend = db_backends.make_backend(settings)
    source = sqlite3.connect('file:%s?mode=ro' % sqlite_path, uri=True)
    started = time.time()
    try:
        conn = backend.writer()
        log('source      : %s' % sqlite_path)
        log('destination : %s' % settings.display)
        if dry_run:
            log('dry run — nothing will be written\n')
            if not set(backend.table_names(conn)):
                log('the destination has no schema yet; a real run applies '
                    'the migrations first\n')
        else:
            applied = migrate.apply_pending(backend, conn)
            log('schema      : %s\n'
                % ('%d migration(s) applied' % len(applied) if applied
                   else 'already up to date'))

        destination_tables = set(backend.table_names(conn))
        shortfalls = []
        for spec in PLAN:
            table = spec[0]
            try:
                source_count, before, after = _copy_table(
                    source, backend, conn, spec, batch_size, dry_run, log,
                    destination_tables)
            except sqlite3.OperationalError as exc:
                # An older SQLite file may predate a table or a column.
                log('  %-20s SKIPPED: %s' % (table, exc))
                shortfalls.append((table, str(exc)))
                continue
            if not dry_run and after < source_count:
                shortfalls.append((
                    table,
                    '%d rows in sqlite but %d in postgres — %d were skipped '
                    'as conflicting' % (source_count, after,
                                        source_count - after)))

        if not dry_run:
            _reset_sequences(backend, conn, log)
            backend.analyze(conn)

        log('\nfinished in %.1fs' % (time.time() - started))
        if shortfalls:
            log('\nrow counts did not match for %d table(s):'
                % len(shortfalls))
            for table, why in shortfalls:
                log('  %-20s %s' % (table, why))
            log('\nRe-running is safe and copies only what is missing. If the '
                'counts still\ndisagree, the destination already held '
                'different rows at those ids;\nmigrate into an empty database '
                'instead.')
            return 1
        log('every table matched its source row count')
        return 0
    finally:
        source.close()
        backend.close()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Copy a SQLite netwatch.db into PostgreSQL')
    parser.add_argument('--sqlite', default='netwatch.db',
                        help='source SQLite file (default: ./netwatch.db)')
    parser.add_argument('--database-url', default=None,
                        help='destination PostgreSQL URL '
                             '(default: DATABASE_URL / PG_*)')
    parser.add_argument('--batch-size', type=int, default=5000,
                        help='rows per INSERT batch (default: 5000)')
    parser.add_argument('--dry-run', action='store_true',
                        help='report what would be copied and exit')
    args = parser.parse_args(argv)
    try:
        return run(args.sqlite, target=args.database_url,
                   batch_size=args.batch_size, dry_run=args.dry_run)
    except (MigrationFailed, db_backends.ConfigError,
            migrate.MigrationError) as exc:
        print('migration failed: %s' % exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
