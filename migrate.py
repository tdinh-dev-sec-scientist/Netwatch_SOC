"""
Schema migrations for NetWatch SOC.

Versioned SQL files, applied in order, recorded in a `schema_migrations`
table. No ORM is in use, so there is no Alembic; this is the lightweight
equivalent, and it is deliberately small enough to read in one sitting.

    python migrate.py status                 # what is applied and what is not
    python migrate.py up                     # apply everything pending
    python migrate.py up --database-url ...  # against a specific database
    python migrate.py up --backend sqlite    # against the dev fallback

Layout:

    migrations/postgresql/0001_initial_schema.sql
    migrations/sqlite/0001_initial_schema.sql

The leading number is the version and must be unique within a directory; the
rest of the filename is a human label. Both backends carry the same version
numbers for the same logical change, so `0002_...` must be written for both
(or, if a change genuinely cannot be expressed in SQLite, as a file that
documents why it is a no-op there).

Rules
─────
* A migration is never edited once applied anywhere. The file's checksum is
  recorded, and a later run reports any file whose content has changed rather
  than silently diverging from the database it created.
* Each migration runs inside a transaction together with its bookkeeping row,
  so a failure leaves neither a half-applied schema nor a false record of one.
  PostgreSQL makes DDL transactional; under SQLite the guarantee is weaker,
  which is one more reason it is the development backend only.
* Migrations are forward-only. There are no down-migrations: rolling back a
  schema change on a live database is a decision to make deliberately, with a
  new forward migration, not a script to run under pressure.
* `DatabaseManager` applies pending migrations at startup, which keeps local
  development and the test suite frictionless. Set NETWATCH_AUTO_MIGRATE=0 in
  a deployment where migrations should be an explicit step instead, and run
  `python migrate.py up` from your release process.
"""

import argparse
import hashlib
import os
import re
import sys
import time

import db_backends

BOOKKEEPING = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT NOT NULL PRIMARY KEY,
    name       TEXT NOT NULL,
    checksum   TEXT NOT NULL,
    applied_at DOUBLE PRECISION NOT NULL
)
"""

# SQLite has no DOUBLE PRECISION keyword pair; REAL is the same thing.
BOOKKEEPING_SQLITE = BOOKKEEPING.replace('DOUBLE PRECISION', 'REAL')

_VERSION = re.compile(r'^(\d+)[_-](.+)\.sql$')


class MigrationError(RuntimeError):
    pass


class Migration:
    __slots__ = ('version', 'name', 'path', 'sql', 'checksum')

    def __init__(self, version, name, path):
        self.version = version
        self.name = name
        self.path = path
        with open(path, 'r', encoding='utf-8') as fh:
            self.sql = fh.read()
        self.checksum = hashlib.sha256(
            self.sql.encode('utf-8')).hexdigest()[:16]

    def __repr__(self):
        return 'Migration(%s, %s)' % (self.version, self.name)


def discover(directory):
    """Every migration in `directory`, ordered by version."""
    if not os.path.isdir(directory):
        raise MigrationError('no migrations directory at %s' % directory)
    found = {}
    for filename in sorted(os.listdir(directory)):
        match = _VERSION.match(filename)
        if not match:
            if filename.endswith('.sql'):
                raise MigrationError(
                    '%s does not start with a version number (expected '
                    'NNNN_description.sql)' % filename)
            continue
        version = match.group(1)
        if version in found:
            raise MigrationError(
                'duplicate migration version %s: %s and %s'
                % (version, found[version].name, filename))
        found[version] = Migration(version, match.group(2),
                                   os.path.join(directory, filename))
    return [found[v] for v in sorted(found)]


def applied(backend, conn):
    """{version: (name, checksum)} already recorded in this database."""
    backend.run_script(
        conn, BOOKKEEPING_SQLITE if backend.name == db_backends.SQLITE
        else BOOKKEEPING)
    backend.commit(conn)
    rows = backend.execute(
        conn, 'SELECT version, name, checksum FROM schema_migrations '
              'ORDER BY version').rows
    # Committed even though nothing was written: the writer connection is not
    # in autocommit, so this read opened a transaction, and leaving it open
    # would hold a snapshot — and block the caller from changing session state.
    backend.commit(conn)
    return {r['version']: (r['name'], r['checksum']) for r in rows}


def pending(backend, conn):
    """(migrations still to apply, checksum drift already applied)."""
    have = applied(backend, conn)
    todo, drifted = [], []
    for migration in discover(backend.migrations_dir):
        record = have.get(migration.version)
        if record is None:
            todo.append(migration)
        elif record[1] != migration.checksum:
            drifted.append(migration)
    return todo, drifted


def apply_pending(backend, conn, log=None):
    """Apply every pending migration. Returns the versions applied.

    Idempotent: a database already at the latest version is untouched, which
    is what makes it safe to call on every process start. Held under the
    backend's migration lock, so two processes starting together serialise
    instead of racing to create the same table.
    """
    with backend.migration_lock(conn):
        return _apply_pending_locked(backend, conn, log)


def _apply_pending_locked(backend, conn, log):
    todo, drifted = pending(backend, conn)
    if drifted:
        raise MigrationError(
            'these migrations have changed since they were applied to %s: %s\n'
            'A migration must never be edited after it has run. Add a new '
            'numbered migration for the change instead.'
            % (backend.settings.display,
               ', '.join('%s_%s' % (m.version, m.name) for m in drifted)))
    done = []
    for migration in todo:
        backend.begin(conn)
        try:
            backend.run_script(conn, migration.sql)
            backend.execute(
                conn,
                'INSERT INTO schema_migrations (version, name, checksum, '
                'applied_at) VALUES (?,?,?,?)',
                (migration.version, migration.name, migration.checksum,
                 time.time()))
            backend.commit(conn)
        except Exception:
            backend.rollback(conn)
            raise
        done.append(migration.version)
        if log:
            log('applied %s_%s' % (migration.version, migration.name))
    return done


def _connect(args):
    settings = db_backends.resolve_settings(target=args.database_url,
                                            backend=args.backend)
    return db_backends.make_backend(settings), settings


def main(argv=None):
    parser = argparse.ArgumentParser(description='NetWatch SOC migrations')
    parser.add_argument('command', choices=('status', 'up'))
    parser.add_argument('--database-url', default=None,
                        help='PostgreSQL URL, or a path when --backend sqlite '
                             '(default: DATABASE_URL / PG_* / NETWATCH_DB)')
    parser.add_argument('--backend', default=None,
                        choices=(db_backends.POSTGRESQL, db_backends.SQLITE))
    args = parser.parse_args(argv)

    try:
        backend, settings = _connect(args)
    except db_backends.ConfigError as exc:
        print('configuration error: %s' % exc, file=sys.stderr)
        return 2

    conn = backend.writer()
    try:
        print('database : %s (%s)' % (settings.display, backend.name))
        if args.command == 'status':
            have = applied(backend, conn)
            todo, drifted = pending(backend, conn)
            for migration in discover(backend.migrations_dir):
                state = 'pending'
                if migration.version in have:
                    state = ('CHANGED SINCE APPLIED'
                             if migration in drifted else 'applied')
                print('  %-6s %-28s %s'
                      % (migration.version, migration.name, state))
            print('%d applied, %d pending' % (len(have), len(todo)))
            return 1 if drifted else 0
        done = apply_pending(backend, conn, log=lambda m: print('  ' + m))
        print('up to date' if not done else '%d migration(s) applied'
              % len(done))
        return 0
    except MigrationError as exc:
        print('migration error: %s' % exc, file=sys.stderr)
        return 1
    finally:
        backend.close()


if __name__ == '__main__':
    sys.exit(main())
