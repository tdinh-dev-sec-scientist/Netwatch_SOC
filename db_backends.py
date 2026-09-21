"""
Database backends for NetWatch SOC: PostgreSQL (production) and SQLite (dev).

`DB_Manager.py` owns every SQL statement and knows nothing about drivers. This
module owns everything the two databases disagree about: how to connect, how to
pool, how placeholders are spelled, how JSON is passed, how to read the catalog
and how to explain a query plan. Adding a third backend means adding a class
here, not touching the queries.

Configuration is entirely environmental:

    DB_BACKEND      postgresql (default) | sqlite
    DATABASE_URL    preferred single-string form, e.g.
                    postgresql://user:pass@host:5432/netwatch?sslmode=require
    PG_HOST PG_PORT PG_USER PG_PASSWORD PG_DB PG_SSLMODE
                    discrete fallback, used when DATABASE_URL is unset
    PG_POOL_MIN PG_POOL_MAX     reader pool bounds (default 1 and 10)
    PG_CONNECT_TIMEOUT          seconds, default 10
    PG_STATEMENT_TIMEOUT_MS     per-statement ceiling, default 30000
    NETWATCH_DB     SQLite file path, used only when DB_BACKEND=sqlite

The shared SQL dialect
──────────────────────
Statements in DB_Manager are written once, in a subset both databases accept,
and translated here. The rules, each of which exists because one backend would
otherwise be silently wrong:

    ?                 positional placeholder; rewritten to %s for psycopg
    GREATEST/LEAST    scalar min/max. SQLite spells these MAX/MIN, which are
                      also its aggregate names; PostgreSQL's MAX/MIN are
                      aggregates only. Registered as SQLite functions below.
    COUNT(*) FILTER   conditional counting. SQLite would accept SUM(bool),
                      PostgreSQL rejects summing a boolean.
    FLOOR()           SQLite's CAST(x AS INTEGER) truncates, PostgreSQL's
                      rounds, which would shift timeline buckets.
    ON CONFLICT       upserts and DO NOTHING, rather than INSERT OR IGNORE
    RETURNING         to obtain generated ids rather than cursor.lastrowid
    TRUE/FALSE        boolean literals, not 0/1
"""

import contextlib
import json
import os
import re
import sqlite3
import threading
import urllib.parse

DEFAULT_SQLITE_PATH = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), 'netwatch.db')

POSTGRESQL = 'postgresql'
SQLITE = 'sqlite'

MIGRATIONS_ROOT = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), 'migrations')


class ConfigError(RuntimeError):
    """Raised for an unusable database configuration, with what to fix."""


# ── row and result plumbing ──────────────────────────────────────────────────

class Result:
    """Materialised query result: dict rows plus an affected-row count.

    Both drivers are wrapped in this rather than exposed, so callers never
    depend on sqlite3.Row's positional indexing or psycopg's cursor lifetime.
    Every query in this application is aggregate or LIMITed, so materialising
    costs nothing and removes a whole class of "cursor already closed" bug.
    """

    __slots__ = ('rows', 'rowcount')

    def __init__(self, rows, rowcount):
        self.rows = rows
        self.rowcount = rowcount

    def one(self):
        return self.rows[0] if self.rows else None

    def scalar(self, default=None):
        row = self.one()
        if row is None:
            return default
        value = next(iter(row.values()))
        return default if value is None else value


class Json:
    """A value to be stored in a JSON column.

    PostgreSQL gets it as jsonb; SQLite gets json.dumps() text. Marking the
    intent at the call site means the write path does not have to know which
    backend it is talking to.
    """

    __slots__ = ('value',)

    def __init__(self, value):
        self.value = value


def json_load(value):
    """Read a JSON column, whichever backend produced it.

    psycopg returns jsonb already parsed; SQLite returns the stored text.
    """
    if value is None or value == '':
        return None
    if isinstance(value, (dict, list)):
        return value
    return json.loads(value)


# ── configuration ────────────────────────────────────────────────────────────

class Settings:
    """Resolved connection settings for one backend."""

    def __init__(self, backend, dsn, display, pool_min=1, pool_max=10,
                 connect_timeout=10, statement_timeout_ms=30000):
        self.backend = backend
        self.dsn = dsn
        self.display = display          # safe to log: never holds a password
        self.pool_min = pool_min
        self.pool_max = pool_max
        self.connect_timeout = connect_timeout
        self.statement_timeout_ms = statement_timeout_ms

    def __repr__(self):
        return 'Settings(backend=%r, display=%r)' % (self.backend,
                                                     self.display)


def redact(dsn):
    """A DSN with its password replaced, for logs, health output and errors."""
    try:
        parts = urllib.parse.urlsplit(dsn)
    except ValueError:
        return '<unparseable dsn>'
    if not parts.password:
        return dsn
    host = parts.hostname or ''
    if parts.port:
        host = '%s:%d' % (host, parts.port)
    netloc = '%s:***@%s' % (parts.username or '', host)
    return urllib.parse.urlunsplit(
        (parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def _int_env(name, default):
    raw = os.environ.get(name)
    if raw is None or raw == '':
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError('%s must be an integer, got %r' % (name, raw))
    if value < 0:
        raise ConfigError('%s must not be negative, got %r' % (name, raw))
    return value


def _postgres_dsn_from_parts():
    """Build a DSN from the discrete PG_* variables.

    Only used when DATABASE_URL is unset. PG_DB is the one value with no
    sensible default: guessing a database name would connect somewhere the
    operator did not intend.
    """
    database = os.environ.get('PG_DB')
    if not database:
        raise ConfigError(
            'No PostgreSQL configuration found. Set DATABASE_URL, e.g.\n'
            '    DATABASE_URL=postgresql://netwatch:secret@localhost:5432/netwatch\n'
            'or the discrete variables PG_DB (required) plus PG_HOST, PG_PORT,\n'
            'PG_USER, PG_PASSWORD, PG_SSLMODE.\n'
            'For a throwaway local database with no server, set DB_BACKEND=sqlite '
            '(development only).')
    user = os.environ.get('PG_USER', 'netwatch')
    password = os.environ.get('PG_PASSWORD', '')
    host = os.environ.get('PG_HOST', 'localhost')
    port = os.environ.get('PG_PORT', '5432')
    quote = urllib.parse.quote
    auth = quote(user, safe='')
    if password:
        auth += ':' + quote(password, safe='')
    dsn = 'postgresql://%s@%s:%s/%s' % (auth, host, port,
                                        quote(database, safe=''))
    sslmode = os.environ.get('PG_SSLMODE')
    if sslmode:
        dsn += '?sslmode=' + quote(sslmode, safe='')
    return dsn


def resolve_settings(target=None, backend=None):
    """Work out which backend to use and how to reach it.

    `target` overrides the environment: a PostgreSQL URL, or a filesystem path
    for SQLite. It is what --db on the benchmark and the test fixtures pass.
    """
    backend = (backend or os.environ.get('DB_BACKEND') or '').strip().lower()
    if target and re.match(r'^(postgres(ql)?|psql)://', target):
        backend = POSTGRESQL
    elif target and not backend:
        # A bare path can only mean SQLite.
        backend = SQLITE
    if backend in ('postgres', 'psql', 'pg'):
        backend = POSTGRESQL
    if not backend:
        backend = POSTGRESQL

    if backend == SQLITE:
        path = target or os.environ.get('NETWATCH_DB') or DEFAULT_SQLITE_PATH
        return Settings(SQLITE, path, path)

    if backend != POSTGRESQL:
        raise ConfigError(
            "DB_BACKEND must be 'postgresql' or 'sqlite', got %r" % backend)

    dsn = target or os.environ.get('DATABASE_URL') or _postgres_dsn_from_parts()
    if dsn.startswith('postgres://'):
        # The historic scheme; libpq accepts it but normalise for consistency.
        dsn = 'postgresql://' + dsn[len('postgres://'):]
    pool_max = _int_env('PG_POOL_MAX', 10)
    pool_min = _int_env('PG_POOL_MIN', 1)
    if pool_max < 1:
        raise ConfigError('PG_POOL_MAX must be at least 1')
    if pool_min > pool_max:
        raise ConfigError('PG_POOL_MIN (%d) exceeds PG_POOL_MAX (%d)'
                          % (pool_min, pool_max))
    return Settings(POSTGRESQL, dsn, redact(dsn), pool_min, pool_max,
                    _int_env('PG_CONNECT_TIMEOUT', 10),
                    _int_env('PG_STATEMENT_TIMEOUT_MS', 30000))


# ── backends ─────────────────────────────────────────────────────────────────

class Backend:
    """What DB_Manager needs from a database, minus the SQL."""

    name = None

    def __init__(self, settings):
        self.settings = settings
        self._translations = {}

    # -- dialect ------------------------------------------------------------
    def translate(self, sql):
        """Rewrite shared-dialect SQL for this driver. Cached per statement."""
        cached = self._translations.get(sql)
        if cached is None:
            cached = self._translations[sql] = self._translate(sql)
        return cached

    def _translate(self, sql):
        return sql

    def adapt(self, params):
        """Convert Json wrappers (and nothing else) for this driver."""
        if not params:
            return params
        if isinstance(params, dict):
            return {k: self._adapt_value(v) for k, v in params.items()}
        return tuple(self._adapt_value(v) for v in params)

    def _adapt_value(self, value):
        return value

    # -- lifecycle ----------------------------------------------------------
    def writer(self):
        raise NotImplementedError

    def reader(self):
        raise NotImplementedError

    def release_reader(self, conn):
        """Hand a reader connection back, if the backend pools them."""

    def close(self):
        raise NotImplementedError

    # -- statements ---------------------------------------------------------
    def execute(self, conn, sql, params=()):
        raise NotImplementedError

    def executemany(self, conn, sql, rows):
        raise NotImplementedError

    def run_script(self, conn, sql):
        """Execute a multi-statement DDL script verbatim.

        Migration files are literal SQL for one backend, so they bypass
        translate() — there are no ? placeholders to rewrite and no literal %
        to protect.
        """
        raise NotImplementedError

    def begin(self, conn):
        raise NotImplementedError

    def commit(self, conn):
        conn.commit()

    def rollback(self, conn):
        conn.rollback()

    # -- introspection ------------------------------------------------------
    def table_names(self, conn):
        raise NotImplementedError

    def index_names(self, conn):
        raise NotImplementedError

    def explain(self, conn, sql, params=()):
        raise NotImplementedError

    def size_bytes(self, conn):
        raise NotImplementedError

    def server_version(self, conn):
        raise NotImplementedError

    def journal_mode(self, conn):
        raise NotImplementedError

    def analyze(self, conn):
        """Refresh planner statistics. Called after bulk loads."""

    def truncate(self, conn, tables):
        """Empty `tables` and reset their generated ids.

        Destructive, and only ever called by the test fixtures and the
        benchmark against a database they own.
        """
        raise NotImplementedError

    @contextlib.contextmanager
    def migration_lock(self, conn):
        """Hold an exclusive lock for the duration of applying migrations.

        Two processes starting at once would otherwise both find the same
        migration pending and both try to apply it, and one would fail on a
        relation that already exists. Serialising them makes the loser see an
        up-to-date database and do nothing.
        """
        yield

    @property
    def migrations_dir(self):
        return os.path.join(MIGRATIONS_ROOT, self.name)


# ── SQLite ───────────────────────────────────────────────────────────────────

def _sqlite_extreme(pick):
    def fn(*args):
        present = [a for a in args if a is not None]
        return pick(present) if present else None
    return fn


def _tune_sqlite(conn):
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA cache_size=-32000')      # ~32 MB page cache
    conn.execute('PRAGMA temp_store=MEMORY')
    conn.execute('PRAGMA busy_timeout=10000')
    # PostgreSQL enforces foreign keys unconditionally; SQLite must be asked,
    # per connection, or ON DELETE CASCADE silently does nothing.
    conn.execute('PRAGMA foreign_keys=ON')
    # PostgreSQL's two-argument scalar min/max. SQLite has these under the
    # names MAX/MIN, but those collide with its aggregates, so the shared
    # dialect uses the PostgreSQL spelling and SQLite learns it here.
    conn.create_function('greatest', -1, _sqlite_extreme(max),
                         deterministic=True)
    conn.create_function('least', -1, _sqlite_extreme(min),
                         deterministic=True)
    conn.row_factory = sqlite3.Row
    return conn


class SQLiteBackend(Backend):
    """File-based SQLite. Development and fast local testing only.

    One long-lived writer connection behind a lock plus thread-local readers:
    SQLite permits exactly one writer, and WAL lets readers proceed alongside
    it. This is the constraint PostgreSQL removes.
    """

    name = SQLITE

    def __init__(self, settings):
        super().__init__(settings)
        self._local = threading.local()
        self._readers = []
        self._readers_lock = threading.Lock()
        self._writer = _tune_sqlite(sqlite3.connect(
            settings.dsn, timeout=30, check_same_thread=False))

    def writer(self):
        return self._writer

    def reader(self):
        conn = getattr(self._local, 'conn', None)
        if conn is None:
            conn = _tune_sqlite(sqlite3.connect(self.settings.dsn, timeout=30))
            self._local.conn = conn
            with self._readers_lock:
                self._readers.append(conn)
        return conn

    def close(self):
        self._writer.close()
        with self._readers_lock:
            readers, self._readers = self._readers, []
        for conn in readers:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        self._local = threading.local()

    def _adapt_value(self, value):
        if isinstance(value, Json):
            return (None if value.value is None
                    else json.dumps(value.value, default=str,
                                    separators=(',', ':')))
        return value

    def execute(self, conn, sql, params=()):
        cur = conn.execute(self.translate(sql), self.adapt(params))
        try:
            rows = [dict(r) for r in cur.fetchall()] if cur.description else []
            return Result(rows, cur.rowcount)
        finally:
            cur.close()

    def executemany(self, conn, sql, rows):
        cur = conn.executemany(self.translate(sql),
                               [self.adapt(r) for r in rows])
        try:
            return Result([], cur.rowcount)
        finally:
            cur.close()

    def run_script(self, conn, sql):
        conn.executescript(sql)

    def begin(self, conn):
        conn.execute('BEGIN')

    def table_names(self, conn):
        return [r['name'] for r in self.execute(
            conn,
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' AND name <> 'schema_migrations' "
            'ORDER BY name').rows]

    def index_names(self, conn):
        # `sql IS NOT NULL` excludes the indexes SQLite creates implicitly for
        # PRIMARY KEY and UNIQUE, so this counts only declared indexes — the
        # same set the PostgreSQL query below returns.
        return [(r['tbl_name'], r['name']) for r in self.execute(
            conn,
            "SELECT name, tbl_name FROM sqlite_master WHERE type='index' "
            "AND sql IS NOT NULL AND tbl_name <> 'schema_migrations' "
            'ORDER BY tbl_name, name').rows]

    def explain(self, conn, sql, params=()):
        return self.execute(conn, 'EXPLAIN QUERY PLAN ' + sql, params).rows

    def size_bytes(self, conn):
        try:
            return os.path.getsize(self.settings.dsn)
        except OSError:
            return 0

    def server_version(self, conn):
        return 'SQLite %s' % sqlite3.sqlite_version

    def journal_mode(self, conn):
        return self.execute(conn, 'PRAGMA journal_mode').scalar('unknown')

    def truncate(self, conn, tables):
        conn.execute('PRAGMA foreign_keys=OFF')
        try:
            for table in tables:
                conn.execute('DELETE FROM "%s"' % table)
            # Restart AUTOINCREMENT so ids are reproducible between tests.
            if self.execute(
                    conn,
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
                    "AND name='sqlite_sequence'").scalar(0):
                conn.execute('DELETE FROM sqlite_sequence')
            conn.commit()
        finally:
            conn.execute('PRAGMA foreign_keys=ON')

    def analyze(self, conn):
        conn.execute('ANALYZE')
        conn.commit()


# ── PostgreSQL ───────────────────────────────────────────────────────────────

_PLACEHOLDER = re.compile(r'\?')


class PostgresBackend(Backend):
    """psycopg 3 with a pooled reader set and a dedicated writer connection.

    Readers come from a `psycopg_pool.ConnectionPool` sized for the Flask
    worker's thread count; they run in autocommit so a request never leaves a
    transaction (and therefore a snapshot) open between queries.

    The writer is a single long-lived connection held outside the pool. The
    packet pipeline writes one multi-statement transaction per batch and is
    the only writer by design — the engine runs in exactly one process, which
    `gunicorn.conf.py` enforces. PostgreSQL would handle concurrent writers
    fine; keeping one avoids deadlocks between batches that touch the same
    host and flow rows in different orders.
    """

    name = POSTGRESQL

    def __init__(self, settings):
        super().__init__(settings)
        try:
            import psycopg
            from psycopg.rows import dict_row
            from psycopg_pool import ConnectionPool
        except ImportError as exc:                # pragma: no cover
            raise ConfigError(
                'PostgreSQL support needs psycopg 3: pip install '
                '"psycopg[binary,pool]"  (%s)' % exc)
        self._psycopg = psycopg
        self._options = '-c statement_timeout=%d' % (
            settings.statement_timeout_ms,)
        kwargs = dict(row_factory=dict_row,
                      connect_timeout=settings.connect_timeout,
                      options=self._options)
        try:
            self._pool = ConnectionPool(
                settings.dsn, min_size=settings.pool_min,
                max_size=settings.pool_max, kwargs=dict(kwargs,
                                                        autocommit=True),
                open=True, timeout=settings.connect_timeout,
                name='netwatch-readers')
            self._pool.wait(timeout=max(settings.connect_timeout, 5))
            self._writer = psycopg.connect(settings.dsn, autocommit=False,
                                           **kwargs)
        except Exception as exc:
            raise ConfigError(
                'Cannot connect to PostgreSQL at %s: %s\n'
                'Check the server is running and DATABASE_URL is correct. For '
                'a local one:\n    docker compose up -d postgres'
                % (settings.display, exc))

    def _translate(self, sql):
        # psycopg treats % as the start of a placeholder, so any literal one
        # has to be doubled before ? is rewritten into %s.
        return _PLACEHOLDER.sub('%s', sql.replace('%', '%%'))

    def _adapt_value(self, value):
        if isinstance(value, Json):
            from psycopg.types.json import Jsonb
            return None if value.value is None else Jsonb(value.value)
        return value

    def writer(self):
        return self._writer

    def reader(self):
        return self._pool.getconn()

    def release_reader(self, conn):
        self._pool.putconn(conn)

    def close(self):
        try:
            self._writer.close()
        finally:
            self._pool.close()

    def execute(self, conn, sql, params=()):
        with conn.cursor() as cur:
            cur.execute(self.translate(sql), self.adapt(params) or None)
            rows = cur.fetchall() if cur.description else []
            return Result(rows, cur.rowcount)

    def executemany(self, conn, sql, rows):
        with conn.cursor() as cur:
            cur.executemany(self.translate(sql), [self.adapt(r) for r in rows])
            return Result([], cur.rowcount)

    def run_script(self, conn, sql):
        with conn.cursor() as cur:
            cur.execute(sql)

    def begin(self, conn):
        # psycopg opens a transaction on the first statement of a non-autocommit
        # connection, so an explicit BEGIN here would be a nested-transaction
        # warning. Roll back any transaction the previous batch left behind
        # after an error so the new one starts clean.
        if conn.info.transaction_status:
            conn.rollback()

    def table_names(self, conn):
        return [r['table_name'] for r in self.execute(
            conn,
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = current_schema() AND table_type = 'BASE TABLE' "
            "AND table_name <> 'schema_migrations' "
            'ORDER BY table_name').rows]

    def index_names(self, conn):
        # Excludes indexes that merely implement a PRIMARY KEY or UNIQUE
        # constraint, matching what SQLite's `sql IS NOT NULL` filter returns,
        # so the count means the same thing on both backends.
        return [(r['tbl_name'], r['name']) for r in self.execute(
            conn,
            """SELECT c.relname AS name, t.relname AS tbl_name
               FROM pg_index i
               JOIN pg_class c ON c.oid = i.indexrelid
               JOIN pg_class t ON t.oid = i.indrelid
               JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname = current_schema()
                 AND t.relname <> 'schema_migrations'
                 AND NOT EXISTS (SELECT 1 FROM pg_constraint
                                 WHERE conindid = i.indexrelid)
               ORDER BY t.relname, c.relname""").rows]

    def explain(self, conn, sql, params=()):
        rows = self.execute(conn, 'EXPLAIN ' + sql, params).rows
        # Normalised to the same shape SQLite's EXPLAIN QUERY PLAN returns, so
        # callers read one key regardless of backend.
        return [{'detail': r['QUERY PLAN']} for r in rows]

    def size_bytes(self, conn):
        return self.execute(
            conn, 'SELECT pg_database_size(current_database())').scalar(0)

    def server_version(self, conn):
        return self.execute(conn, 'SHOW server_version').scalar('unknown')

    def journal_mode(self, conn):
        # PostgreSQL is unconditionally write-ahead logged; wal_level says how
        # much detail the log carries, not whether there is one. Reported under
        # the same key SQLite uses so /api/health and the dashboard are
        # backend-independent.
        return 'wal (wal_level=%s)' % self.execute(
            conn, 'SHOW wal_level').scalar('unknown')

    def truncate(self, conn, tables):
        if not tables:
            return
        quoted = ', '.join('"%s"' % t for t in tables)
        self.execute(conn, 'TRUNCATE %s RESTART IDENTITY CASCADE' % quoted)
        self.commit(conn)

    # An arbitrary but fixed pair of 32-bit integers identifying this
    # application's migration lock. Advisory locks are just numbers to
    # PostgreSQL; the only requirement is that everyone agrees on which.
    _MIGRATION_LOCK = (0x4E57_5443, 0x4D49_4752)     # 'NWTC', 'MIGR'

    @contextlib.contextmanager
    def migration_lock(self, conn):
        # pg_advisory_lock, not pg_advisory_xact_lock: each migration is its own
        # transaction and the lock has to span all of them. A session-level
        # advisory lock survives the commit below, which is what allows that.
        #
        # SET LOCAL, so the allowance applies to the lock wait alone and is
        # reverted by that same commit. PG_STATEMENT_TIMEOUT_MS is sized for
        # queries, and waiting behind another instance's migration is not one.
        self.execute(conn, 'SET LOCAL statement_timeout = 120000')
        self.execute(conn, 'SELECT pg_advisory_lock(?, ?)',
                     self._MIGRATION_LOCK)
        self.commit(conn)
        try:
            yield
        finally:
            # Unlock on the way out however we got here, or the next process to
            # start would wait behind a lock nobody holds a reason for.
            try:
                self.execute(conn, 'SELECT pg_advisory_unlock(?, ?)',
                             self._MIGRATION_LOCK)
            finally:
                self.commit(conn)

    def analyze(self, conn):
        previous = conn.autocommit
        conn.autocommit = True
        try:
            self.execute(conn, 'ANALYZE')
        finally:
            conn.autocommit = previous


BACKENDS = {SQLITE: SQLiteBackend, POSTGRESQL: PostgresBackend}


def make_backend(settings):
    return BACKENDS[settings.backend](settings)


# ── administrative helpers ───────────────────────────────────────────────────
#
# Creating and dropping whole databases is not something the application does;
# these exist for the test fixtures and the benchmark, which each run against a
# scratch database of their own so they never touch a real one.

def database_name(dsn):
    """The database a PostgreSQL DSN points at."""
    return urllib.parse.urlsplit(dsn).path.lstrip('/')


def with_database(dsn, name):
    """The same DSN pointing at a different database."""
    parts = urllib.parse.urlsplit(dsn)
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, '/' + name, parts.query, parts.fragment))


def _admin_connection(dsn):
    """A connection to the `postgres` maintenance database on the same server.

    CREATE DATABASE and DROP DATABASE cannot run inside a transaction, hence
    autocommit.
    """
    import psycopg
    return psycopg.connect(with_database(dsn, 'postgres'), autocommit=True)


def create_database(dsn, exists_ok=True):
    """Create the database `dsn` names. Returns True if it was created."""
    name = database_name(dsn)
    if not name:
        raise ConfigError('DSN names no database: %s' % redact(dsn))
    with _admin_connection(dsn) as conn:
        existing = conn.execute(
            'SELECT 1 FROM pg_database WHERE datname = %s', (name,)).fetchone()
        if existing:
            if not exists_ok:
                raise ConfigError('database %r already exists' % name)
            return False
        # The name comes from test/benchmark code, never from a request, but
        # quote it properly rather than relying on that.
        from psycopg import sql
        conn.execute(sql.SQL('CREATE DATABASE {}').format(
            sql.Identifier(name)))
        return True


def drop_database(dsn):
    """Drop the database `dsn` names, disconnecting anything still attached."""
    from psycopg import sql
    name = database_name(dsn)
    with _admin_connection(dsn) as conn:
        conn.execute(sql.SQL('DROP DATABASE IF EXISTS {} WITH (FORCE)').format(
            sql.Identifier(name)))
