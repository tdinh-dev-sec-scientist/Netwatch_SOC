"""
Database dialects for NetWatch SOC.

The application supports two backends behind one identical `DatabaseManager`
API:

  sqlite      zero-dependency default. Used by the test suite, the benchmark
              and single-container deployments.
  postgresql  the deployment target in docker compose. Chosen when
              NETWATCH_DB_URL is a postgresql:// URL.

Everything that actually differs between the two is isolated here:

  * placeholder style          ``?``  vs  ``%s``
  * identity columns           ``INTEGER PRIMARY KEY AUTOINCREMENT``
                               vs ``BIGSERIAL PRIMARY KEY``
  * 8-byte floats              ``REAL`` vs ``DOUBLE PRECISION``
                               (PostgreSQL ``REAL`` is 4-byte and would lose
                               sub-second precision on unix timestamps)
  * scalar min/max             ``MIN(a,b)`` vs ``LEAST(a,b)``
  * conflict-ignore insert     ``INSERT OR IGNORE`` vs ``ON CONFLICT DO NOTHING``
  * catalog introspection      ``sqlite_master`` vs ``information_schema``
  * plan introspection         ``EXPLAIN QUERY PLAN`` vs ``EXPLAIN``

The shared SQL is written once in DB_Manager using ``?`` placeholders and
``{TOKEN}`` substitutions; each dialect renders it. Both backends run in
explicit-transaction mode (SQLite ``isolation_level=None``, psycopg
``autocommit=True``) so the transaction boundaries in the write path are the
same statements on both.
"""

import os
import re

SQLITE = 'sqlite'
POSTGRESQL = 'postgresql'

DEFAULT_SQLITE_PATH = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), 'netwatch.db')

# Substituted into the shared SQL by `render()`.
_SQLITE_TOKENS = {
    'PK': 'INTEGER PRIMARY KEY AUTOINCREMENT',
    'REAL': 'REAL',
    'INT': 'INTEGER',
    'BIGINT': 'INTEGER',
    'GREATEST': 'MAX',
    'LEAST': 'MIN',
    'INSERT_IGNORE': 'INSERT OR IGNORE INTO',
    'ON_CONFLICT_NOTHING': '',
}
_POSTGRES_TOKENS = {
    'PK': 'BIGSERIAL PRIMARY KEY',
    'REAL': 'DOUBLE PRECISION',
    'INT': 'INTEGER',
    'BIGINT': 'BIGINT',
    'GREATEST': 'GREATEST',
    'LEAST': 'LEAST',
    'INSERT_IGNORE': 'INSERT INTO',
    'ON_CONFLICT_NOTHING': 'ON CONFLICT DO NOTHING',
}

_PLACEHOLDER = re.compile(r'\?')


class Dialect:
    """Base: renders shared SQL and opens connections."""

    name = None
    tokens = {}
    supports_wal = False

    def render(self, sql):
        """Substitute dialect tokens and placeholder style into shared SQL."""
        if '{' in sql:
            sql = sql.format(**self.tokens)
        return self.adapt_placeholders(sql)

    def adapt_placeholders(self, sql):
        return sql

    # ── connections ─────────────────────────────────────────────────────────

    def connect(self, readonly=False):
        raise NotImplementedError

    def tune(self, conn):
        return conn

    # ── introspection ───────────────────────────────────────────────────────

    def table_names_sql(self):
        raise NotImplementedError

    def index_names_sql(self):
        raise NotImplementedError

    def explain_sql(self, sql):
        raise NotImplementedError

    @staticmethod
    def plan_uses_index(plan_text, index_name=None):
        raise NotImplementedError

    def journal_mode(self, manager):
        return 'n/a'


class SQLiteDialect(Dialect):
    name = SQLITE
    tokens = _SQLITE_TOKENS
    supports_wal = True

    def __init__(self, path=None):
        self.path = path or DEFAULT_SQLITE_PATH
        self.target = self.path

    def connect(self, readonly=False):
        import sqlite3
        # check_same_thread=False on both: the single write connection is
        # shared across threads (the engine thread writes while gunicorn's
        # worker threads acknowledge alerts) and is serialised by
        # DatabaseManager's own lock, which is the guarantee sqlite3's check
        # exists to approximate. Reader connections are thread-local, so the
        # check would never fire for them either way.
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        # Explicit transaction control on both backends: nothing is implicitly
        # wrapped, so BEGIN/COMMIT in the write path mean the same thing here
        # as they do on PostgreSQL.
        conn.isolation_level = None
        conn.row_factory = sqlite3.Row
        return self.tune(conn)

    def tune(self, conn):
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.execute('PRAGMA cache_size=-32000')      # ~32 MB page cache
        conn.execute('PRAGMA temp_store=MEMORY')
        conn.execute('PRAGMA busy_timeout=10000')
        conn.execute('PRAGMA foreign_keys=ON')
        return conn

    def executescript(self, conn, script):
        conn.executescript(self.render(script))

    def table_names_sql(self):
        return ("SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name")

    def index_names_sql(self):
        return ("SELECT tbl_name AS table_name, name AS index_name "
                "FROM sqlite_master WHERE type='index' AND sql IS NOT NULL "
                "ORDER BY tbl_name, name")

    def explain_sql(self, sql):
        return 'EXPLAIN QUERY PLAN ' + sql

    @staticmethod
    def plan_text(rows):
        return ' '.join(str(r.get('detail', '')) for r in rows)

    @staticmethod
    def plan_uses_index(plan_text, index_name=None):
        if index_name and index_name not in plan_text:
            return False
        return 'USING' in plan_text and 'INDEX' in plan_text

    @staticmethod
    def plan_scans_table(plan_text, table):
        return ('SCAN ' + table) in plan_text

    def journal_mode(self, manager):
        return manager._scalar('PRAGMA journal_mode', (), 'unknown')

    def describe(self):
        return {'backend': self.name, 'target': self.path}


_SCHEMA_NAME = re.compile(r'^[a-z_][a-z0-9_]{0,62}$')


class PostgresDialect(Dialect):
    name = POSTGRESQL
    tokens = _POSTGRES_TOKENS
    supports_wal = False

    def __init__(self, url, schema=None):
        self.url = url
        if schema is not None and not _SCHEMA_NAME.match(schema):
            # The schema name is interpolated into DDL, which cannot be
            # parameterised, so it is validated rather than escaped.
            raise ValueError('invalid schema name %r' % schema)
        self.schema = schema
        # Never let a password reach a log line or an API response.
        self.target = re.sub(r'//[^@/]*@', '//***@', url)
        if schema:
            self.target += '#' + schema

    def adapt_placeholders(self, sql):
        return _PLACEHOLDER.sub('%s', sql)

    def connect(self, readonly=False):
        import psycopg
        from psycopg.rows import dict_row
        conn = psycopg.connect(self.url, autocommit=True, row_factory=dict_row)
        return self.tune(conn)

    def tune(self, conn):
        # statement_timeout keeps a pathological analyst query from pinning a
        # backend forever; the API's own queries are milliseconds.
        conn.execute("SET statement_timeout = '30s'")
        conn.execute("SET timezone = 'UTC'")
        if self.schema:
            conn.execute('CREATE SCHEMA IF NOT EXISTS %s' % self.schema)
            conn.execute('SET search_path TO %s' % self.schema)
        return conn

    def drop_schema(self, conn):
        """Tear down an isolated schema. Used by the test fixtures."""
        if self.schema:
            conn.execute('DROP SCHEMA IF EXISTS %s CASCADE' % self.schema)

    def executescript(self, conn, script):
        conn.execute(self.render(script))

    def table_names_sql(self):
        return ("SELECT table_name AS name FROM information_schema.tables "
                "WHERE table_schema = current_schema() "
                "AND table_type = 'BASE TABLE' ORDER BY table_name")

    def index_names_sql(self):
        return ("SELECT tablename AS table_name, indexname AS index_name "
                "FROM pg_indexes WHERE schemaname = current_schema() "
                "ORDER BY tablename, indexname")

    def explain_sql(self, sql):
        return 'EXPLAIN ' + sql

    @staticmethod
    def plan_text(rows):
        return ' '.join(str(list(r.values())[0]) for r in rows)

    @staticmethod
    def plan_uses_index(plan_text, index_name=None):
        if index_name and index_name not in plan_text:
            return False
        return 'Index Scan' in plan_text or 'Index Only Scan' in plan_text \
            or 'Bitmap Index Scan' in plan_text

    @staticmethod
    def plan_scans_table(plan_text, table):
        return ('Seq Scan on ' + table) in plan_text

    def describe(self):
        return {'backend': self.name, 'target': self.target}


def from_env(db_path=None, url=None, schema=None):
    """Pick a dialect from an explicit argument or the environment.

    Precedence: explicit `url` > explicit `db_path` > NETWATCH_DB_URL >
    NETWATCH_DB (a filesystem path) > ./netwatch.db.

    `schema` isolates a PostgreSQL connection into its own namespace; the test
    fixtures use it to give every test a private schema on a shared server.
    """
    url = url or (db_path if _is_url(db_path) else None)
    if url is None and not db_path:
        env_url = os.environ.get('NETWATCH_DB_URL')
        if env_url:
            url = env_url
    if url:
        if not _is_url(url):
            raise ValueError('not a database URL: %r' % url)
        return PostgresDialect(url, schema=schema
                               or os.environ.get('NETWATCH_DB_SCHEMA'))
    return SQLiteDialect(db_path or os.environ.get('NETWATCH_DB')
                         or DEFAULT_SQLITE_PATH)


def _is_url(value):
    return isinstance(value, str) and value.startswith(
        ('postgresql://', 'postgres://'))
