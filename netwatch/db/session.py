"""
Engine and connection-pool management.

One ``sqlalchemy.Engine`` per process, with an explicit ``QueuePool``. The
pool matters here: the pipeline's persistence stage runs several writer
threads and the API serves concurrent requests, and both sit behind the same
engine. Sizing the pool below PostgreSQL's ``max_connections`` and above the
concurrent-worker count is the difference between "waits briefly for a
connection" and "opens a TCP connection and re-authenticates per query".
"""

import os
import threading

from sqlalchemy import create_engine, event, text
from sqlalchemy.pool import NullPool, QueuePool

DEFAULT_URL = 'postgresql+psycopg://netwatch:netwatch@localhost:5432/netwatch'

# See the note in _on_connect. 'off' by default because this is a telemetry
# ingest workload; every benchmark records the value it ran under.
SYNCHRONOUS_COMMIT = os.environ.get('NETWATCH_SYNCHRONOUS_COMMIT', 'off')

_lock = threading.Lock()
_engines = {}


def database_url(url=None):
    """Resolve the database URL, normalising the driver to psycopg 3."""
    url = url or os.environ.get('NETWATCH_DATABASE_URL') or DEFAULT_URL
    if url.startswith('postgres://'):          # libpq / Heroku style
        url = 'postgresql://' + url[len('postgres://'):]
    if url.startswith('postgresql://'):
        url = 'postgresql+psycopg://' + url[len('postgresql://'):]
    return url


def get_engine(url=None, pool_size=None, max_overflow=None, echo=False,
               poolclass=None, schema=None):
    """Return the process-wide engine for `url`, creating it on first use.

    `schema` pins every connection's search_path to a named PostgreSQL schema.
    The test suite uses it to give a session-populated fixture database and a
    truncate-per-test database separate namespaces inside one server, which is
    both faster than creating databases and closer to how a deployment would
    isolate tenants.
    """
    url = database_url(url)
    key = (url, schema)
    with _lock:
        engine = _engines.get(key)
        if engine is not None:
            return engine

        pool_size = int(pool_size if pool_size is not None
                        else os.environ.get('NETWATCH_DB_POOL_SIZE', 10))
        max_overflow = int(max_overflow if max_overflow is not None
                           else os.environ.get('NETWATCH_DB_MAX_OVERFLOW', 10))
        connect_args = {'prepare_threshold': 5}
        if schema:
            connect_args['options'] = '-csearch_path=%s' % schema
        # Round-trips dominate the write path, so ask psycopg to keep
        # server-side prepared plans warm after a statement repeats.
        kwargs = {
            'echo': echo,
            'future': True,
            'connect_args': connect_args,
            'pool_pre_ping': True,
        }
        if poolclass is NullPool:
            kwargs['poolclass'] = NullPool
        else:
            kwargs.update(poolclass=QueuePool, pool_size=pool_size,
                          max_overflow=max_overflow, pool_timeout=30,
                          # Recycle below any proxy/server idle timeout so a
                          # silently-closed socket is never handed out.
                          pool_recycle=1800)
        engine = create_engine(url, **kwargs)
        _engines[key] = engine
        return engine


def dispose_all():
    """Close every pooled connection. Used by tests and on shutdown."""
    with _lock:
        for engine in _engines.values():
            engine.dispose()
        _engines.clear()


def wait_for_database(url=None, timeout_s=60.0, interval_s=0.5):
    """Block until the server accepts a connection. Used by the entrypoints."""
    import time
    engine = get_engine(url)
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        try:
            with engine.connect() as conn:
                conn.execute(text('SELECT 1'))
            return engine
        except Exception as exc:      # noqa: BLE001 - retried deliberately
            last = exc
            time.sleep(interval_s)
    raise RuntimeError('database not reachable within %.0fs: %s'
                       % (timeout_s, last))


@event.listens_for(QueuePool, 'connect')
def _on_connect(dbapi_conn, _record):
    """Per-connection session settings applied once, not per query."""
    with dbapi_conn.cursor() as cur:
        cur.execute("SET TIME ZONE 'UTC'")
        # Packet telemetry is an append-only firehose: letting the server
        # acknowledge a commit before the WAL record reaches disk trades a
        # bounded window (a few hundred ms) of the most recent packets for a
        # large ingest gain. That trade is right for telemetry and wrong for,
        # say, payments, so it is a named setting rather than a hidden one.
        # Set NETWATCH_SYNCHRONOUS_COMMIT=on to get PostgreSQL's default back;
        # the benchmarks report whichever value was in force.
        cur.execute('SET synchronous_commit TO %s'
                    % ('on' if SYNCHRONOUS_COMMIT == 'on' else 'off'))
