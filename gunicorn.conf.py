"""
Gunicorn configuration for NetWatch SOC.

The important thing this file does is protect a real architectural constraint.

`App.create_app()` starts the packet-capture/detection engine on a background
thread *inside the process that calls it*. Gunicorn calls it once per worker.
So with N workers you get N independent engines, each generating its own
traffic and writing it: N times the packet rows and N times the alerts, from
what is meant to be one view of one network.

PostgreSQL would accept those concurrent writers without complaint — this is no
longer a database limitation, as it was under SQLite's single writer — which is
exactly why it has to be caught here. Duplicated telemetry is silently wrong
data, not a crash, so `on_starting` refuses to boot the combination. Two
supported topologies:

  1. All-in-one (default) — one worker, many threads. The engine and the API
     share a process. Threads are the right concurrency primitive because every
     request is a short, GIL-releasing database read (p95 around a millisecond).
     Keep PG_POOL_MAX at or above GUNICORN_THREADS so concurrent requests are
     not queueing for a connection.

  2. Split — a dedicated engine container (NETWATCH_SIMULATE=1, no HTTP) plus
     API workers (NETWATCH_SIMULATE=0, workers > 1). Under PostgreSQL these no
     longer need to share a filesystem, only DATABASE_URL, so they can run on
     separate hosts. Size the pool for the whole tier: workers x threads
     connections at most, against the server's max_connections.

Overridable via environment: GUNICORN_WORKERS, GUNICORN_THREADS,
GUNICORN_TIMEOUT, GUNICORN_LOGLEVEL, NETWATCH_BIND.
"""

import multiprocessing
import os


def _int_env(name, default):
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise SystemExit('%s must be an integer, got %r' % (name, raw))


def _redacted_target():
    """The configured database, with any password removed, for the log line."""
    url = os.environ.get('DATABASE_URL')
    if url:
        # Imported lazily so this config file stays loadable without the app's
        # dependencies present (tests exec it with runpy).
        import db_backends
        return db_backends.redact(url)
    if os.environ.get('DB_BACKEND') == 'sqlite':
        return os.environ.get('NETWATCH_DB', '<default sqlite file>')
    return os.environ.get('PG_DB', '<unset>')


def _simulation_enabled():
    return os.environ.get('NETWATCH_SIMULATE', '1') != '0'


def _bind():
    """NETWATCH_BIND wins; otherwise honour a platform-assigned PORT.

    Hosting platforms such as Render tell the container which port to listen on
    through PORT. Locally and under docker compose neither is set, so the
    documented default of 5001 is unchanged.
    """
    explicit = os.environ.get('NETWATCH_BIND')
    if explicit:
        return explicit
    port = os.environ.get('PORT', '5001')
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise SystemExit('PORT must be a TCP port number, got %r' % port)
    return '0.0.0.0:%s' % port


bind = _bind()

# Default to a single worker: correct for the all-in-one topology. Read-only
# API containers override this (see the `web` service in docker-compose.yml).
workers = _int_env('GUNICORN_WORKERS', 1)
threads = _int_env('GUNICORN_THREADS', 8)
worker_class = 'gthread'

# Gunicorn's worker heartbeat file. On a read-only root filesystem this must
# point at a writable mount; /dev/shm is memory-backed, so the heartbeat never
# touches disk and cannot stall on I/O.
worker_tmp_dir = '/dev/shm' if os.path.isdir('/dev/shm') else None

# MUST stay False. With preload_app the app is built in the master before fork,
# and threads do not survive fork() — the engine thread would be started in the
# master and be absent from every worker that actually serves traffic.
preload_app = False

timeout = _int_env('GUNICORN_TIMEOUT', 60)
graceful_timeout = _int_env('GUNICORN_GRACEFUL_TIMEOUT', 30)
keepalive = 5

# Bound request sizes so a hostile client cannot exhaust memory through headers.
limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190

# Recycle workers periodically to bound the effect of any slow leak; jitter
# prevents all workers restarting in lockstep.
max_requests = _int_env('GUNICORN_MAX_REQUESTS', 10000)
max_requests_jitter = _int_env('GUNICORN_MAX_REQUESTS_JITTER', 1000)

# Log to stdout/stderr so the container runtime owns collection and rotation.
accesslog = '-'
errorlog = '-'
loglevel = os.environ.get('GUNICORN_LOGLEVEL', 'info')
access_log_format = ('%(h)s "%(r)s" %(s)s %(b)s %(M)sms "%(a)s"')

# Honour X-Forwarded-* only from trusted proxies. Defaults to none: without a
# reverse proxy in front, trusting these headers lets any client spoof its
# source address in the logs.
forwarded_allow_ips = os.environ.get('GUNICORN_FORWARDED_ALLOW_IPS', '')
proxy_allow_ips = forwarded_allow_ips


def on_starting(server):
    """Refuse topologies that would run more than one engine against one DB."""
    if _simulation_enabled() and workers > 1:
        server.log.error(
            'Refusing to start: NETWATCH_SIMULATE is on with %d workers.\n'
            '  Each worker would start its own capture/detection engine and '
            'write to the same database,\n'
            '  so every packet and alert would be recorded %d times. '
            'PostgreSQL accepts the concurrent\n'
            '  writes happily, which is why this has to be refused here '
            'rather than by the database.\n'
            '  Either set GUNICORN_WORKERS=1 (all-in-one), or run a dedicated '
            'engine container and set\n'
            '  NETWATCH_SIMULATE=0 on these API workers (split topology).',
            workers, workers)
        raise SystemExit(1)

    if workers > 1 and workers > multiprocessing.cpu_count() * 2 + 1:
        server.log.warning(
            'GUNICORN_WORKERS=%d exceeds the usual 2*CPU+1 ceiling (%d CPUs)',
            workers, multiprocessing.cpu_count())

    pool_max = _int_env('PG_POOL_MAX', 10)
    if os.environ.get('DB_BACKEND', 'postgresql') != 'sqlite' \
            and pool_max < threads:
        server.log.warning(
            'PG_POOL_MAX=%d is below GUNICORN_THREADS=%d, so requests will '
            'queue waiting for a database connection', pool_max, threads)

    server.log.info(
        'NetWatch SOC starting: workers=%d threads=%d simulation=%s '
        'backend=%s db=%s',
        workers, threads, 'on' if _simulation_enabled() else 'off',
        os.environ.get('DB_BACKEND', 'postgresql'),
        _redacted_target())


def worker_exit(server, worker):
    """Stop the engine and flush its pending batch on graceful shutdown.

    The engine buffers packets and writes them in one transaction per batch.
    Without this hook a SIGTERM discards whatever is still buffered, because
    the engine runs on a daemon thread that dies with the process.
    """
    try:
        app = worker.wsgi
        simulator = getattr(app, 'simulator', None)
        if simulator is None:
            return
        simulator.stop()
        simulator.flush()
        server.log.info('engine stopped; buffered batch flushed')
    except Exception as exc:                      # never block shutdown
        server.log.warning('engine shutdown hook failed: %s', exc)
