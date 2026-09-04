"""
Gunicorn configuration for NetWatch SOC.

The important thing this file does is protect a real architectural constraint.

`App.create_app()` starts the packet-capture/detection engine on a background
thread *inside the process that calls it*. Gunicorn calls it once per worker.
So with N workers you get N independent engines, each generating its own
traffic and writing to the same SQLite file: duplicated packet rows, duplicated
alerts, and N processes contending for the writer lock.

That is silent corruption, not a crash, so `on_starting` refuses to boot the
combination rather than letting it run. Two supported topologies:

  1. All-in-one (default) — one worker, many threads. The engine and the API
     share a process; SQLite has exactly one writer. Threads are the right
     concurrency primitive here because every request is a short, GIL-releasing
     SQLite read (p95 well under a millisecond).

  2. Split — a dedicated engine container (NETWATCH_SIMULATE=1, no HTTP) plus
     read-only API workers (NETWATCH_SIMULATE=0, workers > 1) over a shared
     volume. SQLite WAL supports one writer with many concurrent readers, so
     this scales the API without touching the write path.

Overridable via environment: GUNICORN_WORKERS, GUNICORN_THREADS,
GUNICORN_TIMEOUT, GUNICORN_LOGLEVEL, NETWATCH_BIND.
"""

import multiprocessing
import re
import os


def _int_env(name, default):
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise SystemExit('%s must be an integer, got %r' % (name, raw))


def _simulation_enabled():
    return os.environ.get('NETWATCH_SIMULATE', '1') != '0'


bind = os.environ.get('NETWATCH_BIND', '0.0.0.0:5001')

# Default to a single worker: correct for the all-in-one topology. Read-only
# API containers override this (see the `web` service in docker-compose.yml).
workers = _int_env('GUNICORN_WORKERS', 1)
threads = _int_env('GUNICORN_THREADS', 8)
worker_class = 'gthread'

# Gunicorn's worker heartbeat file. On a read-only root filesystem this must
# point at a writable mount; /dev/shm is memory-backed, so the heartbeat never
# touches disk and cannot stall on I/O.
worker_tmp_dir = '/dev/shm'

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
            '  Each worker would start its own capture/detection engine '
            'against the same database,\n'
            '  so the packet and alert counts would be multiplied by the '
            'worker count. On SQLite the\n'
            '  workers would also contend for the single writer lock; on '
            'PostgreSQL the duplication\n'
            '  remains even though the contention does not.\n'
            '  Either set GUNICORN_WORKERS=1 (all-in-one), or run a dedicated '
            'engine container and set\n'
            '  NETWATCH_SIMULATE=0 on these API workers (the default compose '
            'topology).',
            workers)
        raise SystemExit(1)

    if workers > 1 and workers > multiprocessing.cpu_count() * 2 + 1:
        server.log.warning(
            'GUNICORN_WORKERS=%d exceeds the usual 2*CPU+1 ceiling (%d CPUs)',
            workers, multiprocessing.cpu_count())

    # Report the store without leaking a password from the URL.
    url = os.environ.get('NETWATCH_DB_URL')
    target = (re.sub(r'//[^@/]*@', '//***@', url) if url
              else os.environ.get('NETWATCH_DB', '<default sqlite>'))
    server.log.info(
        'NetWatch SOC starting: workers=%d threads=%d simulation=%s db=%s',
        workers, threads, 'on' if _simulation_enabled() else 'off', target)


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
