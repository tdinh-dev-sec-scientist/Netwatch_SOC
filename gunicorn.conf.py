"""
Gunicorn configuration for NetWatch.

The important thing this file does is protect a real architectural constraint.

`create_app(run_pipeline=True)` starts the five-stage pipeline *inside the
process that calls it*. Gunicorn calls it once per worker, so with N workers
you get N independent pipelines, each generating its own traffic and writing
to the same database: duplicated packets and alerts, and N times the write
load for no extra coverage. That is a silent data problem rather than a crash,
so `on_starting` refuses the combination instead of letting it run.

Two supported topologies:

  1. Embedded (development) — one worker, many threads, pipeline on. Simple to
     run; the pipeline and the API share a process.

  2. Split (default in compose, and the shape PostgreSQL makes possible) — a
     dedicated engine container running `python -m netwatch.cli engine`, plus
     any number of stateless API workers with the pipeline off. The API tier
     scales horizontally without touching the write path, which is the reason
     persistence moved off SQLite in the first place.

Threads rather than processes for the API tier: every request is a short query
that spends its time inside psycopg waiting on a socket, and psycopg releases
the GIL for that wait.

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
        raise SystemExit('%s must be an integer, got %r' % (name, raw)) from None


def _pipeline_enabled():
    return os.environ.get('NETWATCH_RUN_PIPELINE', '0').strip().lower() \
        not in ('0', 'false', 'no', 'off', '')


bind = os.environ.get('NETWATCH_BIND', '0.0.0.0:5001')

workers = _int_env('GUNICORN_WORKERS', 2)
threads = _int_env('GUNICORN_THREADS', 8)
worker_class = 'gthread'

# Gunicorn's worker heartbeat file. On a read-only root filesystem this must
# point at a writable mount; /dev/shm is memory-backed, so the heartbeat never
# touches disk and cannot stall on I/O.
worker_tmp_dir = '/dev/shm'

# MUST stay False. With preload_app the app is built in the master before fork,
# and neither threads nor database connections survive fork(): an embedded
# pipeline would be started in the master and absent from every worker, and
# pooled connections would be shared across processes.
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
access_log_format = '%(h)s "%(r)s" %(s)s %(b)s %(M)sms "%(a)s"'

# Honour X-Forwarded-* only from trusted proxies. Defaults to none: without a
# reverse proxy in front, trusting these headers lets any client spoof its
# source address in the logs. gunicorn wants a comma-separated list of
# individual addresses (or "*"); it rejects CIDR notation at startup.
forwarded_allow_ips = os.environ.get('GUNICORN_FORWARDED_ALLOW_IPS', '')
proxy_allow_ips = forwarded_allow_ips


def on_starting(server):
    """Refuse topologies that would run more than one pipeline per database."""
    if _pipeline_enabled() and workers > 1:
        server.log.error(
            'Refusing to start: NETWATCH_RUN_PIPELINE is on with %d workers.\n'
            '  Each worker would start its own capture pipeline against the '
            'same database,\n'
            '  producing duplicated packets and alerts and multiplying the '
            'write load.\n'
            '  Either set GUNICORN_WORKERS=1 (embedded), or run a dedicated '
            'engine container and leave\n'
            '  NETWATCH_RUN_PIPELINE unset on these API workers (split '
            'topology).', workers)
        raise SystemExit(1)

    if workers > 1 and workers > multiprocessing.cpu_count() * 2 + 1:
        server.log.warning(
            'GUNICORN_WORKERS=%d exceeds the usual 2*CPU+1 ceiling (%d CPUs)',
            workers, multiprocessing.cpu_count())

    server.log.info('NetWatch starting: workers=%d threads=%d pipeline=%s',
                    workers, threads,
                    'on' if _pipeline_enabled() else 'off')


def worker_exit(server, worker):
    """Drain an embedded pipeline on graceful shutdown.

    The persistence stage buffers packets and commits them per batch. Without
    this hook a SIGTERM would discard whatever is still buffered, because the
    stage workers are daemon threads that die with the process.
    """
    try:
        pipeline = getattr(worker.wsgi, 'pipeline', None)
        if pipeline is None:
            return
        report = pipeline.shutdown(timeout=graceful_timeout)
        server.log.info('pipeline drained: %d packets persisted, %d dropped',
                        report['accounting']['packets_persisted'],
                        report['accounting']['packets_dropped'])
    except Exception as exc:      # noqa: BLE001 - never block shutdown
        server.log.warning('pipeline shutdown hook failed: %s', exc)
