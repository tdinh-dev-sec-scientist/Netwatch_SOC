# syntax=docker/dockerfile:1.7
#
# NetWatch SOC — production image.
#
# Build stages:
#   builder  installs dependencies into a self-contained virtualenv
#   test     runs the full suite against that venv (CI target, not shipped)
#   runtime  final image: venv + application source, non-root, no build tools
#
#   docker build -t netwatch-soc:latest .
#   docker build --target test .            # run the full test suite in the build
#
# Pin the base by digest for reproducible, tamper-evident builds. Resolve the
# current digest yourself rather than trusting one copied from a template:
#   docker buildx imagetools inspect python:3.11-slim-bookworm
# then change the FROM lines to python:3.11-slim-bookworm@sha256:<digest>.

ARG PYTHON_IMAGE=python:3.11-slim-bookworm

# ─────────────────────────────────────────────────────────────── builder ─────
FROM ${PYTHON_IMAGE} AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Dependency layer is cached independently of application source, so a code
# change does not trigger a reinstall.
#
# For a supply-chain-hardened build, generate a hash-pinned lock file
# (`pip-compile --generate-hashes`) and add --require-hashes here; pip then
# refuses any artifact whose digest does not match.
COPY requirements.txt ./
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

ENV PATH="/opt/venv/bin:${PATH}"

# ──────────────────────────────────────────────────────────────── test ───────
# Optional CI target. Runs the suite inside the image being built, so a
# regression fails the build rather than reaching a registry.
#
# `docker build` has no database to reach, so this pass uses the SQLite
# fallback; the PostgreSQL-specific tests skip themselves. It is a smoke gate on
# the image's contents, not the authoritative run — CI runs the full suite
# against a real PostgreSQL service, and `docker compose --profile test run
# --rm tests` runs this image's suite against the compose database.
FROM builder AS test

ENV DB_BACKEND=sqlite \
    NETWATCH_DB=/tmp/netwatch-build-test.db

WORKDIR /app
COPY . .
RUN /opt/venv/bin/python -m pytest -q

# ─────────────────────────────────────────────────────────────── runtime ─────
FROM ${PYTHON_IMAGE} AS runtime

ARG APP_UID=10001
ARG APP_GID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PATH="/opt/venv/bin:${PATH}" \
    DB_BACKEND=postgresql

# Patch the base OS, then drop apt state. No compilers or package managers are
# needed at runtime — the application is pure Python and the venv is prebuilt.
RUN set -eux; \
    apt-get update; \
    apt-get upgrade -y --no-install-recommends; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --gid "${APP_GID}" --system netwatch; \
    useradd  --uid "${APP_UID}" --gid "${APP_GID}" --system \
             --home-dir /app --no-create-home --shell /usr/sbin/nologin netwatch; \
    install -d -o "${APP_UID}" -g "${APP_GID}" -m 0750 /app /data

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app

# Copy source explicitly rather than `COPY . .` so nothing unlisted — a local
# database, a .env, a stray credential file — can be pulled into the image even
# if .dockerignore is edited later.
#
# tests/test_deployment.py fails if a module the app imports, or a script a
# compose service runs, is missing from this list. engine.py was once left out,
# which broke the split topology at `docker compose --profile split up`.
COPY --chown=${APP_UID}:${APP_GID} App.py DB_Manager.py PacketSimulator.py \
     ProtocolAnalyzer.py ThreatDetector.py benchmark.py config.py \
     db_backends.py engine.py frames.py geoip.py hardening.py migrate.py \
     mitre.py gunicorn.conf.py ./
COPY --chown=${APP_UID}:${APP_GID} detectors/ ./detectors/
# The schema lives in versioned SQL, not in the application, so the image
# cannot create its database without these.
COPY --chown=${APP_UID}:${APP_GID} migrations/ ./migrations/
COPY --chown=${APP_UID}:${APP_GID} templates/ ./templates/
COPY --chown=${APP_UID}:${APP_GID} static/ ./static/

USER ${APP_UID}:${APP_GID}

# The database is PostgreSQL and lives outside the container, so this image
# stores nothing and needs no volume: DATABASE_URL is all it wants. The
# read-only root filesystem the compose file applies is therefore enough.

EXPOSE 5001

# Verifies the application answers *and* that its schema is intact — a process
# that is listening but cannot reach its database is not healthy. table_count
# comes from the live connection, so this fails if PostgreSQL is unreachable.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import json,os,sys,urllib.request;\
u='http://127.0.0.1:%s/api/health' % os.environ.get('PORT','5001');\
d=json.load(urllib.request.urlopen(u,timeout=4));\
sys.exit(0 if d.get('status')=='ok' and d.get('table_count')==8 else 1)"]

# Exec form: gunicorn becomes PID 1 and receives SIGTERM directly, so
# `docker stop` triggers a graceful drain instead of a 10-second kill.
ENTRYPOINT ["gunicorn", "--config", "/app/gunicorn.conf.py"]
CMD ["App:create_app()"]
