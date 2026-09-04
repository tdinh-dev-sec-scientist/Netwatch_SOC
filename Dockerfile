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
#   docker build --target test .            # run the full suite in the build
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
FROM builder AS test

WORKDIR /app
COPY . .
RUN /opt/venv/bin/python -m pytest -q

# ─────────────────────────────────────────────────────────────── runtime ─────
FROM ${PYTHON_IMAGE} AS runtime

ARG APP_UID=10001
ARG APP_GID=10001

# NETWATCH_DB is the SQLite fallback. Set NETWATCH_DB_URL to a postgresql://
# URL — as docker-compose.yml does — and it takes precedence.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PATH="/opt/venv/bin:${PATH}" \
    NETWATCH_DB=/data/netwatch.db

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
COPY --chown=${APP_UID}:${APP_GID} App.py DB_Manager.py PacketSimulator.py \
     ProtocolAnalyzer.py ThreatDetector.py benchmark.py config.py \
     db_dialects.py engine.py frames.py geoip.py mitre.py pcap_io.py \
     gunicorn.conf.py ./
COPY --chown=${APP_UID}:${APP_GID} detectors/ ./detectors/
COPY --chown=${APP_UID}:${APP_GID} tools/ ./tools/
COPY --chown=${APP_UID}:${APP_GID} templates/ ./templates/

USER ${APP_UID}:${APP_GID}

# Only used by the SQLite profile: the database, its WAL and its shared-memory
# file live here and need a writable mount. With PostgreSQL nothing in the
# image is written at all, so the root filesystem stays read-only.
VOLUME ["/data"]

EXPOSE 5001

# Verifies the application answers *and* that its schema is intact — a process
# that is listening but has lost its database is not healthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import json,sys,urllib.request;\
d=json.load(urllib.request.urlopen('http://127.0.0.1:5001/api/health',timeout=4));\
sys.exit(0 if d.get('status')=='ok' and d.get('table_count')==9 else 1)"]

# Exec form: gunicorn becomes PID 1 and receives SIGTERM directly, so
# `docker stop` triggers a graceful drain instead of a 10-second kill.
ENTRYPOINT ["gunicorn", "--config", "/app/gunicorn.conf.py"]
CMD ["App:create_app()"]
