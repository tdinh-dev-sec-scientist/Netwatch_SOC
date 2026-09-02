# NetWatch — production image.
#
# Stages:
#   builder  resolves dependencies into a self-contained virtualenv
#   test     runs the suite against a PostgreSQL the caller supplies (CI target)
#   runtime  final image: venv + application source, non-root, no build tools
#
#   docker build -t netwatch:latest .
#   docker build --target test .
#
# Pin the base by digest for a reproducible, tamper-evident build. Resolve the
# current digest yourself rather than trusting one copied from a template:
#   docker buildx imagetools inspect python:3.11-slim-bookworm
# then set PYTHON_IMAGE to python:3.11-slim-bookworm@sha256:<digest>.

ARG PYTHON_IMAGE=python:3.11-slim-bookworm

# ─────────────────────────────────────────────────────────────── builder ─────
FROM ${PYTHON_IMAGE} AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# The dependency layer is cached independently of application source, so a
# code change does not trigger a reinstall. psycopg[binary] ships its own
# libpq wheel, which is why no build toolchain or libpq-dev is needed here.
#
# For a supply-chain-hardened build, generate a hash-pinned lock file
# (`pip-compile --generate-hashes`) and add --require-hashes; pip then refuses
# any artifact whose digest does not match.
COPY requirements.txt ./
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

ENV PATH="/opt/venv/bin:${PATH}"

# ──────────────────────────────────────────────────────────────── test ───────
# CI target. Runs the suite inside the image being built, so a regression
# fails the build rather than reaching a registry. Needs a reachable
# PostgreSQL: pass NETWATCH_TEST_DATABASE_URL at build time, or run this
# target from compose where the database is a service.
FROM builder AS test

WORKDIR /app
COPY requirements-dev.txt ./
RUN /opt/venv/bin/pip install --no-cache-dir -r requirements-dev.txt
COPY . .
RUN /opt/venv/bin/ruff check .
CMD ["/opt/venv/bin/python", "-m", "pytest", "-q", "--cov"]

# ─────────────────────────────────────────────────────────────── runtime ─────
FROM ${PYTHON_IMAGE} AS runtime

ARG APP_UID=10001
ARG APP_GID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PATH="/opt/venv/bin:${PATH}"

# Patch the base OS, then drop apt state. No compilers or package managers are
# needed at runtime: the application is pure Python plus prebuilt wheels.
# Kept as its own layer so it can be rebuilt for a CVE without invalidating
# anything below it, and so the account setup below needs no network at all.
RUN set -eux; \
    apt-get update; \
    apt-get upgrade -y --no-install-recommends; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

# Run as a fixed, unprivileged uid/gid. Fixed rather than arbitrary so a
# mounted volume's ownership is predictable across hosts.
RUN set -eux; \
    groupadd --gid "${APP_GID}" --system netwatch; \
    useradd  --uid "${APP_UID}" --gid "${APP_GID}" --system \
             --home-dir /app --no-create-home --shell /usr/sbin/nologin netwatch; \
    install -d -o "${APP_UID}" -g "${APP_GID}" -m 0750 /app

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app

# Copy source explicitly rather than `COPY . .` so nothing unlisted — a stray
# .env, a local database, a credential file — can be pulled into the image
# even if .dockerignore is edited later.
COPY --chown=${APP_UID}:${APP_GID} netwatch/ ./netwatch/
COPY --chown=${APP_UID}:${APP_GID} benchmarks/ ./benchmarks/
COPY --chown=${APP_UID}:${APP_GID} alembic/ ./alembic/
COPY --chown=${APP_UID}:${APP_GID} alembic.ini gunicorn.conf.py ./

USER ${APP_UID}:${APP_GID}

EXPOSE 5001

# Verifies the application answers *and* that its schema is intact — a process
# that is listening but cannot reach its database is not healthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
    CMD ["python", "-c", "import json,sys,urllib.request;\
d=json.load(urllib.request.urlopen('http://127.0.0.1:5001/api/health',timeout=4));\
sys.exit(0 if d.get('status')=='ok' and d.get('schema_complete') else 1)"]

# Exec form: gunicorn becomes PID 1 and receives SIGTERM directly, so
# `docker stop` triggers a graceful drain instead of a kill after the timeout.
ENTRYPOINT ["gunicorn", "--config", "/app/gunicorn.conf.py"]
CMD ["netwatch.api:create_app()"]
