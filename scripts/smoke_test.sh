#!/usr/bin/env bash
# End-to-end smoke tests against a built image. Used by CI; runnable locally.
#
#   docker build --target runtime -t netwatch-soc:latest .
#   scripts/smoke_test.sh demo         # the Render Blueprint's settings
#   scripts/smoke_test.sh all-in-one   # docker compose --profile all-in-one
#   scripts/smoke_test.sh split        # docker compose --profile split
#
# Unit tests exercise the code; these exercise the deployment: the image, the
# compose topologies and the demo configuration, which is where the engine.py,
# port and gunicorn bugs lived while every unit test passed.
#
# The demo check needs a PostgreSQL server for the container to talk to, and
# starts a throwaway one itself. The compose checks use the compose file's own
# postgres service.

set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="${IMAGE:-netwatch-soc:latest}"
# COMPOSE_EXTRA adds compose arguments, e.g. "-f override.yml" to lower CPU
# limits on a one-CPU machine.
read -r -a COMPOSE_EXTRA_ARGS <<<"${COMPOSE_EXTRA:-}"
COMPOSE=(docker compose -f docker-compose.yml "${COMPOSE_EXTRA_ARGS[@]}")

fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }
pass() { echo "  ok  $*"; }

wait_for_health() {             # url, timeout seconds
  local url=$1 deadline=$(( $(date +%s) + $2 ))
  until curl -sf -m 3 "$url/api/health" >/dev/null; do
    [ "$(date +%s)" -lt "$deadline" ] || fail "$url did not become healthy"
    sleep 2
  done
}

json() {                        # url, python expression over `d`
  curl -sf -m 10 "$1" | python3 -c "import json,sys; d=json.load(sys.stdin); print($2)"
}

packet_count() { json "$1/api/health" "d['tables']['packets']"; }

assert_packets_advance() {      # url
  local before after
  before=$(packet_count "$1"); sleep 6; after=$(packet_count "$1")
  [ "$after" -gt "$before" ] || fail "$1 packet count did not advance ($before -> $after)"
  pass "packets advancing at $1 ($before -> $after)"
}

engines_running() {             # containers whose environment turns the engine on
  local count=0 id
  for id in $(docker ps -q); do
    if docker exec "$id" printenv NETWATCH_SIMULATE 2>/dev/null | grep -qx 1; then
      count=$((count + 1))
    fi
  done
  echo "$count"
}

# ── demo: the exact environment render.yaml sets ──────────────────────────────
# Render supplies DATABASE_URL from the managed database in the Blueprint, which
# has no `value:` in the file to read, so this starts a throwaway PostgreSQL on
# a private network and points the container at that instead. Everything else
# comes verbatim from render.yaml.
PG_IMAGE="${PG_IMAGE:-postgres:16.13-alpine}"

smoke_demo() {
  local port=10000 url="http://127.0.0.1:10000" name=netwatch-smoke-demo
  local pg=netwatch-smoke-pg net=netwatch-smoke-net
  local pg_password=smoke-only-not-a-secret
  local env_args=()
  while IFS= read -r pair; do env_args+=(-e "$pair"); done < <(python3 - <<'PY'
import re
text = open('render.yaml', encoding='utf-8').read()
for key, value in re.findall(r'key:\s*(\w+)\s*\n\s*value:\s*"([^"]*)"', text):
    print('%s=%s' % (key, value))
PY
)
  [ "${#env_args[@]}" -gt 0 ] || fail "no environment variables parsed from render.yaml"

  docker rm -f "$name" "$pg" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  trap 'docker logs --tail 40 '"$name"' 2>&1 || true; docker rm -f '"$name $pg"' >/dev/null 2>&1 || true; docker network rm '"$net"' >/dev/null 2>&1 || true' EXIT

  docker network create "$net" >/dev/null
  docker run -d --name "$pg" --network "$net" \
    -e POSTGRES_DB=netwatch -e POSTGRES_USER=netwatch \
    -e "POSTGRES_PASSWORD=$pg_password" "$PG_IMAGE" >/dev/null
  local pg_deadline=$(( $(date +%s) + 90 ))
  until docker exec "$pg" pg_isready -U netwatch -d netwatch >/dev/null 2>&1; do
    [ "$(date +%s)" -lt "$pg_deadline" ] || fail "throwaway postgres never became ready"
    sleep 2
  done
  pass "throwaway postgres ready"

  # PORT is what Render injects; the image must listen on it.
  docker run -d --name "$name" --network "$net" \
    -p "127.0.0.1:$port:$port" -e PORT=$port \
    -e "DATABASE_URL=postgresql://netwatch:$pg_password@$pg:5432/netwatch" \
    "${env_args[@]}" "$IMAGE" >/dev/null

  wait_for_health "$url" 90
  pass "healthy on platform-assigned PORT=$port"

  [ "$(json "$url/api/health" "d['demo']")" = "True" ] || fail "demo mode is not on"
  pass "demo mode on"

  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$url/api/alerts/1/acknowledge")
  [ "$code" = 403 ] || fail "POST returned $code, expected 403"
  pass "writes refused (403)"

  local headers
  headers=$(curl -sI "$url/")
  for header in content-security-policy x-frame-options x-content-type-options; do
    grep -qi "^$header:" <<<"$headers" || fail "missing $header header"
  done
  pass "security headers present"

  code=$(curl -s -o /dev/null -w '%{http_code}' "$url/static/vendor/chart-4.4.0.umd.js")
  [ "$code" = 200 ] || fail "vendored Chart.js returned $code"
  pass "vendored Chart.js served"

  # The backfill runs on the engine thread after the server is up.
  local firing=0 deadline=$(( $(date +%s) + 120 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    firing=$(json "$url/api/threats/types" "sum(1 for t in d if t['alert_count'])")
    [ "$firing" -ge 17 ] && break
    sleep 3
  done
  [ "$firing" -ge 17 ] || fail "only $firing of 17 threat types fired after backfill"
  pass "backfill: all $firing threat types have alerts"

  [ "$(json "$url/api/health" "d['backend']")" = "postgresql" ] \
    || fail "the image is not running against PostgreSQL"
  pass "backend is postgresql"

  # Migrations ran on startup and built the whole schema.
  [ "$(json "$url/api/health" "d['table_count']")" = 8 ] \
    || fail "schema incomplete: migrations did not run"
  pass "migrations applied on startup (8 tables)"

  assert_packets_advance "$url"
  docker rm -f "$name" "$pg" >/dev/null
  docker network rm "$net" >/dev/null
  trap - EXIT
}

# ── compose topologies ────────────────────────────────────────────────────────
compose_down() { "${COMPOSE[@]}" --profile "$1" down -v --remove-orphans >/dev/null 2>&1 || true; }

compose_up() {                  # profile
  compose_down "$1"
  trap '"${COMPOSE[@]}" --profile '"$1"' logs --tail 40 2>&1 || true; compose_down '"$1" EXIT
  "${COMPOSE[@]}" --profile "$1" up -d --no-build
}

smoke_all_in_one() {
  [ "$("${COMPOSE[@]}" --profile all-in-one config --services | sort | xargs)" \
    = "netwatch postgres" ] \
    || fail "all-in-one profile should contain the netwatch and postgres services"
  compose_up all-in-one
  wait_for_health http://127.0.0.1:5001 90
  pass "all-in-one healthy (read-only rootfs, capabilities dropped)"
  [ "$(json http://127.0.0.1:5001/api/health "d['simulation_running']")" = "True" ] \
    || fail "engine not running in the all-in-one process"
  assert_packets_advance http://127.0.0.1:5001
  [ "$(engines_running)" = 1 ] || fail "expected exactly one engine"
  pass "exactly one engine"
  compose_down all-in-one
  trap - EXIT
}

smoke_split() {
  [ "$("${COMPOSE[@]}" --profile split config --services | sort | xargs)" \
    = "engine postgres web" ] \
    || fail "split profile should contain engine, web and postgres"
  compose_up split
  for port in 5001 5002; do
    wait_for_health "http://127.0.0.1:$port" 120
    [ "$(json "http://127.0.0.1:$port/api/health" "d['simulation_running']")" = "False" ] \
      || fail "API replica on $port is running its own engine"
    pass "API replica healthy on $port with no engine"
  done
  assert_packets_advance http://127.0.0.1:5001
  [ "$(engines_running)" = 1 ] || fail "expected exactly one engine, found $(engines_running)"
  pass "exactly one engine"
  compose_down split
  trap - EXIT
}

case "${1:-}" in
  demo) echo "smoke: demo"; smoke_demo ;;
  all-in-one) echo "smoke: all-in-one"; smoke_all_in_one ;;
  split) echo "smoke: split"; smoke_split ;;
  *) echo "usage: $0 demo|all-in-one|split" >&2; exit 2 ;;
esac
echo "smoke: $1 passed"
