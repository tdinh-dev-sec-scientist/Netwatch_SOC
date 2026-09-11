"""Security headers, read-only demo mode, rate limiting and vendored assets."""

import hashlib
import os
import re

import pytest

import hardening
from App import create_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHART_JS = os.path.join(ROOT, 'static', 'vendor', 'chart-4.4.0.umd.js')
CHART_JS_SHA256 = \
    '321e3a3fa98da4aaa957d10be57cbb514de0989eed8f9d726b5d05902cd01904'


def make_client(populated_db, **settings):
    app = create_app(db=populated_db, engine=populated_db.engine_for_tests,
                     start_simulation=False,
                     security=hardening.Settings(**settings))
    app.config['TESTING'] = True
    return app.test_client()


def unacknowledged_alert_id(db):
    for alert in db.get_alerts(limit=500)['alerts']:
        if not alert['acknowledged']:
            return alert['id']
    pytest.fail('no unacknowledged alert available')


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


# ── headers ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize('path', ['/', '/api/health', '/api/does-not-exist'])
def test_security_headers_on_every_response(client, path):
    response = client.get(path)
    for name, value in hardening.SECURITY_HEADERS.items():
        assert response.headers.get(name) == value, name


def test_csp_restricts_scripts_connections_and_framing():
    csp = hardening.CONTENT_SECURITY_POLICY
    assert "script-src 'self' 'unsafe-inline'" in csp
    assert "connect-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp


def test_dashboard_loads_no_third_party_scripts(client):
    html = client.get('/').get_data(as_text=True)
    sources = re.findall(r'<script[^>]*\bsrc="([^"]+)"', html)
    assert sources, 'expected the vendored Chart.js script tag'
    assert all(src.startswith('/static/') for src in sources), sources


def test_vendored_chart_js_is_served_and_unmodified(client):
    with open(CHART_JS, 'rb') as fh:
        assert hashlib.sha256(fh.read()).hexdigest() == CHART_JS_SHA256
    response = client.get('/static/vendor/chart-4.4.0.umd.js')
    assert response.status_code == 200
    assert b'Chart.js v4.4.0' in response.data[:200]
    response.close()


# ── demo mode ───────────────────────────────────────────────────────────────

def test_demo_mode_blocks_writes_and_changes_nothing(populated_db):
    client = make_client(populated_db, demo=True)
    target = unacknowledged_alert_id(populated_db)
    response = client.post('/api/alerts/%d/acknowledge' % target)
    assert response.status_code == 403
    assert 'read-only' in response.get_json()['error']
    assert populated_db.get_alert(target)['acknowledged'] == 0


@pytest.mark.parametrize('method', ['put', 'patch', 'delete'])
def test_demo_mode_blocks_every_unsafe_method(populated_db, method):
    client = make_client(populated_db, demo=True)
    assert getattr(client, method)('/api/alerts').status_code == 403


def test_demo_mode_still_serves_reads(populated_db):
    client = make_client(populated_db, demo=True)
    assert client.get('/').status_code == 200
    body = client.get('/api/health').get_json()
    assert body['status'] == 'ok' and body['demo'] is True
    assert client.get('/api/alerts?limit=5').status_code == 200


def test_health_reports_demo_off_by_default(client):
    assert client.get('/api/health').get_json()['demo'] is False


# ── rate limiter ────────────────────────────────────────────────────────────

def test_limiter_allows_up_to_the_limit_then_refuses():
    limiter = hardening.RateLimiter(3, 60, clock=FakeClock())
    assert [limiter.hit('a')[0] for _ in range(4)] == [True, True, True, False]


def test_limiter_resets_after_the_window():
    clock = FakeClock()
    limiter = hardening.RateLimiter(1, 60, clock=clock)
    assert limiter.hit('a')[0]
    allowed, reset = limiter.hit('a')
    assert not allowed and reset == pytest.approx(60)
    clock.now += 60
    assert limiter.hit('a')[0]


def test_limiter_keys_are_independent():
    limiter = hardening.RateLimiter(1, 60, clock=FakeClock())
    assert limiter.hit('a')[0] and limiter.hit('b')[0]
    assert not limiter.hit('a')[0]


def test_limiter_memory_is_bounded():
    clock = FakeClock()
    limiter = hardening.RateLimiter(5, 60, max_keys=100, clock=clock)
    for i in range(1000):
        limiter.hit('client-%d' % i)
    assert len(limiter) <= 100
    clock.now += 61
    limiter.hit('late')
    assert len(limiter) <= 100


def test_app_returns_429_with_retry_after(populated_db):
    client = make_client(populated_db, client_limit=(2, 60))
    assert client.get('/api/health').status_code == 200
    assert client.get('/api/health').status_code == 200
    response = client.get('/api/health')
    assert response.status_code == 429
    assert int(response.headers['Retry-After']) >= 1
    assert response.get_json()['status'] == 429
    assert response.headers['X-Content-Type-Options'] == 'nosniff'


def test_global_limit_applies_across_clients(populated_db):
    client = make_client(populated_db, global_limit=(2, 60), proxy_hops=1)
    codes = [client.get('/api/health',
                        headers={'X-Forwarded-For': '203.0.113.%d' % i}
                        ).status_code for i in range(3)]
    assert codes == [200, 200, 429]


def test_forwarded_for_is_ignored_without_trusted_proxies(populated_db):
    """A client cannot mint fresh buckets by inventing X-Forwarded-For values."""
    client = make_client(populated_db, client_limit=(2, 60), proxy_hops=0)
    codes = [client.get('/api/health',
                        headers={'X-Forwarded-For': '198.51.100.%d' % i}
                        ).status_code for i in range(3)]
    assert codes == [200, 200, 429]


def test_trusted_proxy_hop_separates_real_clients(populated_db):
    client = make_client(populated_db, client_limit=(1, 60), proxy_hops=1)
    first = client.get('/api/health', headers={'X-Forwarded-For': '203.0.113.1'})
    second = client.get('/api/health', headers={'X-Forwarded-For': '203.0.113.2'})
    repeat = client.get('/api/health', headers={'X-Forwarded-For': '203.0.113.1'})
    assert (first.status_code, second.status_code, repeat.status_code) == \
        (200, 200, 429)


# ── settings ────────────────────────────────────────────────────────────────

def test_limits_are_off_outside_demo_mode():
    settings = hardening.Settings.from_env({})
    assert settings == hardening.Settings()


def test_demo_mode_turns_on_default_limits():
    settings = hardening.Settings.from_env({'NETWATCH_DEMO': '1'})
    assert settings.demo
    assert settings.client_limit == (600, 60.0)
    assert settings.global_limit == (6000, 60.0)


def test_limits_can_be_tuned_or_disabled():
    settings = hardening.Settings.from_env({
        'NETWATCH_DEMO': 'true', 'NETWATCH_RATE_LIMIT': '100/10',
        'NETWATCH_GLOBAL_RATE_LIMIT': '0', 'NETWATCH_PROXY_HOPS': '1'})
    assert settings.client_limit == (100, 10.0)
    assert settings.global_limit is None
    assert settings.proxy_hops == 1


@pytest.mark.parametrize('env', [
    {'NETWATCH_RATE_LIMIT': 'lots'},
    {'NETWATCH_RATE_LIMIT': '-1/60'},
    {'NETWATCH_GLOBAL_RATE_LIMIT': '10/0'},
    {'NETWATCH_PROXY_HOPS': 'one'},
    {'NETWATCH_PROXY_HOPS': '-1'},
])
def test_invalid_settings_are_rejected(env):
    with pytest.raises(ValueError):
        hardening.Settings.from_env(env)
