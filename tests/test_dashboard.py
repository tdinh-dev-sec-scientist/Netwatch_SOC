"""Dashboard integration: every module must be backed by a working endpoint."""

import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE = os.path.join(ROOT, 'templates', 'Dashboard.html')
# The dashboard's JavaScript is a static file, not an inline block, so that the
# Content Security Policy can forbid inline script. Markup assertions read the
# template; behaviour assertions read the script.
SCRIPT = os.path.join(ROOT, 'static', 'js', 'dashboard.js')

# Module id in the template -> the endpoints its loader calls.
MODULES = {
    'overview': ['/api/stats/overview', '/api/stats/throughput',
                 '/api/stats/severity', '/api/threats/summary', '/api/alerts'],
    'alerts': ['/api/alerts'],
    'threats': ['/api/threats/types', '/api/alerts/stats'],
    'mitre': ['/api/mitre/coverage', '/api/mitre/techniques'],
    'protocols': ['/api/stats/protocols', '/api/protocols'],
    'hosts': ['/api/hosts/top', '/api/geo', '/api/connections'],
    'timeline': ['/api/stats/timeline', '/api/stats/throughput'],
    'performance': ['/api/performance', '/api/health'],
    'packets': ['/api/packets'],
}


@pytest.fixture(scope='module')
def markup():
    with open(TEMPLATE, encoding='utf-8') as fh:
        return fh.read()


@pytest.fixture(scope='module')
def script():
    with open(SCRIPT, encoding='utf-8') as fh:
        return fh.read()


def test_at_least_eight_modules_exist(markup):
    sections = set(re.findall(r'<section id="view-([a-z]+)"', markup))
    assert len(sections) >= 8, 'only %d modules: %s' % (len(sections),
                                                        sorted(sections))
    assert set(MODULES) <= sections


def test_every_module_has_a_nav_entry(markup):
    nav = set(re.findall(r'class="nav-item[^"]*" data-view="([a-z]+)"', markup))
    assert set(MODULES) <= nav


def test_every_module_has_a_loader(script):
    loaders = re.search(r'const LOADERS = \{(.*?)\};', script, re.S)
    assert loaders
    for module in MODULES:
        assert re.search(r'\b%s:\s*load' % module, loaders.group(1)), \
            '%s has no loader wired' % module


@pytest.mark.parametrize('module,endpoints', sorted(MODULES.items()))
def test_module_calls_its_endpoints(script, module, endpoints):
    body = re.search(r'async function load%s\(\)(.*?)\n\}'
                     % module.capitalize(), script, re.S)
    assert body, 'no loader function found for %s' % module
    for endpoint in endpoints:
        assert endpoint in body.group(1), \
            '%s never calls %s' % (module, endpoint)


@pytest.mark.parametrize('module,endpoints', sorted(MODULES.items()))
def test_module_endpoints_respond(client, module, endpoints):
    """Each module's backing endpoints must actually serve data."""
    for endpoint in endpoints:
        response = client.get(endpoint)
        assert response.status_code == 200, \
            '%s backing %s returned %d' % (endpoint, module,
                                           response.status_code)
        payload = response.get_json()
        assert payload is not None
        assert payload != [] or endpoint in ('/api/geo',), \
            '%s backing %s returned no data' % (endpoint, module)


def test_charts_are_present_for_visual_modules(markup):
    canvases = set(re.findall(r'<canvas id="([a-z-]+)"', markup))
    assert len(canvases) >= 8
    for required in ('chart-throughput', 'chart-severity', 'chart-mitre',
                     'chart-protocols', 'chart-timeline', 'chart-perf-tp'):
        assert required in canvases


def test_no_hardcoded_sample_data(script):
    """Guards against charts being fed literal arrays instead of API data."""
    # A long numeric literal array would indicate baked-in demo data.
    suspicious = re.findall(r'\[\s*(?:\d+\s*,\s*){6,}\d+\s*\]', script)
    assert not suspicious, 'hardcoded data arrays found: %s' % suspicious[:3]
    for banned in ('Math.random', 'lorem', 'FAKE', 'dummyData', 'mockData'):
        assert banned not in script, 'dashboard.js contains %r' % banned


def test_every_chart_dataset_is_derived_from_a_response(script):
    """Chart `data:` values must map over a fetched collection."""
    # Chart.js's top-level `data: {` opens the config object; the dataset
    # `data:` entries are the ones that must be derived from a response.
    datasets = [expr.strip() for expr in re.findall(r'\bdata:\s*([^,\n]+)',
                                                    script)]
    datasets = [expr for expr in datasets if expr != '{']
    assert datasets, 'no chart datasets found'
    for expr in datasets:
        assert '.map(' in expr, \
            'chart data not derived from a response: %s' % expr


def test_error_handling_present(markup, script):
    """A failing endpoint must surface, not fail silently."""
    assert 'showError' in script
    assert 'err-banner' in markup
    assert 'res.ok' in script


def test_output_is_escaped(script):
    """API values are rendered through an escaper, not raw interpolation."""
    assert 'function esc(' in script
    assert re.search(r"replace\(/\[&<>", script)
    # Spot-check that user-controlled fields go through esc().
    for field in ('a.src_ip', 'a.threat_type', 'p.protocol'):
        assert 'esc(%s)' % field in script, '%s rendered unescaped' % field


def test_dashboard_served_by_flask(client):
    response = client.get('/')
    assert response.status_code == 200
    body = response.data.decode('utf-8')
    assert 'NETWATCH' in body
    assert 'view-overview' in body
    assert '/static/js/dashboard.js' in body
    assert '/api/stats/overview' in client.get(
        '/static/js/dashboard.js').get_data(as_text=True)
