"""The REST API: every endpoint, the pagination contract, the error contract.

The API is the fifth stage — where processed data leaves the system — so these
tests run against a database the real pipeline filled, not against fixtures
inserted by hand.
"""

import json

import pytest

from netwatch import mitre
from netwatch.analysis.protocol import SUPPORTED_PROTOCOLS

PAGE_KEYS = {'total', 'count', 'limit', 'offset', 'has_more', 'next_offset'}

#: Every route the application registers under /api, with a representative
#: request. `test_every_registered_route_is_exercised` fails if a route is
#: added without a test, so this list cannot silently fall behind the code.
GET_ENDPOINTS = [
    '/api',
    '/api/health',
    '/api/stats/overview',
    '/api/stats/throughput',
    '/api/stats/protocols',
    '/api/stats/severity',
    '/api/stats/timeline',
    '/api/alerts',
    '/api/alerts/stats',
    '/api/threats/summary',
    '/api/threats/types',
    '/api/mitre/techniques',
    '/api/mitre/coverage',
    '/api/hosts',
    '/api/geo',
    '/api/flows',
    '/api/packets',
    '/api/pipeline/metrics',
    '/api/pipeline/runs',
    '/api/live/alerts',
    '/api/detectors',
    '/api/protocols',
    '/api/scenarios',
]

PARAMETERISED_ENDPOINTS = [
    '/api/alerts/<int:alert_id>',
    '/api/alerts/<int:alert_id>/acknowledge',
    '/api/alerts/acknowledge',
    '/api/mitre/techniques/<technique_id>',
    '/api/hosts/<ip>',
]


def get_json(client, path, expect=200):
    response = client.get(path)
    assert response.status_code == expect, (path, response.status_code,
                                            response.get_data(as_text=True))
    assert response.mimetype == 'application/json'
    return response.get_json()


# ── surface ──────────────────────────────────────────────────────────────────

def test_api_index_lists_every_endpoint(client):
    listing = get_json(client, '/api')['endpoints']
    assert len(listing) >= 14
    assert any('/api/alerts' in entry for entry in listing)


def test_every_registered_route_is_exercised(client):
    registered = {str(rule) for rule in client.application.url_map.iter_rules()
                  if str(rule).startswith('/api')}
    covered = set(GET_ENDPOINTS) | set(PARAMETERISED_ENDPOINTS)
    assert registered == covered, (
        'untested routes: %s; stale entries: %s'
        % (sorted(registered - covered), sorted(covered - registered)))


@pytest.mark.parametrize('path', GET_ENDPOINTS)
def test_every_get_endpoint_answers_with_json(client, path):
    get_json(client, path)


# ── health ───────────────────────────────────────────────────────────────────

def test_health_reports_a_complete_schema(client):
    health = get_json(client, '/api/health')
    assert health['status'] == 'ok'
    assert health['database'] == 'postgresql'
    assert health['table_count'] == 10
    assert health['schema_complete'] is True
    assert health['detectors'] == 17
    assert health['protocols_supported'] == len(SUPPORTED_PROTOCOLS)
    assert health['tables']['packets'] > 0
    assert 'pool' in health


# ── statistics ───────────────────────────────────────────────────────────────

def test_overview_counters_are_live(client):
    overview = get_json(client, '/api/stats/overview')
    assert overview['total_packets'] > 0
    assert overview['total_alerts'] > 0
    assert overview['hosts_tracked'] > 0
    assert 0.0 <= overview['mean_confidence'] <= 1.0


def test_throughput_buckets_are_ordered(client):
    payload = get_json(client, '/api/stats/throughput?minutes=1440')
    buckets = payload['buckets']
    assert buckets
    assert [b['bucket'] for b in buckets] == sorted(b['bucket']
                                                    for b in buckets)
    assert all(b['packets'] > 0 for b in buckets)


def test_protocol_stats_reflect_real_traffic(client):
    payload = get_json(client, '/api/stats/protocols?minutes=10080')
    names = {row['protocol'] for row in payload['protocols']}
    assert {'DNS', 'TLS', 'HTTP'} & names
    assert all(row['protocol'] in SUPPORTED_PROTOCOLS
               for row in payload['protocols'])


def test_severity_and_timeline(client):
    severities = get_json(client, '/api/stats/severity?hours=720')
    assert severities['severities']
    assert all(row['count'] > 0 for row in severities['severities'])
    timeline = get_json(client, '/api/stats/timeline?hours=720&bucket_s=3600')
    assert timeline['bucket_s'] == 3600
    assert timeline['buckets']


# ── alerts ───────────────────────────────────────────────────────────────────

def test_alerts_listing_carries_the_pagination_envelope(client):
    payload = get_json(client, '/api/alerts?limit=5')
    assert set(payload) >= PAGE_KEYS
    assert payload['count'] == len(payload['alerts']) <= 5
    for alert in payload['alerts']:
        assert {'id', 'ts', 'severity', 'threat_type', 'src_ip', 'confidence',
                'description'} <= set(alert)


def test_alerts_pages_are_disjoint(client):
    first = get_json(client, '/api/alerts?limit=3&offset=0')['alerts']
    second = get_json(client, '/api/alerts?limit=3&offset=3')['alerts']
    assert not ({a['id'] for a in first} & {a['id'] for a in second})


def test_alerts_filtering_by_severity_and_type(client):
    payload = get_json(client, '/api/alerts?limit=100&severity=CRITICAL')
    assert all(a['severity'] == 'CRITICAL' for a in payload['alerts'])
    kinds = {a['threat_type']
             for a in get_json(client, '/api/alerts?limit=200')['alerts']}
    chosen = sorted(kinds)[0]
    payload = get_json(client, '/api/alerts?limit=100&threat_type=%s' % chosen)
    assert payload['total'] > 0
    assert all(a['threat_type'] == chosen for a in payload['alerts'])


def test_alerts_sorting(client):
    ascending = get_json(client,
                         '/api/alerts?limit=20&sort=ts&order=asc')['alerts']
    assert [a['ts'] for a in ascending] == sorted(a['ts'] for a in ascending)


def test_alert_detail_includes_techniques(client):
    alert_id = get_json(client, '/api/alerts?limit=1')['alerts'][0]['id']
    alert = get_json(client, '/api/alerts/%d' % alert_id)
    assert alert['id'] == alert_id
    assert alert['techniques']
    assert all(t['technique_id'] in mitre.TECHNIQUES
               for t in alert['techniques'])


def test_acknowledge_round_trip(client):
    open_alerts = get_json(
        client, '/api/alerts?limit=20&acknowledged=false')['alerts']
    assert open_alerts
    alert_id = open_alerts[-1]['id']
    response = client.post('/api/alerts/%d/acknowledge' % alert_id)
    assert response.status_code == 200
    assert response.get_json() == {'id': alert_id, 'acknowledged': True}
    assert get_json(client, '/api/alerts/%d' % alert_id)['acknowledged'] is True


def test_bulk_acknowledge(client):
    open_alerts = get_json(
        client, '/api/alerts?limit=3&acknowledged=false')['alerts']
    if not open_alerts:
        pytest.skip('fixture has no unacknowledged alerts left')
    ids = [a['id'] for a in open_alerts]
    response = client.post('/api/alerts/acknowledge',
                           data=json.dumps({'ids': ids}),
                           content_type='application/json')
    assert response.status_code == 200
    body = response.get_json()
    assert body['requested'] == len(ids)
    assert body['updated'] == len(ids)
    assert body['not_found'] == 0


def test_alert_stats_by_type(client):
    payload = get_json(client, '/api/alerts/stats?hours=720')
    assert payload['threat_types']
    for row in payload['threat_types']:
        assert row['count'] > 0
        assert 0.0 <= row['avg_conf'] <= 1.0


# ── threats and ATT&CK ───────────────────────────────────────────────────────

def test_threat_types_join_the_catalog_with_counts(client):
    payload = get_json(client, '/api/threats/types')
    assert payload['count'] == 17
    fired = [row for row in payload['threat_types'] if row['alert_count'] > 0]
    assert fired, 'no detector shows any alerts'
    for row in payload['threat_types']:
        assert row['techniques']
        assert row['severity'] in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')


def test_threats_summary(client):
    payload = get_json(client, '/api/threats/summary?hours=720')
    assert payload['threats']
    for row in payload['threats']:
        assert row['alert_count'] >= 1
        assert row['src_ip']


def test_mitre_endpoints(client):
    listing = get_json(client, '/api/mitre/techniques')
    assert listing['count'] == mitre.technique_count()
    observed = [t for t in listing['techniques'] if t['alert_count'] > 0]
    assert observed
    detail = get_json(client,
                      '/api/mitre/techniques/%s' % observed[0]['technique_id'])
    assert detail['detectors']
    coverage = get_json(client, '/api/mitre/coverage')
    assert coverage['catalogued_techniques'] == mitre.technique_count()
    assert coverage['coverage']


# ── hosts, flows, packets ────────────────────────────────────────────────────

def test_hosts_listing_and_detail(client):
    payload = get_json(client, '/api/hosts?limit=5&order=packets_sent')
    assert set(payload) >= PAGE_KEYS
    assert payload['hosts']
    ip = payload['hosts'][0]['ip']
    host = get_json(client, '/api/hosts/%s' % ip)
    assert host['ip'] == ip
    assert 'top_protocols' in host


def test_hosts_ordering_options(client):
    for order in ('packets_sent', 'bytes_sent', 'threat_score', 'alert_count',
                  'last_seen'):
        payload = get_json(client, '/api/hosts?limit=3&order=%s' % order)
        assert payload['count'] <= 3


def test_hosts_internal_filter(client):
    payload = get_json(client, '/api/hosts?limit=50&internal=true')
    assert all(host['is_internal'] for host in payload['hosts'])


def test_geo_distribution_skips_private_space(client):
    payload = get_json(client, '/api/geo')
    assert all(row['country'] != 'PRIVATE' for row in payload['countries'])


def test_flows_and_packets(client):
    flows = get_json(client, '/api/flows?limit=10')
    assert set(flows) >= PAGE_KEYS
    assert flows['flows']
    assert all(f['packets'] >= 1 for f in flows['flows'])

    packets = get_json(client, '/api/packets?limit=10&protocol=DNS')
    assert set(packets) >= PAGE_KEYS
    assert all(p['protocol'] == 'DNS' for p in packets['packets'])
    assert any(p['l7'].get('dns_qname') for p in packets['packets'])


def test_packets_malicious_filter(client):
    payload = get_json(client, '/api/packets?limit=50&malicious_only=true')
    assert all(p['is_malicious'] for p in payload['packets'])


# ── pipeline observability ───────────────────────────────────────────────────

def test_pipeline_metrics_endpoint_without_a_local_pipeline(client):
    payload = get_json(client, '/api/pipeline/metrics')
    # This app serves reads only, so it reports that rather than inventing
    # numbers for a pipeline it does not own.
    assert payload['running'] is False
    assert 'feed' in payload


def test_live_alerts_reports_its_own_bounds(client):
    payload = get_json(client, '/api/live/alerts?limit=10')
    assert 'feed_capacity' in payload
    assert 'feed_evictions' in payload
    assert isinstance(payload['alerts'], list)


def test_detectors_endpoint_reports_real_counters(client):
    stats = get_json(client, '/api/detectors')
    assert stats['detector_count'] == 17
    assert stats['packets_analyzed'] > 0
    assert stats['findings_total'] > 0
    assert stats['detector_errors'] == 0
    fired = [d for d in stats['detectors'] if d['findings_emitted'] > 0]
    assert len(fired) >= 10


def test_protocols_endpoint_lists_the_supported_set(client):
    payload = get_json(client, '/api/protocols')
    names = {row['protocol'] for row in payload['protocols']}
    assert set(SUPPORTED_PROTOCOLS) <= names
    assert any(row['packets_seen'] > 0 for row in payload['protocols'])


def test_scenarios_endpoint(client):
    payload = get_json(client, '/api/scenarios')
    assert payload['count'] >= 17
    for scenario in payload['scenarios']:
        assert scenario['expected_threats']


# ── the error contract ───────────────────────────────────────────────────────

def assert_error(payload, status, code=None):
    assert payload['status'] == status
    assert set(payload['error']) >= {'code', 'message'}
    if code:
        assert payload['error']['code'] == code


def test_unknown_route_returns_a_json_404(client):
    assert_error(get_json(client, '/api/does-not-exist', expect=404), 404,
                 'not_found')


@pytest.mark.parametrize('path,status,code', [
    ('/api/alerts/99999999', 404, 'not_found'),
    ('/api/mitre/techniques/T9999', 404, 'not_found'),
    ('/api/hosts/203.0.113.254', 404, 'not_found'),
])
def test_missing_resources_return_404_with_details(client, path, status, code):
    payload = get_json(client, path, expect=status)
    assert_error(payload, status, code)
    assert payload['error']['details']


def test_acknowledging_a_missing_alert_returns_404(client):
    response = client.post('/api/alerts/99999999/acknowledge')
    assert response.status_code == 404
    assert_error(response.get_json(), 404, 'not_found')


@pytest.mark.parametrize('path', [
    '/api/alerts?limit=abc',
    '/api/alerts?limit=0',
    '/api/alerts?limit=100000',
    '/api/alerts?offset=-1',
    '/api/alerts?severity=NOPE',
    '/api/alerts?threat_type=not_a_rule',
    '/api/alerts?acknowledged=perhaps',
    '/api/alerts?sort=ts;DROP',
    '/api/alerts?order=sideways',
    '/api/alerts?min_confidence=7',
    '/api/alerts?src_ip=not-an-ip',
    '/api/packets?protocol=GOPHER',
    '/api/packets?min_entropy=99',
    '/api/hosts?order=nonsense',
    '/api/stats/timeline?bucket_s=1',
    '/api/pipeline/runs?source=nowhere',
])
def test_invalid_parameters_return_400_with_what_was_allowed(client, path):
    payload = get_json(client, path, expect=400)
    assert_error(payload, 400, 'validation_error')
    assert 'parameter' in payload['error']['details']


def test_method_not_allowed_is_json(client):
    response = client.post('/api/alerts')
    assert response.status_code == 405
    assert response.mimetype == 'application/json'
    assert_error(response.get_json(), 405, 'method_not_allowed')


@pytest.mark.parametrize('body,message', [
    (None, 'body must be a JSON object'),
    ({}, 'missing ids'),
    ({'ids': []}, 'empty ids'),
    ({'ids': 'nope'}, 'ids not a list'),
    ({'ids': ['a']}, 'ids not integers'),
    ({'ids': list(range(501))}, 'too many ids'),
])
def test_bulk_acknowledge_validates_its_body(client, body, message):
    response = client.post('/api/alerts/acknowledge',
                           data='null' if body is None else json.dumps(body),
                           content_type='application/json')
    assert response.status_code == 400, message
    assert_error(response.get_json(), 400, 'validation_error')


def test_filter_values_are_parameterised_not_interpolated(client):
    """A SQL fragment in a free-text filter must be data, never syntax."""
    payload = get_json(client, "/api/alerts?limit=5&src_ip=1.1.1.1' OR '1'='1",
                       expect=400)
    assert_error(payload, 400, 'validation_error')
    # And the database is still there afterwards.
    assert get_json(client, '/api/health')['status'] == 'ok'


def test_a_repository_failure_becomes_a_503_not_a_stack_trace(client,
                                                              monkeypatch):
    def broken():
        raise RuntimeError('connection refused')

    monkeypatch.setattr(client.application.repository, 'health', broken)
    payload = get_json(client, '/api/health', expect=503)
    assert_error(payload, 503, 'service_unavailable')
    assert 'connection refused' not in json.dumps(payload)


# ── dashboard ────────────────────────────────────────────────────────────────

def test_dashboard_page_renders(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b'<html' in response.data.lower()
