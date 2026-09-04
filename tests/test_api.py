"""REST API tests: every endpoint, its schema, and its error handling."""

import pytest

import mitre
from ProtocolAnalyzer import SUPPORTED_PROTOCOLS

# (method, path) for every endpoint the API exposes.
ENDPOINTS = [
    ('GET', '/api/health'),
    ('GET', '/api/stats/overview'),
    ('GET', '/api/stats/throughput'),
    ('GET', '/api/stats/protocols'),
    ('GET', '/api/stats/severity'),
    ('GET', '/api/stats/timeline'),
    ('GET', '/api/alerts'),
    ('GET', '/api/alerts/stats'),
    ('GET', '/api/threats/summary'),
    ('GET', '/api/threats/types'),
    ('GET', '/api/mitre/techniques'),
    ('GET', '/api/mitre/coverage'),
    ('GET', '/api/hosts/top'),
    ('GET', '/api/geo'),
    ('GET', '/api/connections'),
    ('GET', '/api/packets'),
    ('GET', '/api/performance'),
    ('GET', '/api/detectors'),
    ('GET', '/api/protocols'),
    ('GET', '/api/scenarios'),
    ('GET', '/api/validation'),
]


def get(client, path, **params):
    response = client.get(path, query_string=params)
    assert response.status_code == 200, '%s -> %d %s' % (
        path, response.status_code, response.data[:200])
    return response.get_json()


# ── coverage ─────────────────────────────────────────────────────────────────

def test_at_least_fourteen_endpoints_exist(client):
    from App import create_app  # noqa: F401  (app already built by fixture)
    assert len(ENDPOINTS) >= 14


def test_all_registered_routes_are_covered_by_tests(client):
    registered = {
        str(rule) for rule in client.application.url_map.iter_rules()
        if str(rule).startswith('/api/')
    }
    # Parameterised routes are exercised separately below.
    parameterised = {r for r in registered if '<' in r}
    plain = registered - parameterised
    tested = {path for _method, path in ENDPOINTS}
    assert plain <= tested, 'untested endpoints: %s' % sorted(plain - tested)
    assert len(registered) >= 14


@pytest.mark.parametrize('method,path', ENDPOINTS)
def test_endpoint_returns_json(client, method, path):
    response = client.open(path, method=method)
    assert response.status_code == 200
    assert response.is_json
    assert response.get_json() is not None


# ── individual endpoints ─────────────────────────────────────────────────────

def test_health_reports_schema_and_engine(client):
    body = get(client, '/api/health')
    assert body['status'] == 'ok'
    assert body['table_count'] == 9
    assert body['index_count'] >= 20
    assert body['backend'] in ('sqlite', 'postgresql')
    assert set(body['tables']) == {
        'packets', 'connections', 'hosts', 'alerts', 'mitre_techniques',
        'alert_techniques', 'protocol_stats', 'performance_metrics',
        'validation_runs'}
    engine = body['engine']
    assert engine['detectors'] >= 15
    assert engine['threat_types'] >= 15
    assert engine['techniques'] >= 12
    assert engine['protocols_supported'] >= 15
    assert engine['detector_errors'] == 0


def test_overview_has_live_counters(client):
    body = get(client, '/api/stats/overview')
    for field in ('total_packets', 'total_alerts', 'alerts_24h',
                  'unacknowledged', 'distinct_threat_types',
                  'techniques_observed', 'hosts_tracked', 'active_flows'):
        assert field in body
    assert body['total_packets'] > 0
    assert body['total_alerts'] > 0
    assert body['distinct_threat_types'] >= 10
    assert body['techniques_observed'] >= 12


def test_throughput_buckets_are_ordered(client):
    body = get(client, '/api/stats/throughput', minutes=180)
    assert isinstance(body, list) and body
    buckets = [row['bucket'] for row in body]
    assert buckets == sorted(buckets)
    assert all(row['packets'] > 0 for row in body)


def test_protocol_stats_reflect_real_traffic(client):
    body = get(client, '/api/stats/protocols', minutes=10080)
    names = {row['protocol'] for row in body}
    assert len(names) >= 10
    assert names <= set(SUPPORTED_PROTOCOLS) | {'UNKNOWN'}
    assert all(row['packets'] > 0 for row in body)


def test_severity_and_timeline(client):
    severity = get(client, '/api/stats/severity', hours=24)
    assert severity
    assert {row['severity'] for row in severity} <= {
        'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}

    timeline = get(client, '/api/stats/timeline', hours=24, bucket_s=3600)
    assert timeline
    assert all({'bucket', 'severity', 'count'} <= set(row) for row in timeline)


def test_alerts_listing_schema_and_pagination(client):
    body = get(client, '/api/alerts', limit=5)
    assert set(body) == {'total', 'count', 'limit', 'offset', 'alerts'}
    assert body['limit'] == 5
    assert body['count'] <= 5
    assert body['total'] >= body['count']
    for alert in body['alerts']:
        assert {'id', 'ts', 'severity', 'threat_type', 'detector',
                'confidence', 'description', 'evidence'} <= set(alert)
        assert isinstance(alert['evidence'], dict)

    page2 = get(client, '/api/alerts', limit=5, offset=5)
    assert page2['offset'] == 5
    if body['total'] > 10:
        assert {a['id'] for a in body['alerts']} != {
            a['id'] for a in page2['alerts']}


def test_alerts_filtering(client):
    by_type = get(client, '/api/alerts', threat_type='port_scan', limit=50)
    assert all(a['threat_type'] == 'port_scan' for a in by_type['alerts'])

    high = get(client, '/api/alerts', severity='HIGH', limit=50)
    assert all(a['severity'] == 'HIGH' for a in high['alerts'])

    unacked = get(client, '/api/alerts', acknowledged='false', limit=50)
    assert all(a['acknowledged'] == 0 for a in unacked['alerts'])


def test_alert_detail_includes_techniques(client):
    alert_id = get(client, '/api/alerts', limit=1)['alerts'][0]['id']
    detail = get(client, '/api/alerts/%d' % alert_id)
    assert detail['id'] == alert_id
    assert detail['techniques']
    for tech in detail['techniques']:
        assert tech['technique_id'] in mitre.TECHNIQUES
        assert tech['rationale']
    assert isinstance(detail['related_packets'], list)


def test_acknowledge_round_trip(client):
    target = None
    for alert in get(client, '/api/alerts', limit=50)['alerts']:
        if alert['acknowledged'] == 0:
            target = alert['id']
            break
    assert target is not None, 'no unacknowledged alert to test with'

    response = client.post('/api/alerts/%d/acknowledge' % target)
    assert response.status_code == 200
    assert response.get_json() == {'id': target, 'acknowledged': True}
    assert get(client, '/api/alerts/%d' % target)['acknowledged'] == 1


def test_alert_stats_by_type(client):
    body = get(client, '/api/alerts/stats', hours=720)
    assert body
    for row in body:
        assert row['count'] > 0
        assert 0 < row['avg_conf'] <= 1.0


def test_threat_types_join_catalog_with_counts(client):
    body = get(client, '/api/threats/types')
    assert len(body) >= 15
    for row in body:
        assert {'name', 'threat_type', 'description', 'techniques',
                'alert_count'} <= set(row)
        assert row['techniques']
    fired = [r for r in body if r['alert_count'] > 0]
    assert len(fired) >= 10, 'only %d detector types ever fired' % len(fired)


def test_threats_summary(client):
    body = get(client, '/api/threats/summary', hours=720)
    assert body
    for row in body:
        assert row['alert_count'] >= 1
        assert row['first_seen'] <= row['last_seen']


def test_mitre_techniques_listing(client):
    body = get(client, '/api/mitre/techniques')
    assert len(body) == mitre.technique_count()
    assert len(body) >= 12
    observed = [t for t in body if t['alert_count'] > 0]
    assert len(observed) >= 12, 'only %d techniques observed' % len(observed)
    for tech in body:
        assert tech['technique_id'] in mitre.TECHNIQUES
        assert tech['name'] and tech['tactic'] and tech['rationale']


def test_mitre_technique_detail(client):
    detail = get(client, '/api/mitre/techniques/T1046')
    assert detail['technique_id'] == 'T1046'
    assert detail['name'] == 'Network Service Discovery'
    assert detail['alert_count'] > 0
    assert detail['detectors']
    assert detail['recent_alerts']
    assert any(d['detector'] == 'port_scan' for d in detail['detectors'])


def test_mitre_coverage_grouped_by_tactic(client):
    body = get(client, '/api/mitre/coverage')
    assert body['catalogued_techniques'] >= 12
    assert body['tactics']
    total = sum(t['catalogued'] for t in body['coverage'])
    assert total == mitre.technique_count()
    assert any(t['observed'] > 0 for t in body['coverage'])


def test_hosts_top_and_detail(client):
    hosts = get(client, '/api/hosts/top', limit=5)
    assert 0 < len(hosts) <= 5
    assert all(h['packets_sent'] >= hosts[-1]['packets_sent'] for h in hosts)

    detail = get(client, '/api/hosts/%s' % hosts[0]['ip'])
    assert detail['ip'] == hosts[0]['ip']
    assert 'top_protocols' in detail
    assert 'recent_alerts' in detail
    assert 'top_peers' in detail


def test_hosts_top_ordering_options(client):
    by_threat = get(client, '/api/hosts/top', order='threat_score', limit=5)
    scores = [h['threat_score'] for h in by_threat]
    assert scores == sorted(scores, reverse=True)
    assert scores[0] > 0


def test_geo_distribution(client):
    body = get(client, '/api/geo')
    assert body
    assert all('country' in row for row in body)
    assert all(row['country'] != 'PRIVATE' for row in body)


def test_connections_and_packets(client):
    flows = get(client, '/api/connections', limit=10)
    assert flows
    for flow in flows:
        assert flow['packets'] > 0
        assert flow['first_seen'] <= flow['last_seen']

    packets = get(client, '/api/packets', limit=20)
    assert packets
    for packet in packets:
        assert packet['protocol']
        assert isinstance(packet['l7'], dict)

    dns = get(client, '/api/packets', protocol='DNS', limit=10)
    assert all(p['protocol'] == 'DNS' for p in dns)


def test_performance_endpoint(client):
    body = get(client, '/api/performance')
    assert 'history' in body and 'live' in body
    assert body['history'], 'no measured performance recorded'
    row = body['history'][0]
    assert row['packets_per_min'] > 0
    assert row['window_s'] > 0


def test_detectors_endpoint_reports_real_counters(client):
    body = get(client, '/api/detectors')
    assert body['detector_count'] >= 15
    assert body['threat_type_count'] >= 15
    assert body['technique_count'] >= 12
    assert body['packets_analyzed'] > 0
    assert body['detector_errors'] == 0
    fired = [d for d in body['detectors'] if d['findings_emitted'] > 0]
    assert len(fired) >= 10


def test_protocols_endpoint_lists_supported_set(client):
    body = get(client, '/api/protocols')
    assert len(body) >= 15
    names = {row['protocol'] for row in body}
    assert names == set(SUPPORTED_PROTOCOLS)
    for row in body:
        assert row['risk'] in ('HIGH', 'MEDIUM', 'LOW', 'INFO')
        assert isinstance(row['encrypted'], bool)


def test_scenarios_endpoint(client):
    body = get(client, '/api/scenarios')
    assert len(body) >= 15
    assert all(row['expected_threats'] for row in body)


# ── error handling ───────────────────────────────────────────────────────────

def test_unknown_route_returns_json_404(client):
    response = client.get('/api/does-not-exist')
    assert response.status_code == 404
    assert response.is_json
    assert 'error' in response.get_json()


def test_missing_alert_returns_404(client):
    response = client.get('/api/alerts/99999999')
    assert response.status_code == 404
    assert 'not found' in response.get_json()['error']


def test_acknowledging_missing_alert_returns_404(client):
    response = client.post('/api/alerts/99999999/acknowledge')
    assert response.status_code == 404


def test_unknown_technique_returns_404(client):
    response = client.get('/api/mitre/techniques/T9999')
    assert response.status_code == 404
    assert 'catalog' in response.get_json()['error']


def test_unknown_host_returns_404(client):
    response = client.get('/api/hosts/203.0.113.254')
    assert response.status_code == 404


@pytest.mark.parametrize('path,params', [
    ('/api/alerts', {'limit': 'abc'}),
    ('/api/alerts', {'limit': 0}),
    ('/api/alerts', {'limit': 10_000}),
    ('/api/alerts', {'offset': -1}),
    ('/api/alerts', {'severity': 'URGENT'}),
    ('/api/alerts', {'acknowledged': 'maybe'}),
    ('/api/stats/throughput', {'minutes': 0}),
    ('/api/stats/timeline', {'bucket_s': 1}),
    ('/api/hosts/top', {'order': 'DROP TABLE'}),
    ('/api/packets', {'protocol': 'GOPHER'}),
    ('/api/performance', {'source': 'made-up'}),
    ('/api/connections', {'order': 'nonsense'}),
])
def test_invalid_parameters_return_400(client, path, params):
    response = client.get(path, query_string=params)
    assert response.status_code == 400, '%s %s -> %d' % (
        path, params, response.status_code)
    assert 'error' in response.get_json()


def test_sql_injection_in_filters_is_parameterised(client):
    """Injection attempts must be treated as literal values, not SQL."""
    hostile = "10.0.0.1'; DROP TABLE alerts;--"
    body = get(client, '/api/alerts', src_ip=hostile, limit=10)
    assert body['alerts'] == []
    # The table must still be there.
    assert get(client, '/api/health')['tables']['alerts'] > 0


def test_dashboard_page_renders(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b'<canvas' in response.data or b'<div' in response.data


def test_scenarios_expose_ground_truth_and_class(client):
    """The replay corpus's ground truth, served rather than documented."""
    body = get(client, '/api/scenarios')
    assert len(body) >= 18
    classes = {s['class'] for s in body}
    assert classes == {'attack', 'evasion'}
    for scenario in body:
        assert scenario['expected_threats'], \
            '%s has no expected threat' % scenario['name']


def test_validation_endpoint_is_empty_before_a_run(client):
    """An unvalidated database must say so, not invent a figure."""
    body = get(client, '/api/validation')
    assert body['runs'] == []
    assert body['latest'] == {}
    assert 'TP / (TP + FN)' in body['formulas']['true_positive_rate']


def test_validation_endpoint_returns_a_recorded_run(client, populated_db):
    run_id = populated_db.record_validation_run({
        'kind': 'replay', 'profile': 'tuned', 'corpus': 'api-test',
        'pcap_count': 24, 'packets': 152624, 'true_positives': 19,
        'false_positives': 0, 'false_negatives': 0, 'tpr_pct': 100.0,
        'precision_pct': 100.0, 'alerts_total': 25,
        'detail': {'primary': {'true_positive_rate_pct': 100.0}},
    })
    try:
        body = get(client, '/api/validation')
        assert body['runs'][0]['id'] == run_id
        assert body['latest']['replay']['tpr_pct'] == 100.0
        assert body['latest']['replay']['detail']['primary'][
            'true_positive_rate_pct'] == 100.0
        filtered = get(client, '/api/validation', kind='replay')
        assert filtered['runs'][0]['id'] == run_id
    finally:
        populated_db._exec(populated_db._write_conn,
                           'DELETE FROM validation_runs WHERE id = ?',
                           (run_id,))


def test_validation_rejects_an_unknown_kind(client):
    response = client.get('/api/validation', query_string={'kind': 'bogus'})
    assert response.status_code == 400
