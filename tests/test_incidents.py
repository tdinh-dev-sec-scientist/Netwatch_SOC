"""Incident correlation: grouping rules, and the /api/incidents endpoint."""

import incidents


def alert(ts, kind, src, dst, severity='HIGH', **extra):
    return dict(ts=ts, threat_type=kind, src_ip=src, dst_ip=dst,
                severity=severity, **extra)


def test_repeats_of_one_attack_are_one_incident():
    """97 re-alerts a minute apart, as the FTP storm produced on real traffic."""
    found = incidents.correlate(
        [alert(60.0 * i, 'syn_flood', '18.221.219.4', '172.31.69.25')
         for i in range(97)])
    assert len(found) == 1
    assert found[0]['alert_count'] == 97
    assert found[0]['duration_s'] == 96 * 60.0


def test_detectors_on_one_host_pair_join_one_incident_in_either_direction():
    found = incidents.correlate([
        alert(0, 'brute_force', '13.58.98.64', '172.31.69.25'),
        alert(30, 'data_exfil', '172.31.69.25', '13.58.98.64', 'CRITICAL'),
        alert(90, 'protocol_tunnel', '13.58.98.64', '172.31.69.25', 'MEDIUM'),
    ])
    assert len(found) == 1
    assert found[0]['severity'] == 'CRITICAL'
    assert found[0]['threat_types'] == {'brute_force': 1, 'data_exfil': 1,
                                        'protocol_tunnel': 1}


def test_a_quiet_gap_starts_a_new_incident():
    found = incidents.correlate([
        alert(0, 'port_scan', '10.0.0.5', '10.0.0.9'),
        alert(3600, 'port_scan', '10.0.0.5', '10.0.0.9'),
    ], gap_s=1800)
    assert len(found) == 2


def test_different_host_pairs_stay_apart():
    found = incidents.correlate([
        alert(0, 'port_scan', '10.0.0.5', '10.0.0.9'),
        alert(1, 'port_scan', '10.0.0.5', '10.0.0.10'),
    ])
    assert len(found) == 2


def test_spoofed_floods_group_by_victim():
    found = incidents.correlate(
        [alert(i, 'syn_flood', '198.18.0.%d' % i, '10.0.2.10')
         for i in range(1, 50)])
    assert len(found) == 1 and found[0]['grouped_by'] == 'victim'


def test_newest_incident_first_and_members_marked():
    alerts = [alert(0, 'port_scan', 'a', 'b'), alert(10, 'port_scan', 'c', 'd')]
    found = incidents.correlate(alerts)
    assert [inc['entity'] for inc in found] == [['c', 'd'], ['a', 'b']]
    assert alerts[0]['_incident'] is found[1]


def test_incidents_endpoint(client):
    response = client.get('/api/incidents?hours=720&limit=500')
    assert response.status_code == 200
    body = response.get_json()
    assert body['incidents'] and body['total'] >= len(body['incidents'])
    assert sum(i['alert_count'] for i in body['incidents']) <= body['alerts']
    # Correlation must actually reduce: fewer incidents than alerts.
    assert body['total'] < body['alerts']
    for inc in body['incidents']:
        assert inc['first_ts'] <= inc['last_ts']
        assert inc['techniques']
        assert len(inc['alert_ids']) == inc['alert_count']


def test_incidents_endpoint_validates_arguments(client):
    assert client.get('/api/incidents?gap_min=0').status_code == 400
    assert client.get('/api/incidents?hours=abc').status_code == 400
