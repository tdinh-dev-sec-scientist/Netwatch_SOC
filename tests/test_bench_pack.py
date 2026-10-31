"""Pack loading and validation."""

import copy
import json
import os

import pytest

from netwatch_bench import pack as pack_module
from netwatch_bench.pack import PackError, technique_matches

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKS = os.path.join(ROOT, 'packs')

MINIMAL = {
    'schema': 'netwatch-bench/pack/v0',
    'id': 'tiny',
    'captures': [{'id': 'c1', 'files': ['c1.pcap']}],
    'scenarios': [{
        'id': 'brute', 'techniques': ['T1110'],
        'attackers': ['203.0.113.5'], 'victims': ['10.0.0.2'],
        'windows': [['2020-01-01T00:00:00Z', '2020-01-01T01:00:00Z']],
    }],
}


def write_pack(tmp_path, raw):
    path = tmp_path / 'pack.json'
    path.write_text(json.dumps(raw))
    return pack_module.load(str(tmp_path))


def broken(**changes):
    raw = copy.deepcopy(MINIMAL)
    for dotted, value in changes.items():
        target = raw
        keys = dotted.split('__')
        for key in keys[:-1]:
            target = target[int(key)] if key.isdigit() else target[key]
        target[keys[-1]] = value
    return raw


@pytest.mark.parametrize('pack_id', ['cicids2018-demo', 'cicids2018-dev',
                                     'cicids2018-holdout',
                                     'cicids2018-holdout2'])
def test_shipped_packs_load(pack_id):
    loaded = pack_module.load(os.path.join(PACKS, pack_id))
    assert loaded.id == pack_id
    assert loaded.scenarios and loaded.captures
    for sc in loaded.scenarios:
        assert sc.onset >= sc.windows[0][0]


def test_minimal_pack(tmp_path):
    loaded = write_pack(tmp_path, MINIMAL)
    sc = loaded.scenarios[0]
    assert sc.windows == [(1577836800.0, 1577840400.0)]
    assert sc.onset == 1577836800.0
    assert loaded.capture('c1').resolve() == [str(tmp_path / 'c1.pcap')]
    assert loaded.is_internal('10.0.0.2')
    assert not loaded.is_internal('203.0.113.5')
    assert not loaded.is_internal(None)


@pytest.mark.parametrize('changes, message', [
    ({'schema': 'v9'}, 'schema'),
    ({'scenarios__0__techniques': ['brute_force']}, 'ATT&CK technique'),
    ({'scenarios__0__techniques': []}, 'techniques'),
    ({'scenarios__0__victims': []}, 'victim'),
    ({'scenarios__0__attackers': ['not-an-ip']}, 'IP address'),
    ({'scenarios__0__attackers': []}, 'attackers, a pivot'),
    ({'scenarios__0__windows': [['2020-01-01T01:00:00',
                                 '2020-01-01T00:00:00']]}, 'not after'),
    ({'scenarios__0__windows': [['yesterday', 'today']]}, 'ISO 8601'),
    ({'captures': []}, 'capture'),
    ({'captures__0__files': [{'path': 'a', 'data_path': 'b'}]}, 'exactly one'),
    ({'id': 'has spaces'}, 'identifier'),
    ({'internal_networks': ['10.0.0.0/33']}, 'internal_networks'),
])
def test_validation_names_the_problem(tmp_path, changes, message):
    with pytest.raises(PackError, match=message):
        write_pack(tmp_path, broken(**changes))


def test_duplicate_ids_are_rejected(tmp_path):
    raw = copy.deepcopy(MINIMAL)
    raw['scenarios'].append(copy.deepcopy(raw['scenarios'][0]))
    with pytest.raises(PackError, match='duplicate'):
        write_pack(tmp_path, raw)


def test_dataset_captures_need_a_data_directory(tmp_path):
    raw = broken(captures__0__files=[{'data_path': 'day1/host.pcap'}])
    loaded = write_pack(tmp_path, raw)
    with pytest.raises(PackError, match='--data'):
        loaded.capture('c1').resolve()
    assert loaded.capture('c1').resolve('/datasets') == [
        '/datasets/day1/host.pcap']


def test_custom_internal_networks(tmp_path):
    loaded = write_pack(tmp_path, broken(internal_networks=['100.64.0.0/10']))
    assert loaded.is_internal('100.64.1.1')
    assert not loaded.is_internal('10.0.0.2')


def test_technique_matching_respects_sub_techniques():
    assert technique_matches('T1499.002', 'T1499')
    assert technique_matches('T1110', 'T1110')
    assert not technique_matches('T1499', 'T1499.002')
    assert not technique_matches('T1071.004', 'T1071.001')
    assert not technique_matches('T14990', 'T1499')
