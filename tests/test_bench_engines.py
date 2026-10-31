"""Engine adapters: Suricata (against a stand-in binary), file imports."""

import json
import os
import stat
import sys
import textwrap

import pytest

from netwatch_bench import pack as pack_module
from netwatch_bench.engines import ENGINES, EngineError
from netwatch_bench.engines.netwatch import to_finding
from netwatch_bench.engines.suricata import (SuricataEngine,
                                             alerts_only_config,
                                             eve_to_finding)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, 'packs', 'cicids2018-demo')

EVE_ALERT = {
    'timestamp': '2017-07-14T02:56:05.250000+0000',
    'event_type': 'alert', 'src_ip': '13.58.98.64', 'src_port': 51000,
    'dest_ip': '172.31.69.25', 'dest_port': 22, 'proto': 'TCP',
    'alert': {'signature_id': 2001219, 'signature': 'ET SCAN Potential SSH '
              'Scan', 'category': 'Attempted Information Leak',
              'severity': 2,
              'metadata': {'mitre_technique_id': ['T1110'],
                           'created_at': ['2010_07_30']}},
}

STOCK_CONFIG = textwrap.dedent('''\
    %YAML 1.1
    ---
    outputs:
      - fast:
          enabled: yes
      - eve-log:
          enabled: yes
          types:
            - alert
            - flow
            - dns
      - stats:
          enabled: yes
    ''')


def test_eve_alert_becomes_a_normalized_finding():
    f = eve_to_finding(EVE_ALERT, 'demo')
    assert f['ts'] == pytest.approx(1500000965.25)
    assert f['rule'] == 'sid:2001219'
    assert f['severity'] == 'MEDIUM'
    assert f['techniques'] == ['T1110']
    assert (f['src_ip'], f['dst_ip'], f['dst_port']) == (
        '13.58.98.64', '172.31.69.25', 22)
    assert eve_to_finding({'event_type': 'flow'}, 'demo') is None


def test_eve_alert_without_mitre_metadata_is_untyped():
    event = json.loads(json.dumps(EVE_ALERT))
    del event['alert']['metadata']
    assert eve_to_finding(event, 'demo')['techniques'] == []


def test_alerts_only_config_disables_every_other_output():
    import yaml
    text = alerts_only_config(STOCK_CONFIG)
    assert text.startswith('%YAML 1.1')
    outputs = {k: v for o in yaml.safe_load(text.split('\n', 2)[2])['outputs']
               for k, v in o.items()}
    assert outputs['fast']['enabled'] is False
    assert outputs['stats']['enabled'] is False
    assert outputs['eve-log']['enabled'] is True
    assert outputs['eve-log']['types'] == [
        {'alert': {'tagged-packets': False, 'metadata': True}}]
    conf = yaml.safe_load(text.split('\n', 2)[2])
    assert conf['stream']['checksum-validation'] is False
    assert conf['pcap-file']['checksum-checks'] == 'no'
    kept = yaml.safe_load(alerts_only_config(STOCK_CONFIG, True)
                          .split('\n', 2)[2])
    assert 'pcap-file' not in kept


@pytest.fixture
def fake_suricata(tmp_path):
    """A stand-in `suricata` that writes one EVE alert into its -l dir."""
    script = tmp_path / 'suricata'
    script.write_text(textwrap.dedent('''\
        #!%s
        import json, sys
        args = sys.argv[1:]
        if args == ['-V']:
            print('This is Suricata version 7.0.99 RELEASE')
            sys.exit(0)
        assert '-k' in args and args[args.index('-k') + 1] == 'none'
        pcap = open(args[args.index('-r') + 1], 'rb').read(4)
        assert pcap in (b'\\xd4\\xc3\\xb2\\xa1', b'\\xa1\\xb2\\xc3\\xd4'), pcap
        logdir = args[args.index('-l') + 1]
        with open(logdir + '/eve.json', 'w') as fh:
            fh.write(json.dumps(%r) + '\\n')
            fh.write(json.dumps({'event_type': 'stats'}) + '\\n')
        ''') % (sys.executable, EVE_ALERT))
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    rules = tmp_path / 'local.rules'
    rules.write_text('alert tcp any any -> any 22 (msg:"x"; sid:1;)\n')
    config = tmp_path / 'suricata.yaml'
    config.write_text(STOCK_CONFIG)
    return str(script), str(rules), str(config)


def test_suricata_engine_runs_the_binary_and_reads_eve(tmp_path,
                                                       fake_suricata):
    binary, rules, config = fake_suricata
    engine = SuricataEngine(suricata_bin=binary, rules=rules,
                            suricata_config=config)
    info = engine.describe()
    assert info['version'] == 'This is Suricata version 7.0.99 RELEASE'
    assert len(info['rules_sha256']) == 64
    pack = pack_module.load(DEMO)
    capture = pack.captures[0]
    work = tmp_path / 'work'
    work.mkdir()
    # The demo capture is gzipped: the adapter must hand Suricata a plain pcap.
    found = engine.run(capture, capture.resolve(), str(work))
    assert [f['rule'] for f in found] == ['sid:2001219']
    assert found[0]['capture'] == 'demo'


def test_suricata_engine_argument_errors(fake_suricata):
    binary, rules, _config = fake_suricata
    with pytest.raises(EngineError, match='exactly one'):
        SuricataEngine()
    with pytest.raises(EngineError, match='--rules'):
        SuricataEngine(suricata_bin=binary)
    with pytest.raises(EngineError, match='not found'):
        SuricataEngine(suricata_bin='/nonexistent/suricata', rules=rules)


def test_docker_command_is_isolated_and_read_only(fake_suricata, monkeypatch):
    monkeypatch.setattr('shutil.which', lambda name: '/usr/bin/' + name)
    engine = SuricataEngine(suricata_docker='jasonish/suricata:7.0')
    cmd = engine._docker(['-V'], [('/tmp/a.pcap', '/bench/a.pcap', 'ro')])
    assert cmd[:5] == ['docker', 'run', '--rm', '--network', 'none']
    assert '/tmp/a.pcap:/bench/a.pcap:ro' in cmd
    assert cmd[-2:] == ['jasonish/suricata:7.0', '-V']


def test_file_engines_import_alerts(tmp_path):
    pack = pack_module.load(DEMO)
    eve = tmp_path / 'eve.json'
    eve.write_text(json.dumps(EVE_ALERT) + '\n')
    found = list(ENGINES['eve'](input=[str(eve)]).findings(pack))
    assert [f['capture'] for f in found] == ['demo']

    jsonl = tmp_path / 'zeek.jsonl'
    jsonl.write_text(json.dumps({'ts': 1500000965, 'src_ip': '13.58.98.64',
                                 'dst_ip': '172.31.69.25',
                                 'name': 'SSH::Password_Guessing'}) + '\n')
    engine = ENGINES['findings'](input=['demo=' + str(jsonl)],
                                 engine_name='zeek')
    found = list(engine.findings(pack))
    assert found[0]['engine'] == 'zeek'
    assert engine.describe()['name'] == 'zeek'
    with pytest.raises(EngineError, match='--input'):
        ENGINES['eve']()
    with pytest.raises(EngineError, match='does not exist'):
        list(ENGINES['eve'](input=['nope.json']).findings(pack))


def test_netwatch_records_group_floods_by_victim():
    record = {'ts': 1.0, 'threat_type': 'syn_flood', 'severity': 'HIGH',
              'techniques': ['T1498'], 'src_ip': '1.1.1.1',
              'dst_ip': '10.0.0.1', 'src_port': 1, 'dst_port': 80,
              'protocol': 'TCP'}
    assert to_finding(record, 'c')['group_by'] == 'victim'
    record['threat_type'] = 'port_scan'
    assert to_finding(record, 'c')['group_by'] == 'pair'


def test_capture_scan_ignores_a_truncated_final_record(tmp_path):
    """A capture cut off mid-record must not contribute a garbage timestamp
    (two CSE-CIC-IDS2018 captures end this way)."""
    import struct
    from netwatch_bench.captures import scan
    path = tmp_path / 'cut.pcap'
    with open(path, 'wb') as fh:
        fh.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for sec in (100, 160):
            fh.write(struct.pack('<IIII', sec, 0, 4, 4) + b'abcd')
        fh.write(struct.pack('<IIII', 4000000000, 0, 64, 64) + b'ab')
    assert scan(str(path)) == (2, 100.0, 160.0)
