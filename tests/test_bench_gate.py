"""The regression gate, equal-budget tuning, and the Zeek adapter."""

import copy
import json
import os
import stat
import sys
import textwrap

import pytest

from netwatch_bench import gate
from netwatch_bench import pack as pack_module
from netwatch_bench.cli import main
from netwatch_bench.engines import ENGINES, EngineError
from netwatch_bench.engines.zeek import notice_to_finding
from netwatch_bench.findings import normalize
from netwatch_bench.scoring import match
from netwatch_bench.tune import load_rules, suppressions

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, 'packs', 'cicids2018-demo')


@pytest.fixture(scope='module')
def baseline(tmp_path_factory):
    out = tmp_path_factory.mktemp('gate') / 'baseline'
    assert main(['run', '--pack', DEMO, '--engine', 'netwatch',
                 '--out', str(out)]) == 0
    return json.loads((out / 'scorecard.json').read_text())


def worse(card, **changes):
    card = copy.deepcopy(card)
    for row in card['scenarios']:
        if row['scenario'] in changes.get('miss', ()):
            row['detected'], row['correct_class'] = False, False
        if row['scenario'] in changes.get('misclassify', ()):
            row['correct_class'] = False
            row['techniques_seen'] = ['T1498']
    if 'false_alerts' in changes:
        card['noise']['false_alerts'] = changes['false_alerts']
    for rule, count in changes.get('new_rules', {}).items():
        card['noise']['top_false_positive_rules'][rule] = count
    return card


def kinds(result, failing=True):
    return sorted(p['kind'] for p in result['problems']
                  if p['fails'] == failing)


def test_identical_runs_pass(baseline):
    result = gate.diff(baseline, baseline)
    assert result['passed'] and not result['problems']
    assert 'No change' in gate.markdown(result)


def test_a_lost_detection_fails(baseline):
    result = gate.diff(baseline, worse(baseline, miss=['dos_slowloris']))
    assert not result['passed']
    assert kinds(result) == ['lost_detection']
    assert 'Slowloris' in gate.markdown(result)


def test_a_lost_classification_fails(baseline):
    result = gate.diff(baseline, worse(baseline, misclassify=['dos_goldeneye']))
    assert kinds(result) == ['lost_classification']


def test_gains_are_improvements_not_failures(baseline):
    result = gate.diff(worse(baseline, miss=['web_sqli']), baseline)
    assert result['passed']
    assert any('now detected' in item for item in result['improvements'])


def test_noise_budget_and_slack(baseline):
    base_fp = baseline['noise']['false_alerts']
    within = gate.diff(baseline, worse(baseline, false_alerts=base_fp + 2))
    assert within['passed']
    over = gate.diff(baseline, worse(baseline, false_alerts=base_fp + 3))
    assert kinds(over) == ['noise_budget']
    strict = gate.diff(baseline, worse(baseline, false_alerts=base_fp + 1),
                       gate.Budget(max_noise_increase=0, noise_slack=0))
    assert kinds(strict) == ['noise_budget']


def test_noise_ceiling(baseline):
    result = gate.diff(baseline, baseline,
                       gate.Budget(max_false_alerts_per_host_hour=0.5))
    assert kinds(result) == ['noise_ceiling']


def test_new_noisy_rule_warns_unless_asked_to_fail(baseline):
    candidate = worse(baseline, new_rules={'tls_anomaly': 7})
    assert kinds(gate.diff(baseline, candidate), failing=False) == [
        'new_noisy_rule']
    assert not gate.diff(baseline, candidate,
                         gate.Budget(fail_on_new_noise=True))['passed']


def test_a_changed_pack_fails_unless_allowed(baseline):
    candidate = copy.deepcopy(baseline)
    candidate['manifest']['pack']['sha256'] = '0' * 64
    assert kinds(gate.diff(baseline, candidate)) == ['pack_changed']
    assert gate.diff(baseline, candidate,
                     gate.Budget(allow_pack_change=True))['passed']


def test_sarif_points_at_the_scenario_in_the_pack(baseline):
    result = gate.diff(baseline, worse(baseline, miss=['dos_goldeneye']))
    doc = gate.sarif(result, ROOT)
    assert doc['version'] == '2.1.0'
    (finding,) = doc['runs'][0]['results']
    location = finding['locations'][0]['physicalLocation']
    assert location['artifactLocation']['uri'] == \
        'packs/cicids2018-demo/pack.yaml'
    lines = open(os.path.join(DEMO, 'pack.yaml')).read().splitlines()
    assert lines[location['region']['startLine'] - 1] == '- id: dos_goldeneye'
    assert finding['ruleId'] == 'NWB001' and finding['level'] == 'error'


def test_cli_exit_codes(baseline, tmp_path):
    good = tmp_path / 'good.json'
    bad = tmp_path / 'bad.json'
    good.write_text(json.dumps(baseline))
    bad.write_text(json.dumps(worse(baseline, miss=['ssh_bruteforce'])))
    assert main(['diff', str(good), str(good)]) == 0
    sarif = tmp_path / 'gate.sarif'
    assert main(['diff', str(good), str(bad), '--sarif', str(sarif)]) == 1
    assert json.loads(sarif.read_text())['runs'][0]['results']
    assert main(['diff', str(good), str(tmp_path / 'missing.json')]) == 2


def test_the_committed_baseline_is_current():
    """bench/baselines holds the demo scorecard CI gates against. It must be
    a real run of the current pack, or the gate compares against fiction."""
    path = os.path.join(ROOT, 'bench', 'baselines',
                        'cicids2018-demo.netwatch.json')
    committed = json.load(open(path))
    pack = pack_module.load(DEMO)
    assert committed['manifest']['pack']['sha256'] == pack.sha256()
    assert committed['detection']['n'] == len(pack.scenarios)


# ── equal tuning budget ──────────────────────────────────────────────────────

@pytest.fixture
def tiny(tmp_path):
    raw = {'schema': 'netwatch-bench/pack/v0', 'id': 'tiny',
           'captures': [{'id': 'a', 'files': ['a.pcap']}],
           'scenarios': [{'id': 's', 'techniques': ['T1110'],
                          'attackers': ['203.0.113.5'], 'victims': ['10.0.0.2'],
                          'windows': [[0, 100]]}]}
    (tmp_path / 'pack.json').write_text(json.dumps(raw))
    return pack_module.load(str(tmp_path))


def finding(rule, ts, src, dst):
    return normalize({'ts': ts, 'capture': 'a', 'rule': rule, 'src_ip': src,
                      'dst_ip': dst})


def test_tuning_suppresses_the_noisiest_rules_but_never_a_true_positive(tiny):
    findings = ([finding('loud', 500, '1.1.1.1', '10.0.0.3')] * 5
                + [finding('mixed', 500, '1.1.1.1', '10.0.0.3')] * 9
                + [finding('mixed', 50, '203.0.113.5', '10.0.0.2')]
                + [finding('quiet', 500, '1.1.1.1', '10.0.0.3')] * 2
                + [finding('rare', 500, '1.1.1.1', '10.0.0.3')])
    result = suppressions(tiny, findings, budget=2)
    assert result['rules'] == ['loud', 'quiet']
    assert result['protected_rules'] == ['mixed']
    assert result['false_alerts_removed_on_tuning_pack'] == 7
    assert result['false_alerts_on_tuning_pack'] == 17


def test_tuning_files_load_as_json_or_lines(tmp_path):
    as_json = tmp_path / 't.json'
    as_json.write_text(json.dumps({'rules': ['sid:1', 'sid:2']}))
    as_text = tmp_path / 't.txt'
    as_text.write_text('# noisy\nsid:1\n\nsid:2\n')
    assert load_rules(str(as_json)) == load_rules(str(as_text)) == [
        'sid:1', 'sid:2']


def test_tune_then_score_end_to_end(baseline, tmp_path):
    run = tmp_path / 'run'
    main(['run', '--pack', DEMO, '--engine', 'netwatch', '--out', str(run)])
    tuning = tmp_path / 'tuning.json'
    assert main(['tune', '--from', str(run), '--budget', '1',
                 '--out', str(tuning)]) == 0
    assert json.loads(tuning.read_text())['rules'] == ['credential_attack']
    tuned = tmp_path / 'tuned'
    assert main(['score', '--pack', DEMO, '--from', str(run),
                 '--exclude-rules-file', str(tuning), '--out',
                 str(tuned)]) == 0
    card = json.loads((tuned / 'scorecard.json').read_text())
    assert card['noise']['false_alerts'] == 0
    assert card['manifest']['filter'] == {
        'exclude_rules': ['credential_attack']}


# ── one-sided findings and Zeek ──────────────────────────────────────────────

def test_one_sided_findings_match_only_on_the_attacker(tiny):
    attacker_only = finding('x', 50, '203.0.113.5', None)
    victim_only = finding('x', 50, None, '10.0.0.2')
    assert match(attacker_only, tiny)[0].id == 's'
    assert match(victim_only, tiny) == (None, None)


def test_zeek_notices_become_findings():
    notice = {'ts': 1518620000.5, 'note': 'SSH::Password_Guessing',
              'msg': '13.58.98.64 appears to be guessing SSH passwords',
              'src': '13.58.98.64', 'sub': 'Sampled servers: 172.31.69.25'}
    f = notice_to_finding(notice, 'wed14')
    assert (f['rule'], f['techniques'], f['src_ip'], f['dst_ip']) == (
        'SSH::Password_Guessing', ['T1110'], '13.58.98.64', None)
    conn = {'ts': 1.0, 'note': 'Custom::Thing', 'id.orig_h': '10.0.0.1',
            'id.resp_h': '10.0.0.2', 'id.resp_p': 445, 'proto': 'tcp'}
    f = notice_to_finding(conn, 'c')
    assert (f['techniques'], f['dst_port'], f['protocol']) == ([], 445, 'TCP')
    assert notice_to_finding({'ts': 1, 'note': 'CaptureLoss::Too_Much_Loss'},
                             'c') is None


def test_zeek_engine_runs_the_binary(tmp_path):
    script = tmp_path / 'zeek'
    script.write_text(textwrap.dedent('''\
        #!%s
        import json, sys
        if sys.argv[1:] == ['--version']:
            print('zeek version 7.0.99'); sys.exit(0)
        assert sys.argv[1:3] == ['-C', '-r']
        assert 'LogAscii::use_json=T' in sys.argv
        with open('notice.log', 'w') as fh:
            fh.write(json.dumps({'ts': 1500000961.0,
                                 'note': 'SSH::Password_Guessing',
                                 'src': '13.58.98.64'}) + '\\n')
            fh.write(json.dumps({'ts': 1500000962.0,
                                 'note': 'CaptureLoss::Too_Much_Loss'}) + '\\n')
        ''') % sys.executable)
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    custom = tmp_path / 'mine.zeek'
    custom.write_text('event zeek_init() { }\n')
    engine = ENGINES['zeek'](zeek_bin=str(script), zeek_script=[str(custom)])
    info = engine.describe()
    assert info['version'] == 'zeek version 7.0.99'
    assert info['rules'] == 'local + mine.zeek'
    pack = pack_module.load(DEMO)
    work = tmp_path / 'work'
    work.mkdir()
    found = engine.run(pack.captures[0], pack.captures[0].resolve(), str(work))
    assert [f['rule'] for f in found] == ['SSH::Password_Guessing']
    with pytest.raises(EngineError, match='exactly one'):
        ENGINES['zeek']()


def test_zeek_stopping_at_a_truncated_record_is_a_warning(tmp_path):
    script = tmp_path / 'zeek'
    script.write_text(textwrap.dedent('''\
        #!%s
        import json, sys
        if sys.argv[1:] == ['--version']:
            print('zeek version 7.0.99'); sys.exit(0)
        with open('notice.log', 'w') as fh:
            fh.write(json.dumps({'ts': 1.0, 'note': 'SSH::Password_Guessing',
                                 'src': '13.58.98.64'}) + '\\n')
        sys.stderr.write('fatal error: truncated dump file; tried to read\\n')
        sys.exit(1)
        ''') % sys.executable)
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    out = tmp_path / 'run'
    assert main(['run', '--pack', DEMO, '--engine', 'zeek', '--zeek-bin',
                 str(script), '--out', str(out)]) == 0
    card = json.loads((out / 'scorecard.json').read_text())
    assert card['alerts']['total'] == 1
    assert 'truncated record' in card['manifest']['warnings'][0]
    assert 'Warning' in (out / 'report.md').read_text()
