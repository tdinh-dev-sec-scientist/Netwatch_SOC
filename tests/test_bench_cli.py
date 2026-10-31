"""End to end: the commands a new user runs first, on the bundled demo pack."""

import json
import os

import pytest

from netwatch_bench.cli import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, 'packs', 'cicids2018-demo')


@pytest.fixture(scope='module')
def netwatch_run(tmp_path_factory):
    out = tmp_path_factory.mktemp('runs') / 'netwatch'
    assert main(['run', '--pack', DEMO, '--engine', 'netwatch',
                 '--out', str(out)]) == 0
    return out


def test_validate(capsys):
    assert main(['validate', DEMO]) == 0
    assert '70,758 packets' in capsys.readouterr().out


def test_run_on_the_demo_pack(netwatch_run):
    card = json.loads((netwatch_run / 'scorecard.json').read_text())
    assert card['detection']['k'] == card['detection']['n'] == 7
    assert card['exposure']['packets'] == 70758
    manifest = card['manifest']
    assert manifest['engine']['name'] == 'netwatch'
    assert manifest['pack']['id'] == 'cicids2018-demo'
    assert len(manifest['captures'][0]['files'][0]['sha256']) == 64
    report = (netwatch_run / 'report.md').read_text()
    assert '95% CI' in report and 'Provenance' in report
    lines = (netwatch_run / 'findings.jsonl').read_text().splitlines()
    assert len(lines) == card['alerts']['total']


def test_rescore_with_a_filter_is_recorded(netwatch_run, tmp_path, capsys):
    out = tmp_path / 'high'
    assert main(['score', '--pack', DEMO, '--from', str(netwatch_run),
                 '--min-severity', 'CRITICAL', '--out', str(out)]) == 0
    card = json.loads((out / 'scorecard.json').read_text())
    assert card['manifest']['filter'] == {'min_severity': 'CRITICAL'}
    assert card['alerts']['total'] < 11
    assert '(filtered)' in capsys.readouterr().out


def test_compare_reports_significance(netwatch_run, tmp_path, capsys):
    out = tmp_path / 'high'
    main(['score', '--pack', DEMO, '--from', str(netwatch_run),
          '--min-severity', 'CRITICAL', '--out', str(out)])
    capsys.readouterr()
    assert main(['compare', str(netwatch_run), str(out)]) == 0
    text = capsys.readouterr().out
    assert 'Fisher' in text and 'significant' in text


def test_errors_are_reported_without_a_traceback(tmp_path, capsys):
    assert main(['run', '--pack', str(tmp_path), '--engine', 'netwatch']) == 2
    assert 'no pack.yaml' in capsys.readouterr().err
    assert main(['run', '--pack', DEMO, '--engine', 'eve']) == 2
    assert '--input' in capsys.readouterr().err


def test_validate_without_the_dataset_checks_the_schema_only(capsys):
    assert main(['validate', os.path.join(ROOT, 'packs',
                                          'cicids2018-holdout2')]) == 0
    out = capsys.readouterr().out
    assert 'skip' in out and 'Schema valid' in out


def test_validate_fails_on_a_missing_dataset_file(tmp_path, capsys):
    assert main(['validate', os.path.join(ROOT, 'packs', 'cicids2018-holdout2'),
                 '--data', str(tmp_path)]) == 1
    assert 'FAIL' in capsys.readouterr().out
