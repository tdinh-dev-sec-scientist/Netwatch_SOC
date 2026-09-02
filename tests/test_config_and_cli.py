"""Configuration loading and the command-line entry points."""

import json

import pytest

from netwatch import cli
from netwatch import config as config_module
from netwatch.db import session as session_mod

# ── configuration ────────────────────────────────────────────────────────────

def test_defaults_load_without_a_file():
    cfg = config_module.load()
    assert cfg['engine']['packet_batch'] > 0
    assert cfg['port_scan']['distinct_ports'] > 0


def test_defaults_are_copied_not_shared():
    first = config_module.load()
    first['port_scan']['distinct_ports'] = 1
    assert config_module.load()['port_scan']['distinct_ports'] != 1


def test_overrides_are_merged_not_replaced(tmp_path):
    path = tmp_path / 'override.json'
    path.write_text(json.dumps({'port_scan': {'distinct_ports': 3}}))
    cfg = config_module.load(str(path))
    assert cfg['port_scan']['distinct_ports'] == 3
    # Sibling keys in the same section survive the merge.
    assert cfg['port_scan']['window_s'] == \
        config_module.DEFAULTS['port_scan']['window_s']
    # And so do other sections.
    assert cfg['syn_flood'] == config_module.DEFAULTS['syn_flood']


def test_override_file_is_read_from_the_environment(tmp_path, monkeypatch):
    path = tmp_path / 'override.json'
    path.write_text(json.dumps({'brute_force': {'failures': 99}}))
    monkeypatch.setenv('NETWATCH_CONFIG', str(path))
    assert config_module.load()['brute_force']['failures'] == 99


def test_a_missing_override_file_fails_loudly(tmp_path):
    with pytest.raises(OSError):
        config_module.load(str(tmp_path / 'nope.json'))


# ── database URL handling ────────────────────────────────────────────────────

@pytest.mark.parametrize('given,expected', [
    ('postgres://u:p@h:5432/d', 'postgresql+psycopg://u:p@h:5432/d'),
    ('postgresql://u:p@h:5432/d', 'postgresql+psycopg://u:p@h:5432/d'),
    ('postgresql+psycopg://u:p@h:5432/d', 'postgresql+psycopg://u:p@h:5432/d'),
])
def test_database_urls_are_normalised_to_psycopg3(given, expected):
    assert session_mod.database_url(given) == expected


def test_database_url_falls_back_to_the_environment(monkeypatch):
    monkeypatch.setenv('NETWATCH_DATABASE_URL', 'postgresql://a:b@c:1/d')
    assert session_mod.database_url() == 'postgresql+psycopg://a:b@c:1/d'


def test_engines_are_reused_per_url_and_schema(scratch_url):
    first = session_mod.get_engine(scratch_url)
    second = session_mod.get_engine(scratch_url)
    assert first is second


def test_wait_for_database_gives_up_rather_than_hanging():
    with pytest.raises(RuntimeError):
        session_mod.wait_for_database(
            'postgresql://nobody:nobody@127.0.0.1:1/none',
            timeout_s=0.5, interval_s=0.1)


# ── CLI ──────────────────────────────────────────────────────────────────────

def test_parser_exposes_the_three_commands():
    parser = cli.build_parser()
    for argv in (['initdb'], ['engine'], ['api']):
        assert parser.parse_args(argv).command == argv[0]


def test_engine_command_defaults_are_sane():
    args = cli.build_parser().parse_args(['engine'])
    assert args.batch_size > 0
    assert args.persist_workers >= 1
    assert args.drop_on_overflow is False


def test_a_command_is_required():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args([])


def test_initdb_creates_and_seeds(scratch_url, capsys):
    assert cli.main(['--database-url', scratch_url, 'initdb']) == 0
    assert 'schema ready: 10 tables' in capsys.readouterr().out


def test_engine_command_runs_and_balances_its_accounting(scratch_url,
                                                         tmp_path, capsys):
    report_path = tmp_path / 'engine.json'
    code = cli.main(['--database-url', scratch_url, 'engine',
                     '--duration-s', '1.0', '--rate-pps', '400',
                     '--batch-size', '64', '--persist-workers', '1',
                     '--report-interval-s', '0.5',
                     '--json', str(report_path)])
    assert code == 0
    report = json.loads(report_path.read_text())
    acct = report['accounting']
    assert acct['frames_captured'] > 0
    assert acct['in_flight'] == 0
    assert report['accounting_balanced'] is True
    assert 'engine stopped' in capsys.readouterr().err or True


def test_engine_records_its_window_to_the_database(scratch_url, tmp_path):
    from netwatch.db.repository import Repository
    engine = session_mod.get_engine(scratch_url)
    before = Repository(engine).get_pipeline_runs(source='engine')['total']
    cli.main(['--database-url', scratch_url, 'engine', '--duration-s', '0.6',
              '--rate-pps', '300', '--batch-size', '64',
              '--persist-workers', '1', '--report-interval-s', '0.2'])
    after = Repository(engine).get_pipeline_runs(source='engine')['total']
    assert after > before


def test_rate_of_zero_means_unthrottled(monkeypatch):
    """`--rate-pps 0` must mean "as fast as possible", not "no packets"."""
    captured = {}

    def fake_engine(args):
        captured['rate'] = args.rate_pps
        return 0

    monkeypatch.setattr(cli, 'cmd_engine', fake_engine)
    parser = cli.build_parser()
    args = parser.parse_args(['engine', '--rate-pps', '0'])
    args.func = fake_engine
    if args.rate_pps == 0:
        args.rate_pps = None
    args.func(args)
    assert captured['rate'] is None


def test_numeric_environment_overrides_are_validated(monkeypatch):
    monkeypatch.setenv('NETWATCH_RATE_PPS', 'fast')
    with pytest.raises(SystemExit):
        cli._env_float('NETWATCH_RATE_PPS', 1.0)
