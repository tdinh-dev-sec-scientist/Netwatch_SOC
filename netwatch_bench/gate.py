"""
Regression gate: compare a candidate scorecard with a pinned baseline.

The same idea as a snapshot test. The baseline is a scorecard committed to
the repository; a change to rules, thresholds or engine version produces a
candidate; the gate fails when the candidate is worse in a way that matters:

* a scenario unit the baseline detected is now missed           (lost_detection)
* a unit the baseline classified correctly is now wrong          (lost_classification)
* false alerts rose past the noise budget                        (noise_budget)
* false alerts per host-hour exceed an absolute ceiling          (noise_ceiling)

A rule that starts producing false alerts it never produced before is
reported (new_noisy_rule) but only fails the gate with --fail-on-new-noise.
Improvements are reported and never fail. An intentional regression is
accepted by updating the baseline in the same change, where reviewers see it.
"""

import os

from . import report

RULES = {
    'lost_detection': ('NWB001', 'error',
                       'An attack the baseline detected is now missed'),
    'lost_classification': ('NWB002', 'error',
                            'An attack is now detected as the wrong technique'),
    'noise_budget': ('NWB003', 'error',
                     'False alerts rose past the noise budget'),
    'noise_ceiling': ('NWB004', 'error',
                      'False alerts per host-hour exceed the ceiling'),
    'new_noisy_rule': ('NWB005', 'warning',
                       'A rule raises false alerts it did not raise before'),
    'pack_changed': ('NWB006', 'error',
                     'Baseline and candidate were scored on different packs'),
}


class Budget:
    def __init__(self, max_noise_increase=0.10, noise_slack=2,
                 max_false_alerts_per_host_hour=None, fail_on_new_noise=False,
                 allow_pack_change=False):
        self.max_noise_increase = max_noise_increase
        self.noise_slack = noise_slack
        self.ceiling = max_false_alerts_per_host_hour
        self.fail_on_new_noise = fail_on_new_noise
        self.allow_pack_change = allow_pack_change

    def describe(self):
        return {'max_noise_increase': self.max_noise_increase,
                'noise_slack_alerts': self.noise_slack,
                'max_false_alerts_per_host_hour': self.ceiling,
                'fail_on_new_noise': self.fail_on_new_noise}


def _key(row):
    return (row['scenario'], row['victim'])


def _name(row):
    return row['label'] + (' @ %s' % row['victim'] if row['victim'] else '')


def diff(baseline, candidate, budget=None):
    """Return {'passed': bool, 'problems': [...], 'improvements': [...]}."""
    budget = budget or Budget()
    problems, improvements = [], []

    def problem(kind, message, scenario=None, fails=True):
        problems.append({'kind': kind, 'message': message,
                         'scenario': scenario, 'fails': fails})

    if (baseline['manifest']['pack']['sha256']
            != candidate['manifest']['pack']['sha256']):
        problem('pack_changed',
                'The pack changed between baseline and candidate; '
                'differences below may come from the pack, not the engine. '
                'Re-run the baseline on the new pack.',
                fails=not budget.allow_pack_change)

    before = {_key(r): r for r in baseline['scenarios']}
    for row in candidate['scenarios']:
        old = before.get(_key(row))
        if old is None:
            continue
        if old['detected'] and not row['detected']:
            problem('lost_detection', '%s: detected in the baseline (%s), '
                    'missed now' % (_name(row), ', '.join(old['rules']) or
                                    'no rule recorded'), row['scenario'])
        elif not old['detected'] and row['detected']:
            improvements.append('%s: now detected (%s)'
                                % (_name(row), ', '.join(row['rules'])))
        if old['correct_class'] is True and row['correct_class'] is False \
                and row['detected']:
            problem('lost_classification', '%s: classified as %s in the '
                    'baseline, now only as %s' % (
                        _name(row), ', '.join(old['techniques_seen']),
                        ', '.join(row['techniques_seen']) or 'nothing'),
                    row['scenario'])

    b, c = baseline['noise'], candidate['noise']
    allowed = (b['false_alerts'] * (1 + budget.max_noise_increase)
               + budget.noise_slack)
    if c['false_alerts'] > allowed:
        problem('noise_budget', 'False alerts rose from %d to %d; the budget '
                'allows %d (+%.0f%% and %d alerts of slack)' % (
                    b['false_alerts'], c['false_alerts'], int(allowed),
                    100 * budget.max_noise_increase, budget.noise_slack))
    elif c['false_alerts'] < b['false_alerts']:
        improvements.append('False alerts fell from %d to %d'
                            % (b['false_alerts'], c['false_alerts']))
    rate = c['false_alerts_per_host_hour']
    if budget.ceiling is not None and rate is not None and rate > budget.ceiling:
        problem('noise_ceiling', '%.2f false alerts per host-hour is above '
                'the ceiling of %.2f' % (rate, budget.ceiling))

    old_rules = b['top_false_positive_rules']
    for rule, count in c['top_false_positive_rules'].items():
        if rule not in old_rules and count >= 3:
            problem('new_noisy_rule', '%s raised %d false alerts; it raised '
                    'none in the baseline\'s top list' % (rule, count),
                    fails=budget.fail_on_new_noise)

    return {
        'passed': not any(p['fails'] for p in problems),
        'problems': problems,
        'improvements': improvements,
        'budget': budget.describe(),
        'baseline': {'engine': report.engine_label(baseline),
                     'detected': baseline['detection'],
                     'false_alerts': b['false_alerts']},
        'candidate': {'engine': report.engine_label(candidate),
                      'detected': candidate['detection'],
                      'false_alerts': c['false_alerts']},
        'pack': candidate['pack'],
        'pack_path': candidate['manifest']['pack']['path'],
    }


def markdown(result):
    status = 'passed' if result['passed'] else 'FAILED'
    b, c = result['baseline'], result['candidate']
    out = ['## NetWatch Bench regression gate: %s' % status, '',
           '| | Baseline | Candidate |', '|---|---|---|',
           '| Attacks detected | %d / %d | %d / %d |' % (
               b['detected']['k'], b['detected']['n'],
               c['detected']['k'], c['detected']['n']),
           '| False alerts | %d | %d |' % (b['false_alerts'],
                                          c['false_alerts']), '']
    failing = [p for p in result['problems'] if p['fails']]
    warnings = [p for p in result['problems'] if not p['fails']]
    for title, items in (('Regressions', failing), ('Warnings', warnings)):
        if items:
            out += ['**%s**' % title, '']
            out += ['- `%s` %s' % (RULES[p['kind']][0], p['message'])
                    for p in items]
            out.append('')
    if result['improvements']:
        out += ['**Improvements**', '']
        out += ['- %s' % item for item in result['improvements']]
        out.append('')
    if not result['problems'] and not result['improvements']:
        out += ['No change from the baseline.', '']
    out += ['Budget: +%.0f%% false alerts plus %d of slack%s. An intentional '
            'change is accepted by updating the baseline in the same commit.'
            % (100 * result['budget']['max_noise_increase'],
               result['budget']['noise_slack_alerts'],
               '; ceiling %.2f per host-hour'
               % result['budget']['max_false_alerts_per_host_hour']
               if result['budget']['max_false_alerts_per_host_hour']
               is not None else '')]
    return '\n'.join(out) + '\n'


def _scenario_line(pack_path, scenario_id):
    """1-based line of `- id: <scenario>` in the pack file, for SARIF."""
    if not scenario_id or not os.path.exists(pack_path):
        return 1
    with open(pack_path, encoding='utf-8') as fh:
        for number, line in enumerate(fh, 1):
            stripped = line.strip().lstrip('-').strip()
            if stripped in ('id: %s' % scenario_id,
                            'id: "%s"' % scenario_id,
                            '"id": "%s",' % scenario_id):
                return number
    return 1


def sarif(result, repo_root):
    """SARIF 2.1.0, so regressions show in GitHub's Security tab and on PRs."""
    from . import __version__
    pack_path = result['pack_path']
    uri = os.path.relpath(pack_path, repo_root).replace(os.sep, '/')
    rules = [{
        'id': rule_id, 'name': kind,
        'shortDescription': {'text': text},
        'defaultConfiguration': {'level': level},
        'helpUri': 'https://github.com/tdinh-dev-sec-scientist/Netwatch_SOC/'
                   'blob/main/docs/bench/metric-contract.md',
    } for kind, (rule_id, level, text) in RULES.items()]
    results = []
    for p in result['problems']:
        rule_id, level, _text = RULES[p['kind']]
        results.append({
            'ruleId': rule_id,
            'level': level if p['fails'] else 'warning',
            'message': {'text': p['message']},
            'locations': [{'physicalLocation': {
                'artifactLocation': {'uri': uri},
                'region': {'startLine': _scenario_line(pack_path,
                                                       p['scenario'])},
            }}],
            'partialFingerprints': {
                'netwatchBench/v0': '%s:%s:%s' % (rule_id, result['pack']['id'],
                                                  p['scenario'] or p['kind'])},
        })
    return {
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {'driver': {
                'name': 'netwatch-bench', 'version': __version__,
                'informationUri': 'https://github.com/tdinh-dev-sec-scientist/'
                                  'Netwatch_SOC/tree/main/netwatch_bench',
                'rules': rules}},
            'results': results,
        }],
    }
