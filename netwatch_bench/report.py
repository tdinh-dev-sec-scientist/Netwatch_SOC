"""Render scorecards and comparisons as Markdown and as terminal text."""

from . import stats


def pct(value):
    return '—' if value is None else '%.0f%%' % (100 * value)


def ci_pct(ci):
    return '—' if ci is None else '%.0f–%.0f%%' % (100 * ci[0], 100 * ci[1])


def num(value, digits=1):
    if value is None:
        return '—'
    if value and abs(value) < 10 ** -digits:
        return '%.2g' % value
    return format(round(value, digits), ',.%df' % digits)


def ci_num(ci, digits=1):
    return '—' if ci is None else '%s–%s' % (num(ci[0], digits),
                                             num(ci[1], digits))


def plural(n, word):
    return '%d %s%s' % (n, word, '' if n == 1 else 's')


def mark(value):
    return {True: 'yes', False: '**no**', None: 'n/a'}[value]


def engine_label(card):
    engine = card['manifest']['engine']
    label = engine.get('name', 'engine')
    if card['manifest'].get('filter'):
        label += ' (filtered)'
    return label


def headline(card):
    """The four numbers that matter, as (label, value) pairs."""
    d, c, n = card['detection'], card['classification'], card['noise']
    exposure = card['exposure']
    rows = [
        ('Attacks detected', '%d / %d  (%s, 95%% CI %s)'
         % (d['k'], d['n'], pct(d['rate']), ci_pct(d['ci95']))),
        ('Right technique', '%d / %d assessable  (95%% CI %s)%s'
         % (c['k'], c['n'], ci_pct(c['ci95']),
            '; %d not assessable' % c['not_assessable']
            if c['not_assessable'] else '')),
        ('False alerts', '%s per host-hour  (95%% CI %s; %d in %s host-hours)'
         % (num(n['false_alerts_per_host_hour'], 2),
            ci_num(n['false_alerts_per_host_hour_ci95'], 2),
            n['false_alerts'], num(exposure['host_hours'], 2))),
        ('False incidents', '%s per host-day  (%d of %d incidents)'
         % (num(n['false_incidents_per_host_day']), n['false_incidents'],
            n['incidents'])),
        ('Alert precision', '%s  (%d of %d alerts)'
         % (pct(card['alerts']['precision']['rate']),
            card['alerts']['true_positive'], card['alerts']['total'])),
    ]
    return rows


def markdown(card):
    m = card['manifest']
    exposure = card['exposure']
    out = ['# %s on %s' % (engine_label(card), card['pack']['title']), '',
           '| | |', '|---|---|']
    out += ['| %s | %s |' % (k, v.replace('  (', ' (')) for k, v in headline(card)]
    out.append('| Exposure | %s, %s packets, %s host-hours |'
               % (plural(exposure['captures'], 'capture'),
                  format(exposure['packets'], ','),
                  num(exposure['host_hours'], 2)))
    out += ['', '## Per scenario', '',
            '| Scenario | Victim | Detected | Right technique | Alerts | '
            'First alert | Rules that fired |',
            '|---|---|---|---|---|---|---|']
    for row in card['scenarios']:
        first = row['first_alert_after_s']
        out.append('| %s | %s | %s | %s | %d | %s | %s |' % (
            row['label'], row['victim'] or '—', mark(row['detected']),
            mark(row['correct_class']) if row['detected'] else '—',
            row['alerts'],
            '%+.0fs' % first if first is not None else '—',
            ', '.join('%s ×%d' % kv for kv in row['rules'].items()) or '—'))
    noise = card['noise']
    out += ['', '## False positives', '']
    if noise['top_false_positive_rules']:
        out += ['| Rule | Alerts |', '|---|---|']
        out += ['| %s | %d |' % kv
                for kv in noise['top_false_positive_rules'].items()]
    else:
        out.append('None.')
    if noise['explained_by_annotations']:
        out += ['', 'Explained by known, unlabelled activity in the pack '
                '(still counted as false positives):', '']
        out += ['- `%s`: %s' % (name, plural(n, 'alert'))
                for name, n in noise['explained_by_annotations'].items()]
    out += ['', '## Provenance', '',
            '| | |', '|---|---|',
            '| Engine | %s |' % _engine_line(m['engine']),
            '| Filter | %s |' % (m['filter'] or 'none: every alert the engine '
                                 'raised'),
            '| Pack | `%s` sha256 `%s` |' % (m['pack']['id'],
                                           m['pack']['sha256'][:16]),
            '| Inputs hashed | %s |' % ('yes' if m['inputs_hashed'] else
                                       '**no** (--skip-hash)'),
            '| Tool | netwatch-bench %s, Python %s, %s |'
            % (m['tool']['version'], m['environment']['python'],
               m['environment']['platform']),
            '| Command | `%s` |' % ' '.join(m['command']),
            '| Finished | %s |' % m['finished_utc']]
    if card.get('limitations'):
        out += ['', '## Limitations of this pack', '']
        out += ['- %s' % item for item in card['limitations']]
    out += ['', 'Metric definitions: docs/bench/metric-contract.md']
    return '\n'.join(out) + '\n'


def _engine_line(engine):
    parts = [engine.get('name', '?')]
    for key in ('version', 'runtime', 'config', 'rules'):
        if engine.get(key):
            parts.append('%s `%s`' % (key, engine[key]))
    for key in ('config_sha256', 'rules_sha256'):
        if engine.get(key):
            parts.append('%s `%s`' % (key, engine[key][:16]))
    return ', '.join(parts)


def terminal(card, colour=False):
    def paint(text, code):
        return '\033[%sm%s\033[0m' % (code, text) if colour else text

    out = ['', paint('%s on %s' % (engine_label(card), card['pack']['title']),
                     '1'), '']
    width = max(len(k) for k, _ in headline(card))
    for key, value in headline(card):
        out.append('  %s  %s' % (key.ljust(width), value))
    out += ['', '  ' + paint('Per scenario', '1')]
    for row in card['scenarios']:
        if not row['detected']:
            sign = paint('✗ missed ', '31')
        elif row['correct_class'] is False:
            sign = paint('~ wrong technique', '33')
        else:
            sign = paint('✓ detected', '32')
        first = row['first_alert_after_s']
        name = row['label'] + (' @ %s' % row['victim'] if row['victim'] else '')
        out.append('    %-44s %-18s %s' % (
            name[:44], sign,
            ('%s, first %+.0fs' % (plural(row['alerts'], 'alert'), first))
            if first is not None else ''))
    return '\n'.join(out) + '\n'


# ── comparison ───────────────────────────────────────────────────────────────

def compare(a, b):
    """Two scorecards on the same pack, with exact tests. Returns a dict."""
    same_pack = (a['manifest']['pack']['sha256']
                 == b['manifest']['pack']['sha256'])
    da, db = a['detection'], b['detection']
    na, nb = a['noise'], b['noise']
    ha, hb = a['exposure']['host_hours'], b['exposure']['host_hours']
    by_id = {(r['scenario'], r['victim']): r for r in b['scenarios']}
    rows = []
    for r in a['scenarios']:
        other = by_id.get((r['scenario'], r['victim']))
        rows.append({'label': r['label'], 'victim': r['victim'],
                     'a': r['detected'],
                     'b': other['detected'] if other else None})
    return {
        'a': engine_label(a), 'b': engine_label(b),
        'same_pack': same_pack,
        'same_exposure': abs(ha - hb) < 1e-6,
        'detection': {
            'a': da, 'b': db,
            'fisher_p': stats.fisher_exact(da['k'], da['n'], db['k'], db['n'])
            if da['n'] and db['n'] else None,
        },
        'noise': {
            'a': na['false_alerts_per_host_hour'],
            'b': nb['false_alerts_per_host_hour'],
            'a_ci95': na['false_alerts_per_host_hour_ci95'],
            'b_ci95': nb['false_alerts_per_host_hour_ci95'],
            'rate_test_p': stats.poisson_rate_test(
                na['false_alerts'], ha, nb['false_alerts'], hb),
        },
        'scenarios': rows,
    }


def _verdict(p):
    if p is None:
        return 'not testable'
    if p < 0.05:
        return 'significant at 5%% (p = %s)' % _p(p)
    return '**not** significant at 5%% (p = %s)' % _p(p)


def _p(p):
    return '%.2g' % p if p >= 1e-4 else '< 0.0001'


def compare_markdown(result):
    d, n = result['detection'], result['noise']
    out = ['# %s vs %s' % (result['a'], result['b']), '']
    if not result['same_pack']:
        out += ['> **Warning:** the scorecards come from different packs '
                '(or different versions of one); the comparison below is not '
                'like for like.', '']
    out += ['| | %s | %s | Difference |' % (result['a'], result['b']),
            '|---|---|---|---|',
            '| Attacks detected | %d / %d (95%% CI %s) | %d / %d (95%% CI %s) '
            '| %s |' % (d['a']['k'], d['a']['n'], ci_pct(d['a']['ci95']),
                        d['b']['k'], d['b']['n'], ci_pct(d['b']['ci95']),
                        _verdict(d['fisher_p'])),
            '| False alerts per host-hour | %s (95%% CI %s) | %s (95%% CI %s) '
            '| %s |' % (num(n['a'], 2), ci_num(n['a_ci95'], 2),
                        num(n['b'], 2), ci_num(n['b_ci95'], 2),
                        _verdict(n['rate_test_p'])),
            '', '| Scenario | %s | %s |' % (result['a'], result['b']),
            '|---|---|---|']
    for row in result['scenarios']:
        name = row['label'] + (' @ %s' % row['victim'] if row['victim'] else '')
        out.append('| %s | %s | %s |' % (name, mark(row['a']), mark(row['b'])))
    out += ['', 'Detection: two-sided Fisher exact test. False alerts: exact '
            'conditional test for two Poisson rates. With a handful of '
            'scenarios, only large differences can be significant; report '
            'the intervals, not just the counts.']
    return '\n'.join(out) + '\n'
