"""
Equal tuning budget: the fair way to compare engines.

Comparing an engine as distributed with one tuned on the same data favours
the tuned one. Instead, give every engine the same budget on a development
pack: suppress up to N rules, choosing the ones that raised the most false
alerts and never a rule that raised even one true positive. Then score every
engine, with its own suppression list, on a held-out pack that played no
part in choosing it.

    netwatch-bench tune --from runs/suricata-dev --budget 10 --out tuning.json
    netwatch-bench score --pack packs/cicids2018-holdout --from runs/suricata-holdout \\
        --exclude-rules-file tuning.json --out runs/suricata-holdout-tuned
"""

import collections
import json
import os

from .findings import read_jsonl
from .pack import load
from .scoring import match


def suppressions(pack, findings, budget):
    """The `budget` rules with the most false alerts and no true positive."""
    fp, tp = collections.Counter(), collections.Counter()
    names = {}
    for f in findings:
        sc, _victim = match(f, pack)
        (tp if sc else fp)[f['rule']] += 1
        names.setdefault(f['rule'], f['name'])
    eligible = [(count, rule) for rule, count in fp.items() if not tp[rule]]
    eligible.sort(key=lambda item: (-item[0], item[1]))
    chosen = eligible[:budget]
    protected = sorted(rule for rule in fp if tp[rule])
    return {
        'schema': 'netwatch-bench/tuning/v0',
        'budget': budget,
        'rules': [rule for _count, rule in chosen],
        'detail': [{'rule': rule, 'name': names[rule], 'false_alerts': count}
                   for count, rule in chosen],
        'false_alerts_removed_on_tuning_pack': sum(c for c, _r in chosen),
        'false_alerts_on_tuning_pack': sum(fp.values()),
        'protected_rules': protected,
    }


def from_run(run_dir, budget):
    with open(os.path.join(run_dir, 'scorecard.json'), encoding='utf-8') as fh:
        card = json.load(fh)
    pack = load(card['manifest']['pack']['path'])
    findings = list(read_jsonl(os.path.join(run_dir, 'findings.jsonl')))
    result = suppressions(pack, findings, budget)
    result['tuned_on'] = {'pack': pack.id,
                          'pack_sha256': card['manifest']['pack']['sha256'],
                          'engine': card['manifest']['engine']}
    return result


def load_rules(path):
    """Rule ids from a tuning file (JSON) or a plain list, one per line."""
    with open(path, encoding='utf-8') as fh:
        text = fh.read()
    if text.lstrip().startswith('{'):
        return list(json.loads(text)['rules'])
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.startswith('#')]
