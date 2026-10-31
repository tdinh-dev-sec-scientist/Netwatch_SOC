# Metric contract

What every number in a NetWatch Bench scorecard means. The scorer
(`netwatch_bench/scoring.py`) implements exactly this; if the two disagree,
the code is the bug. Back to [NetWatch Bench](../../netwatch_bench/README.md).

## Units

The unit of comparison is the **scenario unit**: one labelled attack, or one
victim of a `per_victim` attack (a botnet with ten infected hosts is ten
units). Alerts are counted too, but detection is never reported per alert,
because a chatty engine would win by repetition.

## Matching an alert to the ground truth

An alert is a **true positive** for scenario *S* if its timestamp is inside one
of *S*'s windows (inclusive) and either:

1. one end of the alert is an attacker of *S* and the other end is a victim
   of *S*, in either direction; or
2. *S* has a `pivot` (a compromised internal host), the alert goes from the
   pivot to an address inside `internal_networks`, and the alert's
   techniques match *S*'s, or the alert carries no techniques at all.

3. the alert names **only one** address, that address is an attacker of
   *S*, and *S* is not `per_victim`. Aggregate detections ("this host is
   guessing SSH passwords", as Zeek's notices are) name the attacker and
   nothing else. An alert naming only a *victim* is never credited: victims
   receive plenty of unrelated traffic.

Scenarios are tried in pack order; the first match wins. Rule 2 is narrower
than rule 1 on purpose: a compromised workstation keeps its ordinary
traffic, and an unrelated alert on it must not be credited to the attack.
An engine that attributes no techniques gets the benefit of the doubt.

An alert with **no address at all** (an engine's decoder event on a
malformed packet) cannot match anything. It counts as a false positive, and
the report says how many there were.

Every other alert is a **false positive against the labels**. That includes
alerts on real but unlabelled attacks in the background traffic. A pack can
describe those as `annotations`; the report then counts the alerts they
explain, but they **remain false positives**. Annotations explain noise; they
never excuse it.

## Detection and classification

| Metric | Definition |
|---|---|
| **Detected** | At least one true-positive alert matched the unit. |
| **Right technique** | A matched alert carries a technique equal to, or a sub-technique of, one the scenario lists (`T1499.002` satisfies `T1499`; `T1071.004` does not satisfy `T1071.001`). |
| **Not assessable** | The unit was detected, but no matched alert carries any technique. Excluded from the classification rate, rather than counted as wrong. A missed unit counts as wrong. |
| **First alert** | Seconds from the scenario's `onset` (its labelled start; the first window start if omitted) to the first matched alert. Negative if the alert falls in the window's padding before onset. |

Detection rate and classification rate are reported with a **95% Wilson
score interval**, which stays honest at 0/n and n/n, where the usual normal
approximation gives a meaningless zero-width interval.

## Noise

| Metric | Definition |
|---|---|
| **Host-hours** | For each capture: (last packet timestamp − first packet timestamp) × `hosts` (default 1), summed. Measured from the capture files, never from an engine, so every engine on a pack divides by the same exposure. |
| **False alerts per host-hour** | False-positive alerts ÷ host-hours, with an exact 95% Poisson (Garwood) interval. |
| **Incidents** | Alerts on the same unordered pair of hosts, chained while each alert is within 30 minutes of the previous one. Alerts with `group_by: victim` (floods with spoofed sources) are keyed on the destination instead. Correlation runs per capture. |
| **False incidents per host-day** | Incidents containing no true-positive alert ÷ host-hours × 24. |
| **Alert precision** | True-positive alerts ÷ all alerts, with a Wilson interval. Depends on how chatty the engine is, so read it next to the incident numbers. |

## Comparing two runs

`netwatch-bench compare` refuses nothing, but it warns when the two
scorecards come from different packs (by sha256). It reports:

- **detection:** a two-sided Fisher exact test on detected/units;
- **false alerts:** the exact conditional test for two Poisson rates (given
  k₁ + k₂ events, k₁ is binomial with p = t₁ / (t₁ + t₂) under equal rates).

With a handful of scenarios only large differences can be significant.
NetWatch's own headline, 6/6 against Suricata's 3/6, gives p ≈ 0.18: on its
own it does not show that one engine detects more. The 26× difference in
false alerts per host-hour is significant. Report intervals, not just counts.

## Filters

`--min-severity`, `--exclude-name-prefix` and `--exclude-rule` drop alerts
before scoring, which is how the usual first tuning steps (for example,
dropping Suricata's own `SURICATA ` decoder events) are scored. A filter is
recorded in the scorecard's manifest and marks the engine as "(filtered)" in
every report, so a tuned result is never mistaken for the engine as
distributed.

## Equal tuning budget

An engine as distributed against one tuned on the same data is not a fair
fight. `netwatch-bench tune --budget N` gives every engine the same budget
on a development pack: suppress at most *N* rules, chosen by false alerts
raised, **never** a rule that raised a true positive. The suppression list
is then applied, unchanged, to held-out packs that played no part in
choosing it (`score --exclude-rules-file`). The list and the pack it was
tuned on are recorded in the tuning file; the filter is recorded in every
scorecard scored with it.

## The regression gate

`netwatch-bench diff BASELINE CANDIDATE` exits 1 when the candidate:

| Code | Fails when |
|---|---|
| `NWB001` | a unit the baseline detected is missed |
| `NWB002` | a unit the baseline classified correctly is detected with only wrong techniques |
| `NWB003` | false alerts exceed baseline × (1 + `--max-noise-increase`, default 0.10) + `--noise-slack` (default 2) |
| `NWB004` | false alerts per host-hour exceed `--max-false-alerts-per-host-hour` |
| `NWB005` | a rule not in the baseline's top false-positive list raises ≥ 3 (warning; fails with `--fail-on-new-noise`) |
| `NWB006` | the two scorecards come from different packs (unless `--allow-pack-change`) |

Gains never fail the gate. A unit becoming *not assessable* never fails it
either: that is a change in what the engine reports, not in what it detects.
The gate compares two scores on the same pack, so there is no sampling error
to test for: the same traffic and the same engine give the same alerts.

## What these metrics do not measure

- Whether an alert would help an analyst: its text, evidence and severity.
- Throughput or resource cost (see [docs/benchmarks.md](../benchmarks.md) for
  NetWatch's own).
- Anything outside the pack. A score on one lab network is a score on one lab
  network; each pack lists its own limitations, and every report repeats them.
