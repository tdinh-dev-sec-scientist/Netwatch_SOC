"""
Export the CSE-CIC-IDS2018 ground truth as engine-neutral NetWatch Bench packs.

    python eval/cicids2018/export_packs.py

The v1 truth files (ground_truth.json, holdout.json, holdout2.json) name the
NetWatch threat types each attack should raise, which only NetWatch can be
scored on. The packs written here keep the addresses, windows and captures
exactly as they are and replace the threat types with the ATT&CK techniques
those types carry, so any engine that attributes techniques is scored against
the same answer key. tests/test_bench_parity.py checks that scoring NetWatch
on a pack gives the same result as the v1 scorer.

Also writes the demo pack, from the slices demo_sample.py stitches into
demo/cicids2018-sample.pcap.gz.
"""

import datetime as dt
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

from demo_sample import SLICES  # noqa: E402
from fetch import member_filename  # noqa: E402

PACKS = os.path.join(ROOT, 'packs')

# The ATT&CK techniques NetWatch's expected threat types carry, per scenario.
# Exact sub-techniques where the v1 key was narrow (the bot: T1071.001, web
# C2 polling, so a DNS-tunnel alert tagged T1071.004 is not credited).
TECHNIQUES = {
    'ftp_bruteforce': ['T1110', 'T1078'],
    'ssh_bruteforce': ['T1110', 'T1078'],
    'web_bruteforce': ['T1110', 'T1078', 'T1190'],
    'web_xss': ['T1190'],
    'web_sqli': ['T1190'],
    'dos_goldeneye': ['T1499'],
    'dos_slowloris': ['T1499'],
    'dos_slowhttptest': ['T1499'],
    'dos_hulk': ['T1499'],
    'infiltration': ['T1046', 'T1595', 'T1021'],
    'bot_ares': ['T1071.001', 'T1041'],
}

PAD_S = 600          # the v1 windows are padded by 10 minutes each side

SOURCE = {
    'name': 'CSE-CIC-IDS2018',
    'publisher': 'Canadian Institute for Cybersecurity (UNB) and the '
                 'Communications Security Establishment',
    'url': 'https://www.unb.ca/cic/datasets/ids-2018.html',
    'license': 'See the dataset page; cite the paper below when using it.',
    'citation': 'Sharaf, Habibi Lashkari and Ghorbani, "Toward Generating a '
                'New Intrusion Detection Dataset and Intrusion Traffic '
                'Characterization", ICISSP 2018.',
}

COMMON_LIMITATIONS = [
    'One 2018 lab network on AWS. A different network would surface '
    'different false positives.',
    'The victims expose RDP and SSH to the internet, so the benign traffic '
    'holds real, unlabelled internet attacks. Alerts on them count as false '
    'positives against the labels.',
    'Published work has found labelling errors in this dataset (Liu et al., '
    '"Error Prevalence in NIDS datasets", IEEE CNS 2022). These windows and '
    'addresses were checked against the captures, but not packet by packet.',
]

SPLITS = [
    ('cicids2018-dev', 'ground_truth.json',
     'CSE-CIC-IDS2018: development set',
     'NetWatch was tuned on these captures. Scores here say how well an '
     'engine fits them, not how well it generalises.'),
    ('cicids2018-holdout', 'holdout.json',
     'CSE-CIC-IDS2018: held-out set 1',
     'Not replayed through NetWatch until its round-1 code was frozen. Same '
     'lab network as the development set.'),
    ('cicids2018-holdout2', 'holdout2.json',
     'CSE-CIC-IDS2018: held-out set 2',
     'Fetched only after NetWatch round 2 was frozen; a host population '
     'used nowhere else. Same lab network.'),
]


def _iso(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime(
        '%Y-%m-%dT%H:%M:%SZ')


def _epoch(text):
    return dt.datetime.fromisoformat(text).replace(
        tzinfo=dt.timezone.utc).timestamp()


def scenario(sc):
    out = {
        'id': sc['id'], 'label': sc['label'],
        'techniques': TECHNIQUES[sc['id']],
        'attackers': sc['attackers'], 'victims': sc['victims'],
    }
    if sc.get('pivot'):
        out['pivot'] = sc['pivot']
    if sc.get('per_victim'):
        out['per_victim'] = True
    out['windows'] = [[a + 'Z', b + 'Z'] for a, b in sc['windows_utc']]
    out['onset'] = _iso(_epoch(sc['windows_utc'][0][0]) + PAD_S)
    return out


def split_pack(pack_id, truth_file, title, split_note):
    with open(os.path.join(HERE, truth_file), encoding='utf-8') as fh:
        truth = json.load(fh)
    return {
        'schema': 'netwatch-bench/pack/v0',
        'id': pack_id,
        'title': title,
        'description': split_note,
        'source': SOURCE,
        'notes': truth['notes'] + [
            'Exported from eval/cicids2018/%s by export_packs.py.' % truth_file,
            'Windows are padded by 10 minutes each side; onset is the '
            'scheduled start of the attack, for detection latency.',
        ],
        'captures': [{
            'id': cap['name'],
            'files': [{'data_path': member_filename(cap['day'], m)}
                      for m in cap['members']],
        } for cap in truth['captures']],
        'scenarios': [scenario(sc) for sc in truth['scenarios']],
        'limitations': [split_note] + COMMON_LIMITATIONS,
    }


# demo_sample.py SLICES, in order, mapped to the development-set scenario
# each one was cut from. The last slice is real but unlabelled by the dataset.
# The XSS slice is left out: it starts at 17:45 UTC, five minutes before the
# attack's onset (17:50), and holds no packets from the attacker at all.
DEMO_EXCLUDED = {
    'web_xss': 'The demo\'s XSS slice (2018-02-22 17:45-17:50 UTC) ends '
               'before the attack starts and contains no attacker packets, '
               'so it is not labelled as an attack here. Rebuilding the demo '
               'with a later slice would restore it.',
}
DEMO_SCENARIOS = ['web_xss', 'bot_ares', 'dos_slowloris', 'ssh_bruteforce',
                  'web_bruteforce', 'infiltration', 'web_sqli',
                  'dos_goldeneye', None]
DEMO_BASE = 1_500_000_000      # demo_sample.write()'s epoch
DEMO_TAIL_S = 60               # alerts may close a window just after a slice
# Found with the packets themselves: the top external talkers to the RDP
# host's 3389 inside that slice.
DEMO_RDP_SOURCES = ['193.111.198.61', '5.101.40.105', '212.92.117.95',
                    '87.230.72.8']


def demo_pack():
    with open(os.path.join(HERE, 'ground_truth.json'), encoding='utf-8') as fh:
        dev = {sc['id']: sc for sc in json.load(fh)['scenarios']}
    scenarios, annotations = [], []
    for (day, member, _start, seconds, at_min, what), sid in zip(
            SLICES, DEMO_SCENARIOS):
        start = DEMO_BASE + at_min * 60
        window = [_iso(start), _iso(start + seconds + DEMO_TAIL_S)]
        if sid is None:
            annotations.append({
                'id': 'rdp_credential_stuffing', 'label': what,
                'techniques': ['T1110'], 'attackers': DEMO_RDP_SOURCES,
                'victims': ['172.31.69.9'], 'windows': [window],
                'notes': 'Real internet attack on an exposed RDP host. The '
                         'dataset does not label it, so it is not scored.',
            })
            continue
        if sid in DEMO_EXCLUDED:
            continue
        sc = dev[sid]
        victims = sc['victims']
        if sid == 'bot_ares':
            # Only one bot victim's capture is in the demo.
            victims = [member.rsplit('-', 1)[-1]]
        entry = {'id': sid, 'label': what, 'techniques': TECHNIQUES[sid],
                 'attackers': sc['attackers'], 'victims': victims}
        if sc.get('pivot'):
            entry['pivot'] = sc['pivot']
        entry['windows'] = [window]
        entry['onset'] = window[0]
        scenarios.append(entry)
    return {
        'schema': 'netwatch-bench/pack/v0',
        'id': 'cicids2018-demo',
        'title': 'CSE-CIC-IDS2018 demo (45 minutes, 7 attacks)',
        'description': 'Seven labelled attacks cut from CSE-CIC-IDS2018 and '
                       'laid over 45 minutes of a real workstation\'s benign '
                       'traffic. Ships in the repository: no download needed.',
        'source': SOURCE,
        'notes': [
            'Built by eval/cicids2018/demo_sample.py; exported by '
            'export_packs.py. Times are on the demo\'s rebased clock.',
            'Packets are truncated to 256 bytes (headers and the start of '
            'each payload), so byte-volume signals are weaker than on the '
            'full captures.',
        ] + list(DEMO_EXCLUDED.values()),
        'captures': [{
            'id': 'demo',
            'files': [{'path': '../../demo/cicids2018-sample.pcap.gz'}],
        }],
        'scenarios': scenarios,
        'annotations': annotations,
        'limitations': [
            'A smoke test, not evidence: every slice comes from the '
            'development set NetWatch was tuned on, and each was chosen '
            'because NetWatch detects it.',
            'Each attack is a short slice (15 s to 12 min) of a longer '
            'attack, on one 45-minute timeline.',
            'The stitched timeline counts as one host, so per-host-hour '
            'rates on this pack are not comparable with the full packs.',
            'Not a fair test of signature engines: packets are truncated to '
            '256 bytes and slices from different captures are stitched '
            'together, so payload signatures cannot match and stream '
            'reassembly breaks. Suricata on this pack fires mostly engine '
            'anomaly events (checksums, stream state). Compare engines on '
            'the full packs.',
        ] + COMMON_LIMITATIONS[:1],
    }


def write(pack):
    import yaml
    directory = os.path.join(PACKS, pack['id'])
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, 'pack.yaml')
    header = ('# Generated by eval/cicids2018/export_packs.py; edit that, '
              'not this.\n# Format: docs/bench/pack-format.md\n')
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(header + yaml.safe_dump(pack, sort_keys=False, width=79,
                                         allow_unicode=True))
    return path


def main():
    paths = [write(demo_pack())]
    paths += [write(split_pack(*split)) for split in SPLITS]
    for path in paths:
        print(os.path.relpath(path, ROOT))
    return 0


if __name__ == '__main__':
    sys.exit(main())
