"""
Build the PCAP corpora the validation suite replays.

    python -m tools.make_pcaps                 # write pcaps/ + manifest.json
    python -m tools.make_pcaps --check         # verify existing files match

Two corpora are produced, both as real libpcap files written through Scapy:

  pcaps/attack/<scenario>.pcap
      One attack scenario embedded in benign background traffic of the same
      duration — the shape a real capture has. Ground truth is the threat
      type(s) the scenario is defined to produce; anything else the engine
      raises on that file is a false positive.

  pcaps/evasion/<scenario>.pcap
      The same attacks shaped to sit near or under a tuned threshold: a scan
      paced across windows, a beacon with human-scale jitter, a tunnel split
      across short labels, exfiltration spread over several peers. Ground
      truth is what the traffic *is*, not what the thresholds catch, so a miss
      here is a real false negative and is reported as one.

  pcaps/benign/baseline-<seed>.pcap
      Background traffic only, from independent seeds. Ground truth is *no
      alerts*; every alert raised is a false positive.

Traffic is synthetic but the frames are not: `frames.py` emits wire-format
Ethernet with correct IPv4/TCP/UDP/ICMP checksums and conformant L7 encodings,
and the analyzer decodes them with no knowledge of their origin. What is
modelled — rather than captured — is the *traffic mix*. docs/VALIDATION.md
says so plainly; nothing here is presented as a capture of a real network.

Generation is seeded, so re-running reproduces byte-identical files. The
manifest records a SHA-256 per file so a replay run can prove which bytes it
scored.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pcap_io                                        # noqa: E402
from PacketSimulator import TrafficGenerator          # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP_DIR = os.path.join(ROOT, 'pcaps')
MANIFEST = os.path.join(PCAP_DIR, 'manifest.json')

# A fixed epoch keeps the corpus reproducible. Replay re-bases timestamps onto
# the present so the API's time-windowed queries still see the traffic.
BASE_TS = 1_700_000_000.0

# Seeds for the pure-benign corpus. Independent seeds, so a false positive that
# only one traffic sample happens to provoke still shows up.
BENIGN_SEEDS = (11, 22, 33, 44, 55, 66)
BENIGN_PACKETS = 20_000

# Benign packets mixed around each attack, so detectors face the same
# background noise they would in production rather than a sterile capture.
ATTACK_BACKGROUND_PACKETS = 1_500


def build_attack(scenario, seed):
    """Attack scenario interleaved with benign background of the same span."""
    gen = TrafficGenerator(seed=seed)
    background = gen.background(ATTACK_BACKGROUND_PACKETS, start_ts=BASE_TS)
    span = background[-1][0] - background[0][0]
    # Start the attack a quarter of the way in so there is clean traffic on
    # both sides of it.
    attack = gen.scenario(scenario, start_ts=BASE_TS + span * 0.25)
    frames = background + attack
    frames.sort(key=lambda pair: pair[0])
    return frames


def build_benign(seed, packets=BENIGN_PACKETS):
    return TrafficGenerator(seed=seed).background(packets, start_ts=BASE_TS)


def generate(out_dir=PCAP_DIR):
    """Write every capture and return the manifest structure."""
    entries = []

    for index, name in enumerate(sorted(TrafficGenerator.ALL_SCENARIOS)):
        kind = TrafficGenerator.scenario_class(name)
        path = os.path.join(out_dir, kind, '%s.pcap' % name)
        pcap_io.write_pcap(path, build_attack(name, seed=1000 + index))
        summary = pcap_io.pcap_summary(path)
        entries.append({
            'file': os.path.relpath(path, out_dir),
            'class': kind,
            'scenario': name,
            'expected_threats': list(TrafficGenerator.expected_threats(name)),
            'seed': 1000 + index,
            'packets': summary['packets'],
            'duration_s': summary['duration_s'],
            'file_bytes': summary['file_bytes'],
            'sha256': summary['sha256'],
        })

    benign_dir = os.path.join(out_dir, 'benign')
    for seed in BENIGN_SEEDS:
        path = os.path.join(benign_dir, 'baseline-%d.pcap' % seed)
        pcap_io.write_pcap(path, build_benign(seed))
        summary = pcap_io.pcap_summary(path)
        entries.append({
            'file': os.path.relpath(path, out_dir),
            'class': 'benign',
            'scenario': None,
            'expected_threats': [],
            'seed': seed,
            'packets': summary['packets'],
            'duration_s': summary['duration_s'],
            'file_bytes': summary['file_bytes'],
            'sha256': summary['sha256'],
        })

    return {
        'base_ts': BASE_TS,
        'generator': 'frames.py wire-format synthesis via TrafficGenerator',
        'writer': 'scapy %s' % pcap_io.scapy_version(),
        'attack_background_packets': ATTACK_BACKGROUND_PACKETS,
        'benign_packets_per_file': BENIGN_PACKETS,
        'totals': {
            'files': len(entries),
            'attack_files': sum(1 for e in entries if e['class'] == 'attack'),
            'evasion_files': sum(1 for e in entries
                                 if e['class'] == 'evasion'),
            'benign_files': sum(1 for e in entries if e['class'] == 'benign'),
            'packets': sum(e['packets'] for e in entries),
        },
        'captures': entries,
    }


def load_manifest(path=MANIFEST):
    with open(path, 'r', encoding='utf-8') as fh:
        return json.load(fh)


def captures(manifest=None, kind=None, root=PCAP_DIR):
    """Manifest entries with an absolute `path` attached."""
    manifest = manifest or load_manifest()
    out = []
    for entry in manifest['captures']:
        if kind and entry['class'] != kind:
            continue
        item = dict(entry)
        item['path'] = os.path.join(root, entry['file'])
        out.append(item)
    return out


def check(out_dir=PCAP_DIR):
    """Verify every file in the manifest exists with the recorded digest."""
    manifest = load_manifest(os.path.join(out_dir, 'manifest.json'))
    problems = []
    for entry in manifest['captures']:
        path = os.path.join(out_dir, entry['file'])
        if not os.path.exists(path):
            problems.append('%s is missing' % entry['file'])
            continue
        actual = pcap_io.pcap_summary(path)
        if actual['sha256'] != entry['sha256']:
            problems.append('%s digest changed' % entry['file'])
        elif actual['packets'] != entry['packets']:
            problems.append('%s packet count changed' % entry['file'])
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    parser.add_argument('--out', default=PCAP_DIR)
    parser.add_argument('--check', action='store_true',
                        help='verify the existing corpus instead of rebuilding')
    args = parser.parse_args(argv)

    if args.check:
        problems = check(args.out)
        for problem in problems:
            print('FAIL %s' % problem)
        if not problems:
            print('corpus matches manifest')
        return 1 if problems else 0

    manifest = generate(args.out)
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, 'manifest.json'), 'w',
              encoding='utf-8') as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write('\n')

    totals = manifest['totals']
    print('wrote %d captures (%d attack, %d evasion, %d benign), '
          '%d packets total'
          % (totals['files'], totals['attack_files'], totals['evasion_files'],
             totals['benign_files'], totals['packets']))
    for entry in manifest['captures']:
        print('  %-40s %7d packets  %8.1fs  %s'
              % (entry['file'], entry['packets'], entry['duration_s'],
                 entry['class']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
