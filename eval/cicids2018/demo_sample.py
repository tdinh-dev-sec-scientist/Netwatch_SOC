"""
Build the public demo's traffic: a short, real capture stitched from
CSE-CIC-IDS2018.

    python eval/cicids2018/demo_sample.py --data data/cicids2018 \\
        --out demo/cicids2018-sample.pcap.gz

The demo used to run on synthetic traffic only. This cuts a few seconds to a
few minutes out of real captures — each one an attack NetWatch detects — and
lays them over 45 minutes of a real workstation's benign traffic, on one
timeline. App.py replays it in a loop when NETWATCH_REPLAY_PCAP points at it,
so every alert on the demo comes from real packets.

Packets are truncated to SNAPLEN bytes: enough for every header and the start
of every payload the analyzer decodes, at a fraction of the size. Byte-volume
detectors (data_exfil) see less volume than on the full capture.

Source: CSE-CIC-IDS2018, Canadian Institute for Cybersecurity and the
Communications Security Establishment. Sharaf, Habibi Lashkari and Ghorbani,
"Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic
Characterization", ICISSP 2018.
"""

import argparse
import datetime as dt
import gzip
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, HERE)

from fetch import member_filename  # noqa: E402
from replay import read_pcap  # noqa: E402

SNAPLEN = 256
TIMELINE_MIN = 45

# (day, zip member, slice start UTC, seconds, minute it starts in the demo,
#  what it shows). The benign backdrop runs the whole timeline.
BACKDROP = ('Friday-02-03-2018', 'pcap/capEC2AMAZ-O4EL3NG-172.31.69.13',
            '2018-03-02T13:30:00')
SLICES = [
    ('Thursday-22-02-2018', 'pcap/UCAP172.31.69.28',
     '2018-02-22T17:45:00', 300, 2, 'XSS against DVWA'),
    ('Friday-02-03-2018', 'pcap/capEC2AMAZ-O4EL3NG-172.31.69.10',
     '2018-03-02T14:45:00', 720, 6, 'Ares botnet polling its C2'),
    ('Thursday-15-02-2018', 'pcap/UCAP172.31.69.25',
     '2018-02-15T15:05:00', 30, 12, 'Slowloris'),
    ('Wednesday-14-02-2018', 'pcap/UCAP172.31.69.25',
     '2018-02-14T18:10:00', 15, 16, 'SSH brute force'),
    ('Thursday-22-02-2018', 'pcap/UCAP172.31.69.28',
     '2018-02-22T14:20:00', 240, 20, 'Login-form brute force'),
    ('Wednesday-28-02-2018', 'pcap/capEC2AMAZ-O4EL3NG-172.31.69.24-part2',
     '2018-02-28T17:45:00', 90, 26, 'Nmap from an infiltrated workstation'),
    ('Thursday-22-02-2018', 'pcap/UCAP172.31.69.28',
     '2018-02-22T20:15:00', 420, 30, 'SQL injection'),
    ('Thursday-15-02-2018', 'pcap/UCAP172.31.69.25',
     '2018-02-15T13:30:00', 30, 36, 'GoldenEye HTTP flood'),
    ('Friday-02-03-2018', 'pcap/capEC2AMAZ-O4EL3NG-172.31.69.9',
     '2018-03-02T19:34:00', 240, 39, 'Internet RDP credential stuffing '
     '(real, unlabelled by the dataset)'),
]


def _epoch(text):
    return dt.datetime.fromisoformat(text).replace(
        tzinfo=dt.timezone.utc).timestamp()


def cut(path, start, seconds, offset):
    """Frames in [start, start+seconds), re-timed to begin at `offset`."""
    end = start + seconds
    for ts, frame in read_pcap(path):
        if ts < start:
            continue
        if ts >= end:
            return
        yield offset + (ts - start), frame


def build(data_dir):
    frames = []
    day, member, start = BACKDROP
    frames.extend(cut(os.path.join(data_dir, member_filename(day, member)),
                      _epoch(start), TIMELINE_MIN * 60, 0.0))
    for day, member, start, seconds, at_min, _what in SLICES:
        path = os.path.join(data_dir, member_filename(day, member))
        frames.extend(cut(path, _epoch(start), seconds, at_min * 60.0))
    frames.sort(key=lambda pair: pair[0])
    return frames


def write(frames, out):
    """Classic pcap, microsecond resolution, gzip-compressed."""
    base = 1_500_000_000          # arbitrary epoch; the replay rebases it
    with gzip.open(out, 'wb', compresslevel=9) as fh:
        fh.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, SNAPLEN, 1))
        for ts, frame in frames:
            stamp = base + ts
            sec = int(stamp)
            usec = int(round((stamp - sec) * 1e6))
            if usec == 1_000_000:
                sec, usec = sec + 1, 0
            data = frame[:SNAPLEN]
            fh.write(struct.pack('<IIII', sec, usec, len(data), len(frame)))
            fh.write(data)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--data', required=True, help='directory fetch.py wrote')
    ap.add_argument('--out', required=True)
    args = ap.parse_args(argv)
    frames = build(args.data)
    write(frames, args.out)
    print('%d frames over %d minutes -> %s (%.1f MB)'
          % (len(frames), TIMELINE_MIN, args.out,
             os.path.getsize(args.out) / 1e6))
    return 0


if __name__ == '__main__':
    sys.exit(main())
