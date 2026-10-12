"""
Top external talkers to each host, per UTC hour — the ground-truth check.

    python eval/cicids2018/talkers.py data/cicids2018/Thursday-22-02-2018_UCAP172.31.69.28.pcap

For every hour of the capture, prints the four busiest (source, destination,
transport, service port) tuples. A labelled attacker should dominate its
scenario's window and be absent outside it; that is how each address in
ground_truth.json and holdout.json was confirmed before scoring.
Only connections to service ports (< 1024, plus 3389 and 8080) are counted, so
replies to ephemeral ports do not drown the signal.
"""

import collections
import datetime as dt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from replay import read_pcap  # noqa: E402

SERVICE_PORTS_ABOVE_1024 = {3389, 8080}


def main(paths):
    counts = collections.Counter()
    for path in paths:
        for ts, frame in read_pcap(path):
            if frame[12:14] != b'\x08\x00' or frame[23] not in (6, 17):
                continue
            ihl = (frame[14] & 0x0F) * 4
            dport = int.from_bytes(frame[14 + ihl + 2:14 + ihl + 4], 'big')
            if dport >= 1024 and dport not in SERVICE_PORTS_ABOVE_1024:
                continue
            hour = dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime(
                '%Y-%m-%d %H:00')
            src = '.'.join(map(str, frame[26:30]))
            dst = '.'.join(map(str, frame[30:34]))
            proto = 'tcp' if frame[23] == 6 else 'udp'
            counts[(hour, src, dst, '%s/%d' % (proto, dport))] += 1

    by_hour = collections.defaultdict(list)
    for (hour, *rest), n in counts.items():
        by_hour[hour].append((n, rest))
    for hour in sorted(by_hour):
        top = sorted(by_hour[hour], reverse=True)[:4]
        print(hour, '  '.join('%s>%s %s ×%d' % (s, d, p, n)
                              for n, (s, d, p) in top))
    return 0


if __name__ == '__main__':
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    sys.exit(main(sys.argv[1:]))
