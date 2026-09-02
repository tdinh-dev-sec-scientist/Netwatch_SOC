"""Sustained-load soak test for the NetWatch pipeline.

Drives generated wire-format frames through parse -> detect -> batched SQLite
persistence at full speed for a fixed wall-clock duration, and reports, per
minute: throughput, parse failures, resident memory, and detector state size.

Drop accounting is exact and end-to-end:
    frames offered == packets parsed == rows persisted in `packets`
Any inequality is a dropped frame.

    python soak.py --minutes 10 --db /path/soak.db
"""
import argparse, os, resource, sqlite3, statistics, sys, time
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)
import config as config_module
from DB_Manager import DatabaseManager
from PacketSimulator import PacketSimulator, TrafficGenerator
from ProtocolAnalyzer import ProtocolAnalyzer
from ThreatDetector import ThreatDetector

SCENARIOS = ['port_scan', 'network_recon', 'brute_force', 'credential_stuffing',
             'c2_beacon', 'dns_tunnel', 'dga_lookups', 'icmp_tunnel',
             'protocol_tunnel', 'lateral_movement', 'syn_flood', 'udp_flood',
             'ntp_amplification', 'http_attack', 'arp_spoof', 'tls_anomaly',
             'icmp_sweep']

def rss_mb():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0

def detector_state_size(engine):
    total = 0
    for d in getattr(engine, 'detectors', []) or []:
        for v in vars(d).values():
            if isinstance(v, dict):
                total += len(v)
                for inner in v.values():
                    if hasattr(inner, '__len__'):
                        try: total += len(inner)
                        except Exception: pass
    return total

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--minutes', type=float, default=10.0)
    ap.add_argument('--db', required=True)
    ap.add_argument('--seed', type=int, default=1337)
    args = ap.parse_args()

    for suf in ('', '-wal', '-shm'):
        if os.path.exists(args.db + suf):
            os.remove(args.db + suf)

    db = DatabaseManager(args.db)
    engine = ThreatDetector(db, cfg=config_module.load())
    analyzer = ProtocolAnalyzer()
    sim = PacketSimulator(db, engine, analyzer)
    gen = TrafficGenerator(args.seed)

    duration = args.minutes * 60.0
    started = time.perf_counter()
    now_ts = time.time()
    offered = 0
    minute_marks = []
    last_mark = started
    last_offered = 0
    pending = []
    next_scenario = started + 30.0

    print('soak: %.0f minutes, db=%s, seed=%d' % (args.minutes, args.db, args.seed))
    print('%6s %14s %12s %12s %10s %12s' %
          ('min', 'packets', 'pkt/s', 'parse_err', 'rss_mb', 'state_keys'))

    while True:
        elapsed = time.perf_counter() - started
        if elapsed >= duration:
            break
        # inject a real attack scenario roughly every 30s of wall clock
        if elapsed >= next_scenario - started and not pending:
            name = gen.rng.choice(SCENARIOS)
            raw = gen.scenario(name, start_ts=now_ts)
            pending = [fr for _t, fr in raw]
            next_scenario += 30.0
        for _ in range(200):                    # work chunk between clock reads
            if pending:
                frame = pending.pop(0)
            else:
                frame = gen.background_frame(now_ts)
            now_ts += 0.001
            offered += 1
            sim.process(frame, now_ts)
            sim.maybe_flush()
        mark_elapsed = time.perf_counter() - last_mark
        if mark_elapsed >= 60.0:
            n = offered - last_offered
            minute_marks.append(n / mark_elapsed)
            print('%6d %14d %12.1f %12d %10.1f %12d' % (
                len(minute_marks), offered, n / mark_elapsed,
                analyzer.parse_errors, rss_mb(), detector_state_size(engine)))
            last_mark = time.perf_counter()
            last_offered = offered

    sim.flush()
    total_elapsed = time.perf_counter() - started

    persisted = db.reader().execute('SELECT COUNT(*) FROM packets').fetchone()[0]
    alerts = db.reader().execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
    conns = db.reader().execute('SELECT COUNT(*) FROM connections').fetchone()[0]
    db_bytes = os.path.getsize(args.db)

    print('\n── soak result ──────────────────────────────────────────')
    print('  wall clock         : %.1f s (%.2f min)' % (total_elapsed, total_elapsed/60))
    print('  frames offered     : %d' % offered)
    print('  packets parsed     : %d' % sim.packets_processed)
    print('  parse failures     : %d' % analyzer.parse_errors)
    print('  rows persisted     : %d' % persisted)
    print('  DROPPED FRAMES     : %d  (offered - persisted)' % (offered - persisted))
    print('  alerts generated   : %d' % alerts)
    print('  connections tracked: %d' % conns)
    print('  mean throughput    : %.1f pkt/s (%.0f pkt/min)' %
          (offered/total_elapsed, offered/total_elapsed*60))
    if minute_marks:
        print('  per-minute pkt/s   : min %.1f  median %.1f  max %.1f  stdev %.1f' % (
            min(minute_marks), statistics.median(minute_marks), max(minute_marks),
            statistics.pstdev(minute_marks) if len(minute_marks) > 1 else 0.0))
        first, last = minute_marks[0], minute_marks[-1]
        print('  throughput drift   : first minute %.1f -> last minute %.1f (%+.1f%%)' % (
            first, last, (last-first)/first*100))
    print('  peak RSS           : %.1f MB' % rss_mb())
    print('  db size            : %.1f MB' % (db_bytes/1024/1024))

if __name__ == '__main__':
    main()
