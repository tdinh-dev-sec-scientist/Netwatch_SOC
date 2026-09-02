"""False-positive control: benign-only traffic across N independent seeds."""
import collections, os, sys, tempfile
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)
import config as config_module
from DB_Manager import DatabaseManager
from ProtocolAnalyzer import ProtocolAnalyzer
from PacketSimulator import TrafficGenerator
from ThreatDetector import ThreatDetector

SEEDS = [1, 7, 42, 99, 1337, 2024, 31337, 65535]
PER_SEED = 25000
path = os.path.join(tempfile.gettempdir(), 'fp_check.db')
for suf in ('', '-wal', '-shm'):
    if os.path.exists(path+suf): os.remove(path+suf)
db = DatabaseManager(path)
total = 0; fired = collections.Counter(); errs = 0
for seed in SEEDS:
    engine = ThreatDetector(db, cfg=config_module.load())   # fresh state per seed
    analyzer = ProtocolAnalyzer()
    gen = TrafficGenerator(seed)
    for ts, frame in gen.background(PER_SEED, start_ts=1_700_000_000.0):
        pkt = analyzer.safe_parse(frame, ts)
        total += 1
        if pkt is not None:
            for f in engine.analyze(pkt):
                fired[f.threat_type] += 1
    errs += analyzer.parse_errors
    print('seed %-6d %6d packets  alerts=%d  parse_errors=%d' % (
        seed, PER_SEED, sum(fired.values()), analyzer.parse_errors))
print('\nbenign packets analysed : %d across %d seeds' % (total, len(SEEDS)))
print('false positives         : %d  %s' % (sum(fired.values()), dict(fired) or ''))
print('parse failures          : %d' % errs)
