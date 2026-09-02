"""A/B: API query latency with the designed indexes vs. without them.

Drops the indexes AFTER DatabaseManager has run its schema DDL (init_schema
re-creates them with CREATE INDEX IF NOT EXISTS, so dropping before init is a
no-op), then re-times every API-backing query on the same rows.
"""
import argparse
import os
import shutil
import sys

INVOCATION_DIR = os.getcwd()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)
from DB_Manager import DatabaseManager
from benchmark import run_query_latency, summarize

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--db', required=True,
                help='populated database, e.g. from: '
                     'python benchmark.py --iterations 10 --packets 30000 '
                     '--db scale.db --keep-db')
ap.add_argument('--repeats', type=int, default=30)
args = ap.parse_args()
SRC = os.path.join(INVOCATION_DIR, args.db)   # --db is relative to where you ran this
S = os.path.dirname(SRC) or '.'
REPEATS = args.repeats

def fresh(path):
    for suf in ('', '-wal', '-shm'):
        if os.path.exists(path+suf): os.remove(path+suf)
    shutil.copy(SRC, path)
    return DatabaseManager(path)

def drop_indexes(db):
    names = [r[0] for r in db._write_conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'")]
    for n in names:
        db._write_conn.execute('DROP INDEX %s' % n)
    db._write_conn.commit()
    db._write_conn.execute('ANALYZE'); db._write_conn.commit()
    # force a brand-new reader so no cached plan survives
    db._local.conn = None
    return names

a = fresh(os.path.join(S, 'ab_indexed.db'))
counts = {t: a.reader().execute('SELECT COUNT(*) FROM %s' % t).fetchone()[0]
          for t in ('packets','connections','hosts','alerts','mitre_techniques',
                    'alert_techniques','protocol_stats','performance_metrics')}
n_idx = a.reader().execute("SELECT COUNT(*) FROM sqlite_master WHERE type='index' "
                           "AND name NOT LIKE 'sqlite_%'").fetchone()[0]
print('dataset rows      :', counts)
print('total rows        :', sum(counts.values()))
print('explicit indexes  :', n_idx)

per_a, all_a = run_query_latency(a, REPEATS)

b = fresh(os.path.join(S, 'ab_noindex.db'))
dropped = drop_indexes(b)
left = b.reader().execute("SELECT COUNT(*) FROM sqlite_master WHERE type='index' "
                          "AND name NOT LIKE 'sqlite_%'").fetchone()[0]
print('dropped %d indexes; %d explicit indexes remain' % (len(dropped), left))
per_b, all_b = run_query_latency(b, REPEATS)

sa, sb = summarize(all_a), summarize(all_b)
print('\n%-28s %10s %10s %10s' % ('AGGREGATE (22 queries)', 'indexed', 'no-index', 'factor'))
for k in ('p50_ms','p95_ms','p99_ms','max_ms'):
    print('%-28s %10.3f %10.3f %9.1fx' % (k, sa[k], sb[k], sb[k]/max(sa[k],1e-9)))

print('\n%-28s %10s %10s %8s' % ('PER QUERY (p95 ms)', 'indexed', 'no-index', 'factor'))
for n in sorted(per_b, key=lambda n: -per_b[n]['p95_ms']):
    ia, ib = per_a[n]['p95_ms'], per_b[n]['p95_ms']
    print('%-28s %10.3f %10.3f %7.1fx' % (n, ia, ib, ib/max(ia,1e-9)))
