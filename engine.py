"""
Headless capture/detection engine.

Runs the pipeline — frames -> ProtocolAnalyzer -> ThreatDetector -> SQLite —
with no HTTP server attached. This is the writer half of the split deployment
topology: one engine process owns the database, while any number of read-only
API containers serve queries from the same file over SQLite WAL.

    NETWATCH_DB=/data/netwatch.db python engine.py

Environment:
    NETWATCH_DB        database path (default: ./netwatch.db)
    NETWATCH_CONFIG    JSON threshold overrides
    NETWATCH_RATE_PPS  packets per second to generate (default: 95)
    NETWATCH_DURATION  seconds to run, then exit (default: run forever)

Terminates cleanly on SIGTERM/SIGINT: the engine stops, the buffered batch is
flushed, and the database is closed before the process exits — so `docker stop`
does not discard in-flight packets.
"""

import logging
import os
import signal
import sys

import config as config_module
from DB_Manager import DatabaseManager
from PacketSimulator import PacketSimulator
from ProtocolAnalyzer import ProtocolAnalyzer
from ThreatDetector import ThreatDetector

log = logging.getLogger('netwatch.engine')


def _float_env(name, default):
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        raise SystemExit('%s must be numeric, got %r' % (name, raw))


def main():
    logging.basicConfig(
        level=os.environ.get('NETWATCH_LOGLEVEL', 'INFO').upper(),
        format='%(asctime)s %(levelname)s %(name)s: %(message)s',
        stream=sys.stdout)

    cfg = config_module.load()
    db = DatabaseManager()
    detector = ThreatDetector(db, cfg=cfg)
    simulator = PacketSimulator(db, detector, ProtocolAnalyzer(), cfg=cfg)

    log.info('engine ready: detectors=%d techniques=%d db=%s',
             len(detector.detectors), len(detector.techniques_covered()),
             db.db_path)

    def shutdown(signum, _frame):
        # Ask the loop to stop; run() flushes its final batch on the way out.
        log.info('signal %s received, draining', signal.Signals(signum).name)
        simulator.stop()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    duration = _float_env('NETWATCH_DURATION', 0) or None
    try:
        simulator.run(rate_pps=_float_env('NETWATCH_RATE_PPS', 95.0),
                      duration_s=duration)
    finally:
        simulator.flush()
        stats = simulator.stats()
        log.info('engine stopped: packets=%d alerts=%d parse_errors=%d',
                 stats['packets_processed'], stats['alerts_generated'],
                 stats['parse_errors'])
        db.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
