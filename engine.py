"""
Headless capture/detection engine.

Runs the pipeline — frames -> ProtocolAnalyzer -> ThreatDetector -> PostgreSQL
— with no HTTP server attached. This is the writer half of the split deployment
topology: one engine process owns traffic generation and writes, while any
number of API containers serve reads from the same PostgreSQL database. With
PostgreSQL they no longer need to share a filesystem, only a connection string.

    DATABASE_URL=postgresql://netwatch:...@postgres:5432/netwatch python engine.py

Environment:
    DATABASE_URL       PostgreSQL connection string (see db_backends.py for
                       the PG_* fallbacks and the SQLite dev option)
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
import db_backends
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
    try:
        db = DatabaseManager()
    except db_backends.ConfigError as exc:
        raise SystemExit('database configuration error: %s' % exc)
    detector = ThreatDetector(db, cfg=cfg)
    simulator = PacketSimulator(db, detector, ProtocolAnalyzer(), cfg=cfg)

    log.info('engine ready: detectors=%d techniques=%d backend=%s db=%s',
             len(detector.detectors), len(detector.techniques_covered()),
             db.backend_name, db.display)

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
