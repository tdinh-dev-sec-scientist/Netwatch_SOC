"""
Offline pcap replay: run a capture file through the real detection pipeline.

    python replay.py capture.pcap --alerts alerts.jsonl
    python replay.py a.pcap b.pcap --config thresholds.json --summary run.json

Every frame goes through the same `ProtocolAnalyzer.safe_parse` ->
`ThreatDetector.analyze` path as live traffic, stamped with its capture
timestamp, so every sliding window and cooldown runs on the clock of the
capture rather than on wall time. Nothing is written to a database; findings
are emitted as JSON lines, one per alert, for scoring against a dataset's
ground truth (see `eval/`).

With `--persist` the run also goes into the database named by DATABASE_URL
(PostgreSQL by default) through `PacketSimulator.process` and
`DatabaseManager.persist_batch` — the same batched transactions as live
capture — so the API and dashboard serve the real capture. The dashboard's
queries are relative to now, so pair it with `--rebase-now`, which shifts
every timestamp so the capture ends at the moment the replay starts:

    DATABASE_URL=postgresql://netwatch:netwatch@localhost:5432/netwatch \
        python replay.py capture.pcap --persist --rebase-now

Reads classic libpcap files (either byte order, micro- or nanosecond
resolution) with Ethernet or Linux cooked (SLL) link layers. pcapng is
rejected with a message — convert it with `editcap -F pcap`.
Standard library only, like the rest of the capture path.
"""

import argparse
import json
import struct
import sys
import time

import config as config_module
from ProtocolAnalyzer import ProtocolAnalyzer
from ThreatDetector import ThreatDetector

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113

_MAGIC = {
    b'\xd4\xc3\xb2\xa1': ('<', 1e-6),
    b'\xa1\xb2\xc3\xd4': ('>', 1e-6),
    b'\x4d\x3c\xb2\xa1': ('<', 1e-9),
    b'\xa1\xb2\x3c\x4d': ('>', 1e-9),
}
_FAKE_MACS = b'\x00\x00\x00\x00\x00\x00' * 2


def read_pcap(path):
    """Yield (timestamp, ethernet_frame_bytes) for every record in a pcap."""
    with open(path, 'rb') as fh:
        header = fh.read(24)
        if len(header) < 24:
            raise ValueError('%s: not a pcap file (too short)' % path)
        if header[:4] == b'\x0a\x0d\x0d\x0a':
            raise ValueError('%s: pcapng is not supported; convert with '
                             '`editcap -F pcap`' % path)
        try:
            endian, resolution = _MAGIC[header[:4]]
        except KeyError:
            raise ValueError('%s: unrecognised pcap magic' % path)
        linktype = struct.unpack(endian + 'I', header[20:24])[0] & 0x0FFFFFFF
        if linktype not in (LINKTYPE_ETHERNET, LINKTYPE_RAW,
                            LINKTYPE_LINUX_SLL):
            raise ValueError('%s: unsupported link type %d'
                             % (path, linktype))
        rec = struct.Struct(endian + 'IIII')
        while True:
            head = fh.read(16)
            if len(head) < 16:
                return
            sec, frac, incl, _orig = rec.unpack(head)
            data = fh.read(incl)
            if len(data) < incl:
                return  # truncated final record
            ts = sec + frac * resolution
            if linktype == LINKTYPE_ETHERNET:
                yield ts, data
            elif linktype == LINKTYPE_LINUX_SLL:
                # 16-byte cooked header; the protocol type is its last field.
                yield ts, _FAKE_MACS + data[14:16] + data[16:]
            else:
                version = data[0] >> 4 if data else 0
                ethertype = b'\x86\xdd' if version == 6 else b'\x08\x00'
                yield ts, _FAKE_MACS + ethertype + data


def last_timestamp(path):
    """Timestamp of the final record, found by skipping over packet data."""
    last = None
    with open(path, 'rb') as fh:
        header = fh.read(24)
        endian, resolution = _MAGIC.get(header[:4], (None, None))
        if endian is None:
            raise ValueError('%s: not a classic pcap file' % path)
        rec = struct.Struct(endian + 'IIII')
        while True:
            head = fh.read(16)
            if len(head) < 16:
                return last
            sec, frac, incl, _orig = rec.unpack(head)
            fh.seek(incl, 1)
            last = sec + frac * resolution


def finding_record(f, source):
    return {
        'ts': f.ts, 'threat_type': f.threat_type, 'detector': f.detector,
        'severity': f.severity, 'confidence': f.confidence,
        'src_ip': f.src_ip, 'dst_ip': f.dst_ip,
        'src_port': f.src_port, 'dst_port': f.dst_port,
        'protocol': f.protocol, 'techniques': list(f.techniques),
        'reason': f.reason, 'evidence': f.evidence,
        'incident_key': list(f.incident_key) if f.incident_key else None,
        'source': source,
    }


def replay(paths, cfg=None, on_finding=None, progress_every=0, db=None,
           shift_s=0.0):
    """Run every pcap in `paths`, in order, through one detector instance.

    Files are treated as one continuous capture, so pass them in time order.
    Returns a summary dict; each finding is handed to `on_finding(record)`.
    With `db` (a DatabaseManager) packets and alerts are also persisted, in
    the live pipeline's batches. `shift_s` is added to every timestamp.
    """
    cfg = cfg or config_module.load()
    analyzer = ProtocolAnalyzer()
    detector = ThreatDetector(db, cfg=cfg)
    simulator = None
    if db is not None:
        from PacketSimulator import PacketSimulator
        simulator = PacketSimulator(db, detector, analyzer, cfg=cfg)
    packets = parsed = findings = 0
    first_ts = last_ts = None
    by_type = {}
    started = time.perf_counter()

    for path in paths:
        for ts, frame in read_pcap(path):
            ts += shift_s
            packets += 1
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            if simulator is not None:
                before = simulator.packets_processed
                new = simulator.process(frame, ts)
                simulator.maybe_flush()
                if simulator.packets_processed == before:
                    continue
            else:
                pkt = analyzer.safe_parse(frame, ts)
                if pkt is None:
                    continue
                new = detector.analyze(pkt)
            parsed += 1
            for f in new:
                findings += 1
                by_type[f.threat_type] = by_type.get(f.threat_type, 0) + 1
                if on_finding:
                    on_finding(finding_record(f, path))
            if progress_every and packets % progress_every == 0:
                print('  %d packets, %d alerts, %.0f pkt/s'
                      % (packets, findings,
                         packets / (time.perf_counter() - started)),
                      file=sys.stderr, flush=True)

    if simulator is not None:
        simulator.flush()
    elapsed = time.perf_counter() - started
    if simulator is not None and elapsed > 0:
        simulator._record_window(elapsed, simulator.packets_processed,
                                 simulator.alerts_generated)
    return {
        'files': list(paths),
        'packets': packets,
        'parsed': parsed,
        'parse_errors': analyzer.parse_errors,
        'detector_errors': detector.detector_errors,
        'capture_start': first_ts,
        'capture_end': last_ts,
        'capture_hours': ((last_ts - first_ts) / 3600.0) if packets else 0.0,
        'alerts': findings,
        'alerts_by_type': dict(sorted(by_type.items())),
        'protocols': dict(sorted(analyzer.stats.items(),
                                 key=lambda kv: -kv[1])),
        'elapsed_s': round(elapsed, 2),
        'pkt_per_s': round(packets / elapsed, 1) if elapsed else 0.0,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('pcaps', nargs='+', help='pcap files, in time order')
    ap.add_argument('--config', help='JSON threshold overrides '
                    '(same format as NETWATCH_CONFIG)')
    ap.add_argument('--alerts', help='write findings here as JSON lines')
    ap.add_argument('--summary', help='write the run summary here as JSON')
    ap.add_argument('--progress', type=int, default=0, metavar='N',
                    help='print progress every N packets')
    ap.add_argument('--persist', action='store_true',
                    help='also write packets and alerts to the database '
                    'named by DATABASE_URL')
    ap.add_argument('--alerts-only', action='store_true',
                    help='with --persist, write alerts only: no packet, '
                    'flow, host or protocol rows (for multi-GB captures)')
    ap.add_argument('--rebase-now', action='store_true',
                    help='shift timestamps so the capture ends now')
    args = ap.parse_args(argv)

    cfg = config_module.load(args.config)
    shift = 0.0
    if args.rebase_now:
        shift = time.time() - last_timestamp(args.pcaps[-1])
    db = None
    if args.persist:
        import db_backends
        from DB_Manager import DatabaseManager
        if args.alerts_only:
            cfg['engine']['store_packets'] = False
        try:
            db = DatabaseManager()
        except db_backends.ConfigError as exc:
            raise SystemExit('database configuration error: %s' % exc)
    out = open(args.alerts, 'w', encoding='utf-8') if args.alerts else None
    try:
        summary = replay(
            args.pcaps, cfg,
            on_finding=(lambda r: out.write(json.dumps(r) + '\n'))
            if out else None,
            progress_every=args.progress, db=db, shift_s=shift)
    finally:
        if out:
            out.close()
        if db is not None:
            db.close()
    text = json.dumps(summary, indent=2)
    if args.summary:
        with open(args.summary, 'w', encoding='utf-8') as fh:
            fh.write(text + '\n')
    print(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
