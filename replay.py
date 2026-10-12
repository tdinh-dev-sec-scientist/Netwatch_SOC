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

Reads classic libpcap (either byte order, micro- or nanosecond resolution)
and pcapng, with Ethernet, raw IP or Linux cooked (SLL) link layers.
Standard library only, like the rest of the capture path.
"""

import argparse
import gzip
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


_LINKTYPES = (LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL)
PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'


def _to_ethernet(linktype, data):
    """Normalise a captured record to an Ethernet frame for the analyzer."""
    if linktype == LINKTYPE_ETHERNET:
        return data
    if linktype == LINKTYPE_LINUX_SLL:
        # 16-byte cooked header; the protocol type is its last field.
        return _FAKE_MACS + data[14:16] + data[16:]
    version = data[0] >> 4 if data else 0
    ethertype = b'\x86\xdd' if version == 6 else b'\x08\x00'
    return _FAKE_MACS + ethertype + data


def read_pcap(path):
    """Yield (timestamp, ethernet_frame_bytes) for every record in a capture.

    Classic pcap and pcapng are both accepted; the format is detected from
    the first four bytes. A `.gz` file is decompressed as it is read.
    """
    with _open(path) as fh:
        header = fh.read(24)
        if len(header) < 24:
            raise ValueError('%s: not a pcap file (too short)' % path)
        if header[:4] == PCAPNG_MAGIC:
            fh.seek(0)
            yield from _read_pcapng(fh, path)
            return
        try:
            endian, resolution = _MAGIC[header[:4]]
        except KeyError:
            raise ValueError('%s: unrecognised pcap magic' % path)
        linktype = struct.unpack(endian + 'I', header[20:24])[0] & 0x0FFFFFFF
        if linktype not in _LINKTYPES:
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
            yield sec + frac * resolution, _to_ethernet(linktype, data)


def _read_pcapng(fh, path):
    """pcapng: section, interface and packet blocks (Enhanced and Simple).

    Each interface carries its own link type and timestamp resolution
    (if_tsresol); a new section resets both. Other block types are skipped.
    """
    endian = '<'
    interfaces = []          # [(linktype, seconds per tick)]
    last_ts = 0.0
    while True:
        head = fh.read(8)
        if len(head) < 8:
            return
        block_type = struct.unpack(endian + 'I', head[:4])[0]
        if head[:4] == PCAPNG_MAGIC:
            magic = fh.read(4)
            endian = '<' if magic == b'\x4d\x3c\x2b\x1a' else '>'
            length = struct.unpack(endian + 'I', head[4:8])[0]
            fh.seek(length - 12, 1)
            interfaces = []
            continue
        length = struct.unpack(endian + 'I', head[4:8])[0]
        if length < 12:
            raise ValueError('%s: corrupt pcapng block' % path)
        body = fh.read(length - 8)
        if len(body) < length - 8:
            return   # truncated final block
        if block_type == 1:                       # Interface Description
            linktype = struct.unpack(endian + 'H', body[:2])[0]
            interfaces.append((linktype, _pcapng_tsresol(body[8:-4], endian)))
        elif block_type == 6:                     # Enhanced Packet
            iface, hi, lo, incl = struct.unpack(endian + 'IIII', body[:16])
            linktype, tick = interfaces[iface]
            if linktype not in _LINKTYPES:
                continue
            last_ts = ((hi << 32) | lo) * tick
            yield last_ts, _to_ethernet(linktype, body[20:20 + incl])
        elif block_type == 3 and interfaces:      # Simple Packet: no time
            linktype, _tick = interfaces[0]
            orig = struct.unpack(endian + 'I', body[:4])[0]
            if linktype in _LINKTYPES:
                yield last_ts, _to_ethernet(linktype, body[4:4 + orig])


def _pcapng_tsresol(options, endian):
    """Seconds per timestamp tick from an IDB's options (default 1 µs)."""
    off = 0
    while off + 4 <= len(options):
        code, size = struct.unpack(endian + 'HH', options[off:off + 4])
        if code == 0:
            break
        if code == 9 and size >= 1:               # if_tsresol
            raw = options[off + 4]
            return 2.0 ** -(raw & 0x7F) if raw & 0x80 else 10.0 ** -raw
        off += 4 + size + (-size % 4)
    return 1e-6


def _open(path):
    return gzip.open(path, 'rb') if str(path).endswith('.gz') \
        else open(path, 'rb')


def last_timestamp(path):
    """Timestamp of the final record, found by skipping over packet data."""
    last = None
    with _open(path) as fh:
        header = fh.read(24)
        if header[:4] == PCAPNG_MAGIC or str(path).endswith('.gz'):
            for last, _frame in read_pcap(path):
                pass
            return last
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
