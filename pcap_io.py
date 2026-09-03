"""
Capture I/O — Scapy-backed PCAP replay, PCAP writing and live sniffing.

This is the boundary between NetWatch and the wire. Scapy owns the capture
layer: reading and writing libpcap files, and sniffing a live interface. It
deliberately does *not* own protocol decoding — `ProtocolAnalyzer` decodes raw
frames itself, so what the detectors see is identical whether a frame arrived
from a file, an interface or the traffic generator.

    from pcap_io import iter_pcap
    for ts, frame in iter_pcap('pcaps/attack/port_scan.pcap'):
        simulator.process(frame, ts)

Reading is streamed one packet at a time so a large capture never has to fit
in memory; `read_pcap()` is the eager variant for small files.
"""

import hashlib
import logging
import os

LINKTYPE_ETHERNET = 1

_SCAPY_ERROR = (
    'scapy is required for PCAP replay and live capture: pip install scapy')


def _scapy_utils():
    try:
        from scapy.utils import PcapReader, PcapWriter
    except ImportError as exc:                       # pragma: no cover
        raise RuntimeError(_SCAPY_ERROR) from exc
    # Only scapy.utils is imported, so its layer registry is empty and it warns
    # once per file that link type 1 is unknown. That is exactly what we want —
    # frames come back as opaque bytes for ProtocolAnalyzer to decode, with no
    # dissect/rebuild round trip in between — so the warning is silenced rather
    # than avoided by pulling in layers we do not use.
    logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
    return PcapReader, PcapWriter


def scapy_version():
    """The installed Scapy version, or None when it is not importable."""
    try:
        import scapy
    except ImportError:                              # pragma: no cover
        return None
    return getattr(scapy, '__version__', 'unknown')


# ── writing ──────────────────────────────────────────────────────────────────

def write_pcap(path, frames, linktype=LINKTYPE_ETHERNET):
    """Write `[(ts, frame_bytes), ...]` to a libpcap file. Returns the count.

    Frames are handed to Scapy as raw bytes, so nothing is re-encoded on the
    way out: a capture written here and read back is byte-identical to what
    produced it. `test_pcap_io.py` asserts that round trip.
    """
    _reader, PcapWriter = _scapy_utils()
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    written = 0
    writer = PcapWriter(path, linktype=linktype, sync=False)
    try:
        # write_packet() skips the file header, so emit it explicitly rather
        # than relying on the first write() to do it.
        writer.write_header(None)
        for ts, frame in frames:
            raw = bytes(frame)
            seconds = int(ts)
            writer.write_packet(
                raw, sec=seconds, usec=int(round((ts - seconds) * 1_000_000)),
                caplen=len(raw), wirelen=len(raw))
            written += 1
    finally:
        writer.close()
    return written


# ── reading ──────────────────────────────────────────────────────────────────

def iter_pcap(path, limit=None):
    """Stream `(ts, frame_bytes)` from a PCAP without loading it all."""
    PcapReader, _writer = _scapy_utils()
    count = 0
    with PcapReader(path) as reader:
        for packet in reader:
            yield float(packet.time), bytes(packet)
            count += 1
            if limit is not None and count >= limit:
                return


def read_pcap(path, limit=None):
    """Eager `iter_pcap`. Use for corpora small enough to hold in memory."""
    return list(iter_pcap(path, limit=limit))


def pcap_summary(path):
    """Packet count, byte total, timespan and digest of a capture."""
    digest = hashlib.sha256()
    with open(path, 'rb') as fh:
        for block in iter(lambda: fh.read(1 << 20), b''):
            digest.update(block)

    packets = payload_bytes = 0
    first = last = None
    for ts, frame in iter_pcap(path):
        packets += 1
        payload_bytes += len(frame)
        if first is None:
            first = ts
        last = ts
    return {
        'path': path,
        'packets': packets,
        'bytes': payload_bytes,
        'first_ts': first,
        'last_ts': last,
        'duration_s': round((last - first), 3) if packets > 1 else 0.0,
        'file_bytes': os.path.getsize(path),
        'sha256': digest.hexdigest(),
    }


# ── live capture ─────────────────────────────────────────────────────────────

def live_sniffer(handler, iface=None, bpf_filter=None, store=False):
    """A Scapy AsyncSniffer wired into the same `process(frame, ts)` seam.

    Not started here — the caller decides when, and needs CAP_NET_RAW:

        sniffer = live_sniffer(lambda f, ts: sim.process(f, ts), iface='eth0')
        sniffer.start()
    """
    try:
        from scapy.sendrecv import AsyncSniffer
    except ImportError as exc:                       # pragma: no cover
        raise RuntimeError(_SCAPY_ERROR) from exc

    def _prn(packet):
        handler(bytes(packet), float(packet.time))

    kwargs = {'prn': _prn, 'store': store}
    if iface:
        kwargs['iface'] = iface
    if bpf_filter:
        kwargs['filter'] = bpf_filter
    return AsyncSniffer(**kwargs)
