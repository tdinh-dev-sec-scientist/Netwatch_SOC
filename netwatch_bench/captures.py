"""
Capture facts the scorer needs independently of any engine: packet count and
the time span each capture covers (the host-hour denominator), plus hashes.

Measured once per capture by reading record headers, so every engine scored
on a pack divides by the same exposure.
"""

import gzip
import hashlib
import struct

_PCAP_MAGIC = {
    b'\xd4\xc3\xb2\xa1': ('<', 1e-6),
    b'\xa1\xb2\xc3\xd4': ('>', 1e-6),
    b'\x4d\x3c\xb2\xa1': ('<', 1e-9),
    b'\xa1\xb2\x3c\x4d': ('>', 1e-9),
}
_PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'


def _open(path):
    with open(path, 'rb') as fh:
        gzipped = fh.read(2) == b'\x1f\x8b'
    return gzip.open(path, 'rb') if gzipped else open(path, 'rb')


def scan(path):
    """(packets, first_ts, last_ts) of one pcap or pcapng file."""
    with _open(path) as fh:
        header = fh.read(24)
        if header[:4] == _PCAPNG_MAGIC:
            return _scan_pcapng(path)
        if header[:4] not in _PCAP_MAGIC:
            raise ValueError('%s: not a pcap or pcapng file' % path)
        endian, resolution = _PCAP_MAGIC[header[:4]]
        record = struct.Struct(endian + 'IIII')
        packets, first, last = 0, None, None
        while True:
            head = fh.read(16)
            if len(head) < 16:
                break
            sec, frac, incl, _orig = record.unpack(head)
            fh.seek(incl, 1)
            ts = sec + frac * resolution
            packets += 1
            if first is None:
                first = ts
            last = ts
    return packets, first, last


def _scan_pcapng(path):
    # pcapng is rarer in datasets; reuse NetWatch's full reader for it.
    from replay import read_pcap
    packets, first, last = 0, None, None
    for ts, _frame in read_pcap(path):
        packets += 1
        if first is None:
            first = ts
        last = ts
    return packets, first, last


def sha256(path, chunk=1 << 20):
    digest = hashlib.sha256()
    with open(path, 'rb') as fh:
        for block in iter(lambda: fh.read(chunk), b''):
            digest.update(block)
    return digest.hexdigest()


def describe(capture, paths, hash_files=True):
    """Facts about one pack capture, checking any pinned hashes."""
    files, packets, first, last = [], 0, None, None
    for entry, path in zip(capture.files, paths):
        count, lo, hi = scan(path)
        packets += count
        if lo is not None:
            first = lo if first is None else min(first, lo)
            last = hi if last is None else max(last, hi)
        digest = sha256(path) if hash_files or entry.get('sha256') else None
        if entry.get('sha256') and digest != entry['sha256']:
            raise ValueError('%s: sha256 %s does not match the pack (%s); the '
                             'file is not the one the pack was labelled on'
                             % (path, digest, entry['sha256']))
        files.append({'path': entry['path'] or entry['data_path'],
                      'sha256': digest, 'packets': count})
    span = (last - first) if first is not None else 0.0
    return {
        'id': capture.id, 'files': files, 'packets': packets,
        'start': first, 'end': last,
        'host_hours': span / 3600.0 * capture.hosts,
    }
