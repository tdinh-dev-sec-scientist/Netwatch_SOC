"""
Download individual host captures from the CSE-CIC-IDS2018 dataset.

The dataset is public on AWS Open Data (s3://cse-cic-ids2018, no account
needed), but each day's capture is one 38-50 GB zip of ~450 per-host pcaps.
This reads the zip's central directory with HTTP range requests and pulls only
the members named in `ground_truth.json` / `holdout.json`, so the whole evaluation needs about
about 3.3 GB of pcaps rather than 400 GB.

    python eval/cicids2018/fetch.py --out data/cicids2018          # everything
    python eval/cicids2018/fetch.py --out data/cicids2018 --truth eval/cicids2018/holdout.json

Standard library only.
"""

import argparse
import io
import json
import os
import shutil
import struct
import sys
import urllib.parse
import urllib.request
import zipfile
import zlib

BUCKET = 'https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/'
HERE = os.path.dirname(os.path.abspath(__file__))


class SizeMismatch(Exception):
    """A transfer ended early; the member is retried."""


class RangeFile(io.RawIOBase):
    """A seekable, read-only file over HTTP range requests."""

    def __init__(self, url):
        self.url = url
        self.pos = 0
        head = urllib.request.Request(url, method='HEAD')
        with urllib.request.urlopen(head, timeout=60) as resp:
            self.size = int(resp.headers['Content-Length'])

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, offset, whence=0):
        base = {0: 0, 1: self.pos, 2: self.size}[whence]
        self.pos = base + offset
        return self.pos

    def _get(self, start, end):
        req = urllib.request.Request(
            self.url, headers={'Range': 'bytes=%d-%d' % (start, end)})
        for attempt in range(5):
            try:
                with urllib.request.urlopen(req, timeout=300) as resp:
                    return resp.read()
            except OSError:
                if attempt == 4:
                    raise

    def readinto(self, buf):
        if self.pos >= self.size or not len(buf):
            return 0
        end = min(self.pos + len(buf), self.size) - 1
        data = self._get(self.pos, end)
        buf[:len(data)] = data
        self.pos += len(data)
        return len(data)


def day_zip_url(day):
    return BUCKET + urllib.parse.quote(
        'Original Network Traffic and Log data/%s/pcap.zip' % day)


def fetch_member(day, member, dest):
    """Stream one deflated member of a day's pcap.zip to `dest`, inflating."""
    raw = RangeFile(day_zip_url(day))
    archive = zipfile.ZipFile(io.BufferedReader(raw, buffer_size=1 << 20))
    info = archive.getinfo(member)
    if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise SystemExit('%s: unsupported compression %d'
                         % (member, info.compress_type))
    local = raw._get(info.header_offset, info.header_offset + 29)
    name_len, extra_len = struct.unpack('<HH', local[26:30])
    start = info.header_offset + 30 + name_len + extra_len
    end = start + info.compress_size - 1

    req = urllib.request.Request(raw.url, headers={
        'Range': 'bytes=%d-%d' % (start, end)})
    inflater = (zlib.decompressobj(-15)
                if info.compress_type == zipfile.ZIP_DEFLATED else None)
    tmp = dest + '.part'
    with urllib.request.urlopen(req, timeout=300) as resp, \
            open(tmp, 'wb') as out:
        while True:
            chunk = resp.read(1 << 22)
            if not chunk:
                break
            out.write(inflater.decompress(chunk) if inflater else chunk)
        if inflater:
            out.write(inflater.flush())
    if os.path.getsize(tmp) != info.file_size:
        raise SizeMismatch('%s: size mismatch (%d != %d)'
                         % (member, os.path.getsize(tmp), info.file_size))
    os.replace(tmp, dest)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--out', required=True, help='directory for the pcaps')
    ap.add_argument('--truth', default=os.path.join(HERE, 'ground_truth.json'),
                    help='ground-truth file listing the captures '
                    '(ground_truth.json or holdout.json)')
    ap.add_argument('--only', action='append', default=[],
                    help='capture name(s) from the ground-truth file')
    args = ap.parse_args(argv)

    with open(args.truth, encoding='utf-8') as fh:
        truth = json.load(fh)
    os.makedirs(args.out, exist_ok=True)
    for cap in truth['captures']:
        if args.only and cap['name'] not in args.only:
            continue
        for member in cap['members']:
            dest = os.path.join(args.out, member_filename(cap['day'], member))
            if os.path.exists(dest):
                print('have  %s' % dest)
                continue
            print('fetch %s :: %s' % (cap['day'], member), flush=True)
            for attempt in range(3):
                try:
                    fetch_member(cap['day'], member, dest)
                    break
                except (OSError, SizeMismatch) as exc:
                    if attempt == 2:
                        raise
                    print('  retry after: %s' % exc, flush=True)
    print('free disk: %.1f GB' % (shutil.disk_usage(args.out).free / 1e9))
    return 0


def member_filename(day, member):
    """Local file name for one zip member: day plus host, no spaces."""
    base = member.rsplit('/', 1)[-1].replace(' ', '')
    return '%s_%s.pcap' % (day, base.replace('.pcap', ''))


if __name__ == '__main__':
    sys.exit(main())
