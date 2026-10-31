"""
Zeek as an engine: run it offline over each capture and read notice.log.

    --zeek-bin zeek                      a local install
    --zeek-docker zeek/zeek:7.0          sandboxed (--network none)
    --zeek-script my-detections.zeek     your own scripts, loaded after `local`

Zeek's detections are notices. Each notice type is mapped to the ATT&CK
techniques it indicates (NOTICE_TECHNIQUES); unknown notices are scored on
detection and noise but are not assessable for classification. Health
notices about the sensor itself (capture loss, packet filters) are not
detections and are left out; the list is recorded in the manifest.
"""

import hashlib
import json
import os
import shutil
import subprocess

from .base import Engine, EngineError, file_sha256, plain_pcap

NOTICE_TECHNIQUES = {
    'SSH::Password_Guessing': ['T1110'],
    'SSH::Login_By_Password_Guesser': ['T1110', 'T1078'],
    'FTP::Bruteforcing': ['T1110'],
    'HTTP::SQL_Injection_Attacker': ['T1190'],
    'HTTP::SQL_Injection_Victim': ['T1190'],
    'Scan::Port_Scan': ['T1046'],
    'Scan::Address_Scan': ['T1046'],
    'Scan::Random_Scan': ['T1046'],
    'Signatures::Sensitive_Signature': [],
    'TeamCymruMalwareHashRegistry::Match': ['T1105'],
}
HEALTH_NOTICE_PREFIXES = ('CaptureLoss::', 'PacketFilter::')


def notice_to_finding(notice, capture_id):
    """One notice.log record as a normalized finding, or None for health."""
    note = notice.get('note') or 'unknown'
    if note.startswith(HEALTH_NOTICE_PREFIXES):
        return None
    src = notice.get('id.orig_h') or notice.get('src')
    dst = notice.get('id.resp_h') or notice.get('dst')
    return {
        'ts': float(notice['ts']), 'capture': capture_id, 'engine': 'zeek',
        'rule': note, 'name': note,
        'severity': 'MEDIUM',
        'techniques': NOTICE_TECHNIQUES.get(note, []),
        'src_ip': src, 'dst_ip': dst,
        'src_port': notice.get('id.orig_p'),
        'dst_port': notice.get('id.resp_p') or notice.get('p'),
        'protocol': (notice.get('proto') or '').upper() or None,
        'group_by': 'pair', 'reason': notice.get('msg'),
    }


def read_notices(path, capture_id):
    with open(path, encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            finding = notice_to_finding(json.loads(line), capture_id)
            if finding:
                yield finding


class ZeekEngine(Engine):
    name = 'zeek'

    def __init__(self, zeek_bin=None, zeek_docker=None, zeek_script=None,
                 **_ignored):
        if bool(zeek_bin) == bool(zeek_docker):
            raise EngineError('give exactly one of --zeek-bin or --zeek-docker')
        if zeek_bin and not shutil.which(zeek_bin):
            raise EngineError('zeek binary %r not found' % zeek_bin)
        if zeek_docker and not shutil.which('docker'):
            raise EngineError('--zeek-docker needs the docker CLI')
        self.scripts = list(zeek_script or [])
        for path in self.scripts:
            if not os.path.exists(path):
                raise EngineError('%s does not exist' % path)
        self.binary = zeek_bin
        self.image = zeek_docker

    def _command(self, args, workdir=None, mounts=()):
        if not self.image:
            return [self.binary] + list(args)
        cmd = ['docker', 'run', '--rm', '--network', 'none']
        for host, inside, mode in mounts:
            cmd += ['-v', '%s:%s:%s' % (os.path.abspath(host), inside, mode)]
        if workdir:
            cmd += ['-w', '/bench/work']
        return cmd + [self.image, 'zeek'] + list(args)

    def _exec(self, cmd, cwd=None):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
        except OSError as exc:
            raise EngineError('could not run %s: %s' % (cmd[0], exc))
        if proc.returncode != 0:
            raise EngineError('zeek failed (exit %d):\n%s' % (
                proc.returncode, (proc.stderr or proc.stdout)[-2000:]))
        return proc.stdout

    def describe(self):
        scripts = hashlib.sha256()
        for path in self.scripts:
            scripts.update(file_sha256(path).encode())
        return {
            'name': self.name,
            'version': self._exec(self._command(['--version'])).strip(),
            'runtime': ('docker:' + self.image) if self.image else self.binary,
            'rules': 'local' + ''.join(' + ' + os.path.basename(p)
                                       for p in self.scripts),
            'rules_sha256': scripts.hexdigest() if self.scripts else None,
            'excluded_notice_prefixes': list(HEALTH_NOTICE_PREFIXES),
        }

    def run(self, capture, paths, workdir):
        findings = []
        for index, pcap in enumerate(paths):
            pcap = plain_pcap(pcap, workdir, index)
            logdir = os.path.join(workdir, 'zeek-%d' % index)
            os.makedirs(logdir, exist_ok=True)
            if self.image:
                mounts = [(pcap, '/bench/capture.pcap', 'ro'),
                          (logdir, '/bench/work', 'rw')]
                scripts = []
                for i, path in enumerate(self.scripts):
                    inside = '/bench/script-%d.zeek' % i
                    mounts.append((path, inside, 'ro'))
                    scripts.append(inside)
                cmd = self._command(['-C', '-r', '/bench/capture.pcap', 'local',
                                     'LogAscii::use_json=T'] + scripts,
                                    workdir=True, mounts=mounts)
                self._exec(cmd)
            else:
                cmd = self._command(['-C', '-r', os.path.abspath(pcap), 'local',
                                     'LogAscii::use_json=T']
                                    + [os.path.abspath(p) for p in self.scripts])
                self._exec(cmd, cwd=logdir)
            notices = os.path.join(logdir, 'notice.log')
            if os.path.exists(notices):
                findings.extend(read_notices(notices, capture.id))
        return findings
