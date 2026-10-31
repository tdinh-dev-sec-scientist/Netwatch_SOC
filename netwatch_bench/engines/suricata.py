"""
Suricata as an engine: run it offline over each capture and read EVE alerts.

    --suricata-bin /usr/bin/suricata --rules suricata.rules
    --suricata-docker jasonish/suricata:7.0          (rules default to the
                                                      image's ET Open copy)

ATT&CK techniques come from the rule's own metadata (`mitre_technique_id`,
which ET Open rules carry where the maintainers assigned one), so Suricata's
classification is scored only where its rules make a claim.
"""

import datetime as dt
import json
import os
import shutil
import subprocess

from .base import Engine, EngineError, file_sha256, plain_pcap

SEVERITY = {1: 'HIGH', 2: 'MEDIUM', 3: 'LOW', 4: 'INFO'}
IMAGE_RULES = '/var/lib/suricata/rules/suricata.rules'
IMAGE_CONFIG = '/etc/suricata/suricata.yaml'


def eve_to_finding(event, capture_id):
    """One EVE event as a normalized finding, or None if it is not an alert."""
    if event.get('event_type') != 'alert':
        return None
    alert = event.get('alert') or {}
    stamp = event['timestamp']
    try:
        ts = dt.datetime.strptime(stamp, '%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
    except ValueError:
        ts = dt.datetime.fromisoformat(stamp).timestamp()
    metadata = alert.get('metadata') or {}
    techniques = [t for t in metadata.get('mitre_technique_id') or []
                  if isinstance(t, str) and t.upper().startswith('T')]
    sid = alert.get('signature_id')
    return {
        'ts': ts, 'capture': capture_id, 'engine': 'suricata',
        'rule': 'sid:%s' % sid if sid is not None else 'unknown',
        'name': alert.get('signature') or 'unknown',
        'category': alert.get('category'),
        'severity': SEVERITY.get(alert.get('severity'), 'INFO'),
        'techniques': techniques,
        'src_ip': event.get('src_ip'), 'dst_ip': event.get('dest_ip'),
        'src_port': event.get('src_port'), 'dst_port': event.get('dest_port'),
        'protocol': event.get('proto'), 'group_by': 'pair',
    }


def read_eve(path, capture_id):
    with open(path, encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if line:
                finding = eve_to_finding(json.loads(line), capture_id)
                if finding:
                    yield finding


def alerts_only_config(text):
    """A suricata.yaml whose only output is EVE alerts.

    The stock config also logs every flow, HTTP transaction and DNS query,
    which over a long capture is gigabytes nobody reads.
    """
    import yaml
    body = text.split('\n', 1)[1] if text.startswith('%YAML') else text
    conf = yaml.safe_load(body)
    for output in conf.get('outputs', []):
        (name, settings), = output.items()
        if not isinstance(settings, dict):
            continue
        if name == 'eve-log':
            settings.update({'enabled': True, 'filetype': 'regular',
                             'filename': 'eve.json',
                             'types': [{'alert': {'tagged-packets': False,
                                                  'metadata': True}}]})
        else:
            settings['enabled'] = False
    return '%YAML 1.1\n---\n' + yaml.safe_dump(conf)


class SuricataEngine(Engine):
    name = 'suricata'

    def __init__(self, suricata_bin=None, suricata_docker=None, rules=None,
                 suricata_config=None, **_ignored):
        if bool(suricata_bin) == bool(suricata_docker):
            raise EngineError('give exactly one of --suricata-bin or '
                              '--suricata-docker')
        if suricata_bin and not rules:
            raise EngineError('--rules is required with --suricata-bin')
        if suricata_bin and not shutil.which(suricata_bin):
            raise EngineError('suricata binary %r not found' % suricata_bin)
        if suricata_docker and not shutil.which('docker'):
            raise EngineError('--suricata-docker needs the docker CLI')
        for path in (rules, suricata_config):
            if path and not os.path.exists(path):
                raise EngineError('%s does not exist' % path)
        self.binary = suricata_bin
        self.image = suricata_docker
        self.rules = rules
        self.config = suricata_config
        self._config_text = None

    # ── command construction ────────────────────────────────────────────────

    def _docker(self, args, mounts=(), entrypoint=None):
        cmd = ['docker', 'run', '--rm', '--network', 'none']
        for host, inside, mode in mounts:
            cmd += ['-v', '%s:%s:%s' % (os.path.abspath(host), inside, mode)]
        if entrypoint:
            cmd += ['--entrypoint', entrypoint]
        return cmd + [self.image] + list(args)

    def _exec(self, cmd):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)
        except OSError as exc:
            raise EngineError('could not run %s: %s' % (cmd[0], exc))
        if proc.returncode != 0:
            raise EngineError('%s failed (exit %d):\n%s'
                              % (' '.join(cmd[:6]), proc.returncode,
                                 (proc.stderr or proc.stdout)[-2000:]))
        return proc.stdout

    def _base_config(self):
        if self._config_text is None:
            if self.config:
                with open(self.config, encoding='utf-8') as fh:
                    self._config_text = fh.read()
            elif self.image:
                self._config_text = self._exec(self._docker(
                    [IMAGE_CONFIG], entrypoint='cat'))
            else:
                with open('/etc/suricata/suricata.yaml', encoding='utf-8') as fh:
                    self._config_text = fh.read()
        return self._config_text

    def version(self):
        if self.image:
            out = self._exec(self._docker(['-V']))
        else:
            out = self._exec([self.binary, '-V'])
        return out.strip().splitlines()[-1] if out.strip() else None

    def _rules_sha256(self):
        if self.rules:
            return file_sha256(self.rules)
        out = self._exec(self._docker([IMAGE_RULES], entrypoint='sha256sum'))
        return out.split()[0] if out else None

    def describe(self):
        return {
            'name': self.name,
            'version': self.version(),
            'runtime': ('docker:' + self.image) if self.image else self.binary,
            'rules': self.rules or ('%s (bundled in the image)' % IMAGE_RULES),
            'rules_sha256': self._rules_sha256(),
            'config_sha256': __import__('hashlib').sha256(
                self._base_config().encode()).hexdigest(),
        }

    def run(self, capture, paths, workdir):
        config_path = os.path.join(workdir, 'suricata.yaml')
        with open(config_path, 'w', encoding='utf-8') as fh:
            fh.write(alerts_only_config(self._base_config()))
        findings = []
        for index, pcap in enumerate(paths):
            logdir = os.path.join(workdir, 'log-%d' % index)
            os.makedirs(logdir, exist_ok=True)
            pcap = plain_pcap(pcap, workdir, index)
            if self.image:
                mounts = [(config_path, '/bench/suricata.yaml', 'ro'),
                          (pcap, '/bench/capture.pcap', 'ro'),
                          (logdir, '/bench/log', 'rw')]
                rules = IMAGE_RULES
                if self.rules:
                    mounts.append((self.rules, '/bench/rules.rules', 'ro'))
                    rules = '/bench/rules.rules'
                cmd = self._docker(
                    ['-c', '/bench/suricata.yaml', '-S', rules,
                     '-r', '/bench/capture.pcap', '-l', '/bench/log',
                     '-k', 'none', '--runmode', 'single'], mounts)
            else:
                cmd = [self.binary, '-c', config_path, '-S', self.rules,
                       '-r', pcap, '-l', logdir, '-k', 'none',
                       '--runmode', 'single']
            self._exec(cmd)
            eve = os.path.join(logdir, 'eve.json')
            if os.path.exists(eve):
                findings.extend(read_eve(eve, capture.id))
        return findings
