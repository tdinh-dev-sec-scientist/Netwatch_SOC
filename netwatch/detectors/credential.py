"""Credential access detectors driven by in-protocol authentication results."""

import base64
import binascii

from .base import Detector, TimedCounter, TimedSet

# Protocols whose authentication outcome is visible on the wire.
_FAILURE = 'failure'
_SUCCESS = 'success'
_ATTEMPT = 'attempt'


_FROM_SERVER = 'server'
_FROM_CLIENT = 'client'


def auth_event(pkt):
    """Classify a packet's authentication signal.

    Returns (service, outcome, origin) or None, where `origin` says whether
    the packet came from the client or the server. That matters for
    attribution: a "530 Login incorrect" travels server -> client, so the
    party under suspicion is the packet's *destination*.

    Only real protocol status codes are used — nothing is inferred from
    packet timing or volume alone.
    """
    proto = pkt.get('protocol')

    if proto == 'FTP':
        code = pkt.get('ftp_code')
        if code == 530:
            return 'FTP', _FAILURE, _FROM_SERVER
        if code == 230:
            return 'FTP', _SUCCESS, _FROM_SERVER
        if pkt.get('ftp_command') == 'PASS':
            return 'FTP', _ATTEMPT, _FROM_CLIENT
    elif proto == 'SMTP':
        code = pkt.get('smtp_code')
        if code in (535, 530, 534):
            return 'SMTP', _FAILURE, _FROM_SERVER
        if code == 235:
            return 'SMTP', _SUCCESS, _FROM_SERVER
    elif proto == 'POP3':
        status = pkt.get('pop3_status')
        if status == '-ERR':
            return 'POP3', _FAILURE, _FROM_SERVER
        if pkt.get('pop3_command') == 'PASS':
            return 'POP3', _ATTEMPT, _FROM_CLIENT
    elif proto == 'IMAP':
        status = pkt.get('imap_status')
        if status == 'NO':
            return 'IMAP', _FAILURE, _FROM_SERVER
        if status == 'OK' and pkt.get('imap_message', '').upper().startswith(
                'LOGIN'):
            return 'IMAP', _SUCCESS, _FROM_SERVER
    elif proto == 'HTTP':
        if pkt.get('http_status') == 401:
            return 'HTTP', _FAILURE, _FROM_SERVER
        if pkt.get('http_auth'):
            return 'HTTP', _ATTEMPT, _FROM_CLIENT
    elif proto == 'SSH':
        # SSH authentication happens inside the encrypted channel, so failures
        # are not observable. What *is* observable is each new session's
        # cleartext version banner; a burst of them from one source is the
        # standard network-side signature of an SSH password attack.
        if pkt.get('ssh_version') and pkt.get('dst_port') == 22:
            return 'SSH', _ATTEMPT, _FROM_CLIENT
    return None


def extract_username(pkt):
    """Pull a username out of a packet when the protocol exposes one."""
    proto = pkt.get('protocol')
    if proto == 'FTP' and pkt.get('ftp_command') == 'USER':
        return pkt.get('ftp_arg') or None
    if proto == 'POP3' and pkt.get('pop3_command') == 'USER':
        return pkt.get('pop3_arg') or None
    if proto == 'IMAP' and pkt.get('imap_command') == 'LOGIN':
        arg = pkt.get('imap_arg') or ''
        return arg.split(' ')[0].strip('"') or None
    if proto == 'RDP' and pkt.get('rdp_cookie'):
        return pkt['rdp_cookie']
    if proto == 'HTTP' and pkt.get('http_auth', '').startswith('Basic '):
        creds = decode_basic_auth(pkt['http_auth'])
        if creds:
            return creds[0]
    return None


def extract_password(pkt):
    """Pull a cleartext password out of a packet when one is present.

    Returns the password, or None. Callers must record only its length —
    never the value.
    """
    proto = pkt.get('protocol')
    if proto == 'FTP' and pkt.get('ftp_command') == 'PASS':
        return pkt.get('ftp_arg') or None
    if proto == 'POP3' and pkt.get('pop3_command') == 'PASS':
        return pkt.get('pop3_arg') or None
    if proto == 'HTTP' and pkt.get('http_auth', '').startswith('Basic '):
        creds = decode_basic_auth(pkt['http_auth'])
        return creds[1] if creds else None
    return None


def decode_basic_auth(header):
    """Decode an HTTP Basic header into (user, password), or None."""
    try:
        raw = base64.b64decode(header[6:].strip(), validate=True)
        text = raw.decode('utf-8', 'replace')
    except (binascii.Error, ValueError):
        return None
    if ':' not in text:
        return None
    user, _, password = text.partition(':')
    return user, password


class BruteForceDetector(Detector):
    """Repeated authentication failures against one service on one host."""

    name = 'brute_force'
    threat_type = 'brute_force'
    description = ('In-protocol authentication failures (FTP 530, SMTP 535, '
                   'POP3 -ERR, IMAP NO, HTTP 401) or SSH session bursts '
                   'exceeding a threshold within a window')
    techniques = ('T1110', 'T1078')
    default_severity = 'CRITICAL'
    protocols = ('FTP', 'SMTP', 'POP3', 'IMAP', 'HTTP', 'SSH')

    def __init__(self, cfg):
        super().__init__(cfg)
        self._failures = TimedCounter(cfg['window_s'])
        self._recent_fail_keys = {}

    def inspect(self, pkt):
        event = auth_event(pkt)
        if event is None:
            return []
        service, outcome, origin = event
        self.packets_seen += 1
        ts = pkt['ts']
        # Attribute to the client regardless of which side sent this packet.
        if origin == _FROM_SERVER:
            client, server = pkt.get('dst_ip'), pkt.get('src_ip')
        else:
            client, server = pkt.get('src_ip'), pkt.get('dst_ip')
        key = (client, server, service)

        if outcome == _SUCCESS:
            # A success immediately after a failure burst is the strongest
            # signal available: the brute force worked.
            failures = self._failures.count(key, ts)
            if failures >= self.cfg['failures'] and self._cooled_down(
                    ('success',) + key, ts):
                return [self._finding(
                    pkt, 'CRITICAL', 0.95,
                    'Successful %s authentication from %s to %s after %d '
                    'failures in %ds — likely compromised account'
                    % (service, client, server, failures,
                       self.cfg['window_s']),
                    ('T1110', 'T1078'), src_ip=client, dst_ip=server,
                    service=service, preceding_failures=failures,
                    outcome='success', window_s=self.cfg['window_s'],
                )]
            return []

        if outcome == _ATTEMPT and service != 'SSH':
            return []  # attempts alone are not evidence; wait for a failure

        count = self._failures.add(key, ts)
        threshold = self.cfg['failures']
        if service == 'SSH':
            # Session bursts are noisier evidence than an explicit 530, so
            # require more of them before alerting.
            threshold = max(threshold * 2, 10)
        if count < threshold:
            return []
        if not self._cooled_down(key, ts):
            return []

        severity = 'CRITICAL' if count >= threshold * 5 else 'HIGH'
        confidence = min(0.97, 0.65 + count / (threshold * 20.0))
        if service == 'SSH':
            confidence = min(confidence, 0.85)  # inferred, not observed
        label = ('session attempts' if service == 'SSH'
                 else 'authentication failures')
        return [self._finding(
            pkt, severity, confidence,
            '%d %s %s from %s to %s in %ds'
            % (count, service, label, client, server, self.cfg['window_s']),
            ('T1110',), src_ip=client, dst_ip=server,
            service=service, failure_count=count, evidence_type=label,
            window_s=self.cfg['window_s'], threshold=threshold,
        )]

    def expire(self, now):
        super().expire(now)
        self._failures.expire(now)


class CredentialAttackDetector(Detector):
    """Credential stuffing, password spraying and cleartext credential exposure.

    Distinguished from brute force by *breadth*: brute force hammers one
    account, stuffing tries many accounts, spraying tries one account across
    many hosts.
    """

    name = 'credential_attack'
    threat_type = 'credential_attack'
    description = ('Many distinct usernames from one source (stuffing), one '
                   'username across many hosts (spraying), or reusable '
                   'credentials sent in cleartext')
    techniques = ('T1110', 'T1078')
    default_severity = 'HIGH'
    protocols = ('FTP', 'POP3', 'IMAP', 'RDP', 'HTTP')

    def __init__(self, cfg):
        super().__init__(cfg)
        self._users_by_src = TimedSet(cfg['window_s'])
        self._hosts_by_user = TimedSet(cfg['window_s'])
        self._pending_user = {}   # (src, dst, proto) -> (username, ts)

    def inspect(self, pkt):
        username = extract_username(pkt)
        password = extract_password(pkt)
        if not username and not password:
            return []
        self.packets_seen += 1
        ts = pkt['ts']
        src = pkt.get('src_ip')
        session = (src, pkt.get('dst_ip'), pkt.get('protocol'))
        findings = []

        if password is not None and self.cfg.get('alert_on_cleartext'):
            # FTP and POP3 send USER and PASS in separate packets, so pair the
            # password with the username seen earlier on the same session.
            known = self._pending_user.get(session)
            findings.extend(self._cleartext(
                pkt, username or (known[0] if known else '<unknown>'),
                password, ts))

        if not username:
            return findings
        self._pending_user[session] = (username, ts)

        n_users = self._users_by_src.add(src, username, ts)
        n_hosts = self._hosts_by_user.add(username, pkt.get('dst_ip'), ts)

        if n_users >= self.cfg['distinct_users'] and self._cooled_down(
                ('stuffing', src), ts):
            findings.append(self._finding(
                pkt, 'HIGH', min(0.96, 0.6 + n_users / 60.0),
                '%s attempted %d distinct usernames in %ds (credential '
                'stuffing): %s' % (
                    src, n_users, self.cfg['window_s'],
                    ', '.join(sorted(self._users_by_src.members(src))[:6])),
                ('T1110', 'T1078'),
                pattern='credential_stuffing', distinct_users=n_users,
                sample_users=sorted(self._users_by_src.members(src))[:12],
                window_s=self.cfg['window_s'],
            ))

        if n_hosts >= self.cfg['distinct_users'] and self._cooled_down(
                ('spray', username), ts):
            findings.append(self._finding(
                pkt, 'HIGH', min(0.94, 0.6 + n_hosts / 60.0),
                "Username '%s' tried against %d distinct hosts in %ds "
                '(password spraying)'
                % (username, n_hosts, self.cfg['window_s']),
                ('T1110', 'T1078'),
                pattern='password_spraying', username=username,
                distinct_hosts=n_hosts, window_s=self.cfg['window_s'],
            ))

        return findings

    def _cleartext(self, pkt, username, password, ts):
        proto = pkt.get('protocol')
        key = ('cleartext', pkt.get('src_ip'), pkt.get('dst_ip'), proto)
        if not self._cooled_down(key, ts):
            return []
        return [self._finding(
            pkt, 'MEDIUM', 0.99,
            "Cleartext %s credentials for '%s' observed from %s to %s — "
            'directly reusable by anyone on the path'
            % (proto, username, pkt['src_ip'], pkt['dst_ip']),
            ('T1078',),
            pattern='cleartext_credentials', username=username,
            protocol_exposed=proto, password_length=len(password),
        )]

    def expire(self, now):
        super().expire(now)
        self._users_by_src.expire(now)
        self._hosts_by_user.expire(now)
        cutoff = now - self.cfg['window_s']
        for session in [s for s, (_u, t) in self._pending_user.items()
                        if t < cutoff]:
            del self._pending_user[session]
