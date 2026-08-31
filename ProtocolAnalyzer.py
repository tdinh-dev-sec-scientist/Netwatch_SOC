"""
ProtocolAnalyzer — deep packet inspection over real wire-format bytes.

Input is a raw Ethernet frame (bytes). Output is a flat dict of decoded fields.
Nothing here guesses from port numbers alone: ports are only a fallback used to
choose which L7 decoder to attempt, and every decoder validates the bytes it is
given before claiming the protocol.

Layers decoded, and what is extracted from each:

  L2   ETHERNET  eth_src, eth_dst, ethertype
       ARP       arp_op, arp_sender_mac/ip, arp_target_mac/ip
  L3   IPv4      src_ip, dst_ip, ttl, ip_proto, ip_id, ip_flags, ip_total_len
       IPv6      src_ip, dst_ip, hop_limit, next_header, flow_label
  L4   TCP       src_port, dst_port, flags, seq, ack, window, tcp_payload_len
       UDP       src_port, dst_port, udp_len
       ICMP      icmp_type, icmp_code, icmp_id, icmp_seq, icmp_payload_len
  L7   DNS       dns_qname, dns_qtype, dns_qr, dns_rcode, dns_ancount,
                 dns_max_label_len, dns_qname_entropy
       HTTP      http_method, http_uri, http_version, http_host, http_user_agent,
                 http_status, http_auth, http_content_len
       TLS       tls_record_type, tls_version, tls_sni, tls_cipher_count,
                 tls_handshake_type, tls_has_sni
       SSH       ssh_version, ssh_software, ssh_msg_type
       FTP       ftp_command, ftp_arg, ftp_code
       SMTP      smtp_command, smtp_arg, smtp_code
       POP3      pop3_command, pop3_status
       IMAP      imap_tag, imap_command, imap_status
       SNMP      snmp_version, snmp_community, snmp_pdu_type
       NTP       ntp_mode, ntp_version, ntp_req_code, ntp_is_monlist
       TELNET    telnet_negotiation, telnet_text
       SMB       smb_dialect, smb_command
       RDP       rdp_tpkt_len, rdp_x224_type, rdp_cookie
       DHCP      dhcp_op, dhcp_msg_type, dhcp_client_mac
       QUIC      quic_long_header, quic_version, quic_dcid_len

Payload entropy is computed for every packet carrying an L4 payload and is used
by the tunneling/exfiltration detectors.
"""

import math
import struct

ETH_HDR = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

# Port hints only select which decoder to *attempt*; each decoder validates.
TCP_PORT_HINTS = {
    21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP', 80: 'HTTP',
    110: 'POP3', 143: 'IMAP', 443: 'TLS', 445: 'SMB', 587: 'SMTP',
    993: 'IMAP', 995: 'POP3', 3389: 'RDP', 8080: 'HTTP', 8443: 'TLS',
}
UDP_PORT_HINTS = {
    53: 'DNS', 67: 'DHCP', 68: 'DHCP', 123: 'NTP', 161: 'SNMP',
    162: 'SNMP', 443: 'QUIC', 5353: 'DNS',
}

DNS_QTYPES = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 10: 'NULL', 12: 'PTR',
    15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY',
}

TCP_FLAG_BITS = [
    (0x01, 'FIN'), (0x02, 'SYN'), (0x04, 'RST'), (0x08, 'PSH'),
    (0x10, 'ACK'), (0x20, 'URG'), (0x40, 'ECE'), (0x80, 'CWR'),
]

HTTP_METHODS = (b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS',
                b'PATCH', b'TRACE', b'CONNECT')

FTP_COMMANDS = (b'USER', b'PASS', b'RETR', b'STOR', b'LIST', b'CWD',
                b'QUIT', b'PASV', b'PORT', b'TYPE', b'SIZE')
SMTP_COMMANDS = (b'EHLO', b'HELO', b'MAIL', b'RCPT', b'DATA', b'AUTH',
                 b'QUIT', b'RSET', b'STARTTLS')
POP3_COMMANDS = (b'USER', b'PASS', b'STAT', b'LIST', b'RETR', b'DELE', b'QUIT')
IMAP_COMMANDS = (b'LOGIN', b'SELECT', b'FETCH', b'LIST', b'LOGOUT',
                 b'CAPABILITY', b'AUTHENTICATE')

# Protocols this analyzer can positively identify and extract fields from.
SUPPORTED_PROTOCOLS = (
    'ARP', 'IPv4', 'IPv6', 'TCP', 'UDP', 'ICMP',
    'DNS', 'HTTP', 'TLS', 'SSH', 'FTP', 'SMTP', 'POP3', 'IMAP',
    'SNMP', 'NTP', 'TELNET', 'SMB', 'RDP', 'DHCP', 'QUIC',
)

# Protocols whose contents are opaque to inspection.
ENCRYPTED_PROTOCOLS = frozenset({'TLS', 'SSH', 'QUIC'})

PROTOCOL_RISK = {
    'TELNET': 'HIGH', 'FTP': 'MEDIUM', 'SNMP': 'MEDIUM', 'SMB': 'MEDIUM',
    'RDP': 'MEDIUM', 'HTTP': 'LOW', 'SMTP': 'LOW', 'POP3': 'LOW',
    'IMAP': 'LOW', 'DNS': 'INFO', 'NTP': 'INFO', 'DHCP': 'INFO',
    'SSH': 'LOW', 'TLS': 'INFO', 'QUIC': 'INFO', 'ARP': 'INFO',
    'ICMP': 'INFO', 'TCP': 'INFO', 'UDP': 'INFO', 'IPv4': 'INFO',
    'IPv6': 'INFO',
}


def shannon_entropy(data):
    """Shannon entropy in bits/byte (0.0 - 8.0)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)


def _mac(raw):
    return ':'.join('%02x' % b for b in raw)


def _ipv4(raw):
    return '%d.%d.%d.%d' % tuple(raw)


def _ipv6(raw):
    parts = [('%02x%02x' % (raw[i], raw[i + 1])).lstrip('0') or '0'
             for i in range(0, 16, 2)]
    return ':'.join(parts)


def decode_tcp_flags(bits):
    names = [n for bit, n in TCP_FLAG_BITS if bits & bit]
    return '|'.join(names) if names else 'NONE'


class ParseError(Exception):
    """Frame could not be decoded far enough to be useful."""


class ProtocolAnalyzer:
    """Stateless deep packet inspector. Safe to share across threads."""

    def __init__(self):
        self.stats = {}
        self.parse_errors = 0

    # ── entry point ──────────────────────────────────────────────────────────

    def parse(self, frame, ts=None):
        """Decode an Ethernet frame. Returns a flat dict of extracted fields.

        Raises ParseError when the frame is too short or malformed to yield a
        usable L3 record. Truncated *upper* layers degrade gracefully instead:
        the packet keeps whatever was decoded and gains a `truncated` flag.
        """
        if not isinstance(frame, (bytes, bytearray, memoryview)):
            raise ParseError('frame must be bytes')
        frame = bytes(frame)
        if len(frame) < ETH_HDR:
            raise ParseError('frame shorter than Ethernet header')

        pkt = {
            'ts': ts,
            'frame_len': len(frame),
            'protocol': 'UNKNOWN',
            'layers': [],
            'truncated': False,
            'src_ip': None, 'dst_ip': None,
            'src_port': None, 'dst_port': None,
            'flags': '', 'payload_len': 0, 'entropy': 0.0,
        }

        eth_dst, eth_src, ethertype = struct.unpack('!6s6sH', frame[:ETH_HDR])
        pkt['eth_dst'] = _mac(eth_dst)
        pkt['eth_src'] = _mac(eth_src)
        pkt['ethertype'] = ethertype
        pkt['layers'].append('ETHERNET')

        body = frame[ETH_HDR:]
        if ethertype == ETHERTYPE_ARP:
            self._parse_arp(pkt, body)
        elif ethertype == ETHERTYPE_IPV4:
            self._parse_ipv4(pkt, body)
        elif ethertype == ETHERTYPE_IPV6:
            self._parse_ipv6(pkt, body)
        else:
            raise ParseError('unsupported ethertype 0x%04x' % ethertype)

        self.stats[pkt['protocol']] = self.stats.get(pkt['protocol'], 0) + 1
        return pkt

    def safe_parse(self, frame, ts=None):
        """parse() that returns None instead of raising. Counts failures."""
        try:
            return self.parse(frame, ts)
        except (ParseError, struct.error, IndexError, ValueError,
                UnicodeError):
            self.parse_errors += 1
            return None

    # ── L2/L3 ────────────────────────────────────────────────────────────────

    def _parse_arp(self, pkt, data):
        if len(data) < 28:
            raise ParseError('short ARP')
        (htype, ptype, hlen, plen, op) = struct.unpack('!HHBBH', data[:8])
        pkt['layers'].append('ARP')
        pkt['protocol'] = 'ARP'
        pkt['arp_op'] = op  # 1=request 2=reply
        if hlen == 6 and plen == 4:
            pkt['arp_sender_mac'] = _mac(data[8:14])
            pkt['arp_sender_ip'] = _ipv4(data[14:18])
            pkt['arp_target_mac'] = _mac(data[18:24])
            pkt['arp_target_ip'] = _ipv4(data[24:28])
            pkt['src_ip'] = pkt['arp_sender_ip']
            pkt['dst_ip'] = pkt['arp_target_ip']
            # Gratuitous ARP: sender and target protocol address are identical.
            pkt['arp_gratuitous'] = (
                pkt['arp_sender_ip'] == pkt['arp_target_ip'])

    def _parse_ipv4(self, pkt, data):
        if len(data) < 20:
            raise ParseError('short IPv4')
        ver_ihl = data[0]
        if ver_ihl >> 4 != 4:
            raise ParseError('not IPv4')
        ihl = (ver_ihl & 0x0F) * 4
        if ihl < 20 or len(data) < ihl:
            raise ParseError('bad IPv4 IHL')
        total_len, ip_id, frag, ttl, proto = struct.unpack(
            '!HHHBB', data[2:10])
        pkt['layers'].append('IPv4')
        pkt['protocol'] = 'IPv4'
        pkt['src_ip'] = _ipv4(data[12:16])
        pkt['dst_ip'] = _ipv4(data[16:20])
        pkt['ttl'] = ttl
        pkt['ip_proto'] = proto
        pkt['ip_id'] = ip_id
        pkt['ip_total_len'] = total_len
        pkt['ip_flags'] = (frag >> 13) & 0x07
        pkt['ip_frag_offset'] = frag & 0x1FFF

        # Trust the header length field over the captured buffer, but never
        # read past what we actually have.
        payload = data[ihl:total_len] if 0 < total_len <= len(data) else data[ihl:]
        self._parse_l4(pkt, proto, payload)

    def _parse_ipv6(self, pkt, data):
        if len(data) < 40:
            raise ParseError('short IPv6')
        vtf, plen, nh, hlim = struct.unpack('!IHBB', data[:8])
        if vtf >> 28 != 6:
            raise ParseError('not IPv6')
        pkt['layers'].append('IPv6')
        pkt['protocol'] = 'IPv6'
        pkt['src_ip'] = _ipv6(data[8:24])
        pkt['dst_ip'] = _ipv6(data[24:40])
        pkt['hop_limit'] = hlim
        pkt['next_header'] = nh
        pkt['flow_label'] = vtf & 0xFFFFF
        pkt['ip_proto'] = nh
        self._parse_l4(pkt, nh, data[40:40 + plen] if plen else data[40:])

    # ── L4 ───────────────────────────────────────────────────────────────────

    def _parse_l4(self, pkt, proto, data):
        if proto == IPPROTO_TCP:
            self._parse_tcp(pkt, data)
        elif proto == IPPROTO_UDP:
            self._parse_udp(pkt, data)
        elif proto == IPPROTO_ICMP:
            self._parse_icmp(pkt, data)

    def _parse_tcp(self, pkt, data):
        if len(data) < 20:
            pkt['truncated'] = True
            return
        sport, dport, seq, ack, off_res = struct.unpack('!HHIIB', data[:13])
        flag_bits = data[13]
        window = struct.unpack('!H', data[14:16])[0]
        doff = (off_res >> 4) * 4
        if doff < 20:
            pkt['truncated'] = True
            return
        pkt['layers'].append('TCP')
        pkt['protocol'] = 'TCP'
        pkt['src_port'] = sport
        pkt['dst_port'] = dport
        pkt['tcp_seq'] = seq
        pkt['tcp_ack'] = ack
        pkt['tcp_flag_bits'] = flag_bits
        pkt['flags'] = decode_tcp_flags(flag_bits)
        pkt['window'] = window
        payload = data[doff:] if len(data) >= doff else b''
        pkt['tcp_payload_len'] = len(payload)
        self._parse_l7(pkt, payload, TCP_PORT_HINTS, sport, dport)

    def _parse_udp(self, pkt, data):
        if len(data) < 8:
            pkt['truncated'] = True
            return
        sport, dport, length, _ck = struct.unpack('!HHHH', data[:8])
        pkt['layers'].append('UDP')
        pkt['protocol'] = 'UDP'
        pkt['src_port'] = sport
        pkt['dst_port'] = dport
        pkt['udp_len'] = length
        payload = data[8:]
        self._parse_l7(pkt, payload, UDP_PORT_HINTS, sport, dport)

    def _parse_icmp(self, pkt, data):
        if len(data) < 4:
            pkt['truncated'] = True
            return
        itype, icode = data[0], data[1]
        pkt['layers'].append('ICMP')
        pkt['protocol'] = 'ICMP'
        pkt['icmp_type'] = itype
        pkt['icmp_code'] = icode
        payload = b''
        if itype in (0, 8) and len(data) >= 8:  # echo request/reply
            pkt['icmp_id'], pkt['icmp_seq'] = struct.unpack('!HH', data[4:8])
            payload = data[8:]
        else:
            payload = data[4:]
        pkt['icmp_payload_len'] = len(payload)
        pkt['payload_len'] = len(payload)
        pkt['entropy'] = shannon_entropy(payload)
        pkt['payload'] = payload

    # ── L7 dispatch ──────────────────────────────────────────────────────────

    def _parse_l7(self, pkt, payload, hints, sport, dport):
        pkt['payload_len'] = len(payload)
        pkt['payload'] = payload
        if not payload:
            return
        pkt['entropy'] = shannon_entropy(payload)

        # Signature-based identification takes precedence over port hints so a
        # protocol running on a non-standard port is still correctly named.
        decoder = self._identify_by_signature(payload)
        if decoder is None:
            decoder = hints.get(dport) or hints.get(sport)

        handler = self._DECODERS.get(decoder)
        if handler is None:
            return
        if handler(self, pkt, payload):
            pkt['protocol'] = decoder
            pkt['layers'].append(decoder)
            expected = hints.get(dport) or hints.get(sport)
            # Flag a positively-identified protocol on an unexpected port.
            pkt['nonstandard_port'] = expected is not None and expected != decoder

    @staticmethod
    def _identify_by_signature(p):
        if p[:4] == b'SSH-':
            return 'SSH'
        if p[:1] == b'\x16' and p[1:2] == b'\x03':
            return 'TLS'
        if p[:1] in (b'\x14', b'\x15', b'\x17') and p[1:2] == b'\x03':
            return 'TLS'
        if p[:5] == b'HTTP/' or any(
                p.startswith(m + b' ') for m in HTTP_METHODS):
            return 'HTTP'
        if p[:4] == b'\xffSMB' or p[:4] == b'\xfeSMB':
            return 'SMB'
        if p[:4] == b'\x00\x00\x00\x00' and len(p) > 8 and p[4:8] == b'\xffSMB':
            return 'SMB'
        return None

    # ── L7 decoders (each returns True if the bytes really are that protocol) ─

    def _dec_dns(self, pkt, p):
        if len(p) < 12:
            return False
        txid, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', p[:12])
        if qd == 0 and an == 0:
            return False
        if qd > 32 or an > 256:
            return False
        pkt['dns_txid'] = txid
        pkt['dns_qr'] = (flags >> 15) & 1
        pkt['dns_opcode'] = (flags >> 11) & 0x0F
        pkt['dns_rcode'] = flags & 0x0F
        pkt['dns_ancount'] = an
        pkt['dns_qdcount'] = qd

        labels, off = [], 12
        for _ in range(64):
            if off >= len(p):
                pkt['truncated'] = True
                break
            ln = p[off]
            if ln == 0:
                off += 1
                break
            if ln & 0xC0:  # compression pointer — no name to read inline
                off += 2
                break
            off += 1
            if off + ln > len(p):
                pkt['truncated'] = True
                break
            labels.append(p[off:off + ln])
            off += ln
        if labels:
            qname = b'.'.join(labels)
            pkt['dns_qname'] = qname.decode('ascii', 'replace')
            pkt['dns_max_label_len'] = max(len(l) for l in labels)
            pkt['dns_label_count'] = len(labels)
            # Entropy of the encoded portion, excluding the registrable domain,
            # is what separates tunneled payload from ordinary hostnames.
            encoded = b''.join(labels[:-2]) if len(labels) > 2 else b''
            pkt['dns_qname_entropy'] = shannon_entropy(encoded or qname)
        if off + 4 <= len(p):
            qtype, _qclass = struct.unpack('!HH', p[off:off + 4])
            pkt['dns_qtype'] = qtype
            pkt['dns_qtype_name'] = DNS_QTYPES.get(qtype, str(qtype))
        return True

    def _dec_http(self, pkt, p):
        head = p[:2048]
        line_end = head.find(b'\r\n')
        if line_end < 0:
            line_end = len(head)
        first = head[:line_end]
        if first.startswith(b'HTTP/'):
            parts = first.split(b' ', 2)
            if len(parts) < 2 or not parts[1].isdigit():
                return False
            pkt['http_version'] = parts[0].decode('ascii', 'replace')
            pkt['http_status'] = int(parts[1])
        else:
            parts = first.split(b' ')
            if len(parts) < 3 or parts[0] not in HTTP_METHODS:
                return False
            if not parts[-1].startswith(b'HTTP/'):
                return False
            # A conforming request line has exactly three fields, but attack
            # payloads sometimes carry raw spaces. Rejoin the middle so the
            # full URI still reaches the signature matcher.
            pkt['http_method'] = parts[0].decode('ascii')
            pkt['http_uri'] = b' '.join(parts[1:-1]).decode('utf-8', 'replace')
            pkt['http_version'] = parts[-1].decode('ascii', 'replace')

        for raw_line in head[line_end + 2:].split(b'\r\n'):
            if not raw_line:
                break
            sep = raw_line.find(b':')
            if sep < 0:
                continue
            name = raw_line[:sep].lower()
            value = raw_line[sep + 1:].strip().decode('utf-8', 'replace')
            if name == b'host':
                pkt['http_host'] = value
            elif name == b'user-agent':
                pkt['http_user_agent'] = value
            elif name == b'authorization':
                pkt['http_auth'] = value
            elif name == b'content-length':
                try:
                    pkt['http_content_len'] = int(value)
                except ValueError:
                    pass
            elif name == b'cookie':
                pkt['http_cookie_len'] = len(value)
        pkt['http_header_len'] = line_end
        return True

    def _dec_tls(self, pkt, p):
        if len(p) < 5 or p[1] != 0x03:
            return False
        rtype, ver_major, ver_minor, rlen = p[0], p[1], p[2], \
            struct.unpack('!H', p[3:5])[0]
        if rtype not in (20, 21, 22, 23):
            return False
        pkt['tls_record_type'] = rtype
        pkt['tls_record_len'] = rlen
        pkt['tls_version'] = {0: 'SSLv3', 1: 'TLS1.0', 2: 'TLS1.1',
                              3: 'TLS1.2', 4: 'TLS1.3'}.get(ver_minor,
                                                            'unknown')
        if rtype != 22 or len(p) < 6:
            return True
        hs_type = p[5]
        pkt['tls_handshake_type'] = hs_type
        if hs_type != 1:  # only ClientHello carries SNI / cipher list
            return True
        try:
            off = 9  # skip handshake header (4) then client_version(2)
            cver = struct.unpack('!H', p[off:off + 2])[0]
            pkt['tls_client_version'] = {0x0300: 'SSLv3', 0x0301: 'TLS1.0',
                                         0x0302: 'TLS1.1', 0x0303: 'TLS1.2',
                                         0x0304: 'TLS1.3'}.get(cver, 'unknown')
            off += 2 + 32  # client_version + random
            sid_len = p[off]
            off += 1 + sid_len
            cs_len = struct.unpack('!H', p[off:off + 2])[0]
            pkt['tls_cipher_count'] = cs_len // 2
            off += 2 + cs_len
            comp_len = p[off]
            off += 1 + comp_len
            if off + 2 > len(p):
                pkt['tls_has_sni'] = False
                return True
            ext_total = struct.unpack('!H', p[off:off + 2])[0]
            off += 2
            end = min(off + ext_total, len(p))
            while off + 4 <= end:
                etype, elen = struct.unpack('!HH', p[off:off + 4])
                off += 4
                if etype == 0 and off + 5 <= len(p):  # server_name
                    nlen = struct.unpack('!H', p[off + 3:off + 5])[0]
                    # SNI is already punycode on the wire, so it is ASCII.
                    pkt['tls_sni'] = p[off + 5:off + 5 + nlen].decode(
                        'ascii', 'replace') if nlen else ''
                off += elen
            pkt['tls_has_sni'] = 'tls_sni' in pkt
        except (struct.error, IndexError, UnicodeError):
            pkt['truncated'] = True
        return True

    def _dec_ssh(self, pkt, p):
        if p[:4] == b'SSH-':
            line = p.split(b'\r\n', 1)[0][:255]
            bits = line.split(b'-', 2)
            if len(bits) >= 2:
                pkt['ssh_version'] = bits[1].decode('ascii', 'replace')
            if len(bits) >= 3:
                pkt['ssh_software'] = bits[2].decode('ascii', 'replace')
            return True
        # Binary Packet Protocol: uint32 len, byte padlen, byte msg_type
        if len(p) >= 6:
            plen = struct.unpack('!I', p[:4])[0]
            if 0 < plen < 35000:
                pkt['ssh_msg_type'] = p[5]
                return True
        return False

    def _dec_line_protocol(self, pkt, p, commands, prefix):
        """Shared decoder for the CRLF request/response protocols."""
        line = p.split(b'\r\n', 1)[0][:512]
        if not line:
            return False
        upper = line.upper()
        token = upper.split(b' ', 1)[0]
        if token in commands:
            pkt[prefix + '_command'] = token.decode('ascii')
            arg = line[len(token):].strip()
            pkt[prefix + '_arg'] = arg.decode('utf-8', 'replace')[:128]
            return True
        if len(token) == 3 and token.isdigit():
            pkt[prefix + '_code'] = int(token)
            pkt[prefix + '_message'] = line[3:].strip().decode(
                'utf-8', 'replace')[:128]
            return True
        return False

    def _dec_ftp(self, pkt, p):
        return self._dec_line_protocol(pkt, p, FTP_COMMANDS, 'ftp')

    def _dec_smtp(self, pkt, p):
        return self._dec_line_protocol(pkt, p, SMTP_COMMANDS, 'smtp')

    def _dec_pop3(self, pkt, p):
        line = p.split(b'\r\n', 1)[0][:512]
        if line[:3] == b'+OK' or line[:4] == b'-ERR':
            pkt['pop3_status'] = line[:4].decode('ascii').strip()
            pkt['pop3_message'] = line.split(b' ', 1)[-1].decode(
                'utf-8', 'replace')[:128]
            return True
        token = line.upper().split(b' ', 1)[0]
        if token in POP3_COMMANDS:
            pkt['pop3_command'] = token.decode('ascii')
            pkt['pop3_arg'] = line[len(token):].strip().decode(
                'utf-8', 'replace')[:128]
            return True
        return False

    def _dec_imap(self, pkt, p):
        line = p.split(b'\r\n', 1)[0][:512]
        parts = line.split(b' ', 2)
        if len(parts) < 2:
            return False
        tag, second = parts[0], parts[1].upper()
        if second in (b'OK', b'NO', b'BAD'):
            pkt['imap_tag'] = tag.decode('ascii', 'replace')[:32]
            pkt['imap_status'] = second.decode('ascii')
            pkt['imap_message'] = (parts[2].decode('utf-8', 'replace')[:128]
                                   if len(parts) > 2 else '')
            return True
        if second in IMAP_COMMANDS:
            pkt['imap_tag'] = tag.decode('ascii', 'replace')[:32]
            pkt['imap_command'] = second.decode('ascii')
            pkt['imap_arg'] = (parts[2].decode('utf-8', 'replace')[:128]
                               if len(parts) > 2 else '')
            return True
        return False

    def _dec_snmp(self, pkt, p):
        # BER: SEQUENCE { INTEGER version, OCTET STRING community, PDU }
        if len(p) < 8 or p[0] != 0x30:
            return False
        off = 2
        if p[1] & 0x80:  # long-form length
            off = 2 + (p[1] & 0x7F)
        if off + 2 > len(p) or p[off] != 0x02:
            return False
        vlen = p[off + 1]
        if vlen != 1 or off + 3 > len(p):
            return False
        pkt['snmp_version'] = {0: 'v1', 1: 'v2c', 3: 'v3'}.get(p[off + 2],
                                                               'unknown')
        off += 3
        if off + 2 > len(p) or p[off] != 0x04:
            return False
        clen = p[off + 1]
        if clen & 0x80 or off + 2 + clen > len(p):
            return False
        pkt['snmp_community'] = p[off + 2:off + 2 + clen].decode(
            'ascii', 'replace')
        off += 2 + clen
        if off < len(p):
            pkt['snmp_pdu_type'] = {
                0xA0: 'get-request', 0xA1: 'get-next', 0xA2: 'response',
                0xA3: 'set-request', 0xA5: 'get-bulk',
            }.get(p[off], 'unknown')
        return True

    def _dec_ntp(self, pkt, p):
        if len(p) < 4:
            return False
        b0 = p[0]
        mode = b0 & 0x07
        version = (b0 >> 3) & 0x07
        if version == 0 or version > 4:
            return False
        pkt['ntp_mode'] = mode
        pkt['ntp_version'] = version
        # Mode 7 is the vendor-private control channel that carries MON_GETLIST.
        # Its high bit is the response flag, which is the only thing separating
        # a monlist request from the (much larger) reply.
        if mode == 7 and len(p) >= 8:
            pkt['ntp_response'] = bool(p[0] & 0x80)
            pkt['ntp_req_code'] = p[3]
            pkt['ntp_is_monlist'] = p[3] == 42
        else:
            pkt['ntp_response'] = False
            pkt['ntp_is_monlist'] = False
        return True

    def _dec_telnet(self, pkt, p):
        if p[0:1] == b'\xff':
            opts = []
            i = 0
            while i + 2 < len(p) and p[i] == 0xFF and len(opts) < 16:
                opts.append((p[i + 1], p[i + 2]))
                i += 3
            pkt['telnet_negotiation'] = len(opts)
            return True
        printable = sum(1 for b in p[:64] if 32 <= b < 127 or b in (10, 13))
        if printable >= max(1, len(p[:64])) * 0.9:
            pkt['telnet_text'] = p[:128].decode('ascii', 'replace')
            pkt['telnet_negotiation'] = 0
            return True
        return False

    def _dec_smb(self, pkt, p):
        off = 0
        if p[:4] not in (b'\xffSMB', b'\xfeSMB'):
            if len(p) > 8 and p[4:8] in (b'\xffSMB', b'\xfeSMB'):
                off = 4  # NetBIOS session header
            else:
                return False
        magic = p[off:off + 4]
        pkt['smb_dialect'] = 'SMB1' if magic == b'\xffSMB' else 'SMB2'
        if magic == b'\xffSMB' and len(p) > off + 4:
            pkt['smb_command'] = p[off + 4]
        elif len(p) >= off + 14:
            pkt['smb_command'] = struct.unpack(
                '!H', p[off + 12:off + 14][::-1])[0]
        return True

    def _dec_rdp(self, pkt, p):
        # TPKT: version 3, reserved 0, 2-byte length
        if len(p) < 7 or p[0] != 0x03 or p[1] != 0x00:
            return False
        tpkt_len = struct.unpack('!H', p[2:4])[0]
        if tpkt_len < 7:
            return False
        pkt['rdp_tpkt_len'] = tpkt_len
        pkt['rdp_x224_type'] = p[5]
        idx = p.find(b'Cookie: mstshash=')
        if idx >= 0:
            end = p.find(b'\r\n', idx)
            pkt['rdp_cookie'] = p[idx + 17:end if end > 0 else idx + 80].decode(
                'utf-8', 'replace')[:64]
        return True

    def _dec_dhcp(self, pkt, p):
        if len(p) < 240 or p[0] not in (1, 2):
            return False
        if p[236:240] != b'\x63\x82\x53\x63':  # magic cookie
            return False
        pkt['dhcp_op'] = p[0]
        pkt['dhcp_client_mac'] = _mac(p[28:34])
        off = 240
        while off + 2 <= len(p):
            opt = p[off]
            if opt == 255:
                break
            if opt == 0:
                off += 1
                continue
            olen = p[off + 1]
            if opt == 53 and off + 2 < len(p):
                pkt['dhcp_msg_type'] = {
                    1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST', 4: 'DECLINE',
                    5: 'ACK', 6: 'NAK', 7: 'RELEASE', 8: 'INFORM',
                }.get(p[off + 2], 'unknown')
            off += 2 + olen
        return True

    def _dec_quic(self, pkt, p):
        if len(p) < 5:
            return False
        first = p[0]
        if not (first & 0x80):  # short header — no version to validate
            pkt['quic_long_header'] = False
            return bool(first & 0x40)  # fixed bit must be set
        if not (first & 0x40):
            return False
        version = struct.unpack('!I', p[1:5])[0]
        pkt['quic_long_header'] = True
        pkt['quic_version'] = version
        if len(p) >= 6:
            pkt['quic_dcid_len'] = p[5]
        return True

    _DECODERS = {
        'DNS': _dec_dns, 'HTTP': _dec_http, 'TLS': _dec_tls, 'SSH': _dec_ssh,
        'FTP': _dec_ftp, 'SMTP': _dec_smtp, 'POP3': _dec_pop3,
        'IMAP': _dec_imap, 'SNMP': _dec_snmp, 'NTP': _dec_ntp,
        'TELNET': _dec_telnet, 'SMB': _dec_smb, 'RDP': _dec_rdp,
        'DHCP': _dec_dhcp, 'QUIC': _dec_quic,
    }

    # ── helpers used elsewhere ───────────────────────────────────────────────

    @staticmethod
    def get_risk(protocol):
        return PROTOCOL_RISK.get(protocol, 'INFO')

    @staticmethod
    def is_encrypted(protocol):
        return protocol in ENCRYPTED_PROTOCOLS

    @staticmethod
    def supported_protocols():
        return list(SUPPORTED_PROTOCOLS)
