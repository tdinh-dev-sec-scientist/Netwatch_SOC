"""
Wire-format frame construction.

Everything the detection pipeline sees is built here as real bytes: Ethernet
headers, IPv4/IPv6 headers with correct checksums, TCP/UDP/ICMP headers, and
protocol-conformant application payloads. The analyzer then decodes those bytes
with no privileged knowledge of how they were produced — which is what makes
the parser and the detectors genuinely testable.

Swapping this module for a live `scapy.AsyncSniffer` (or a pcap reader) needs
no change anywhere downstream: both produce raw frames.
"""

import struct

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD

TCP_FLAGS = {'FIN': 0x01, 'SYN': 0x02, 'RST': 0x04, 'PSH': 0x08,
             'ACK': 0x10, 'URG': 0x20}

DNS_QTYPE = {'A': 1, 'NS': 2, 'CNAME': 5, 'NULL': 10, 'PTR': 12, 'MX': 15,
             'TXT': 16, 'AAAA': 28, 'SRV': 33, 'ANY': 255}


def checksum16(data):
    """Standard internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def mac_bytes(mac):
    return bytes(int(p, 16) for p in mac.split(':'))


def ip_bytes(ip):
    return bytes(int(p) for p in ip.split('.'))


def flags_to_bits(flags):
    if isinstance(flags, int):
        return flags
    bits = 0
    for name in str(flags).split('|'):
        bits |= TCP_FLAGS.get(name.strip().upper(), 0)
    return bits


# ── link / network layers ────────────────────────────────────────────────────

def ethernet(payload, src_mac, dst_mac, ethertype=ETHERTYPE_IPV4):
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + \
        struct.pack('!H', ethertype) + payload


def ipv4(payload, src_ip, dst_ip, proto, ttl=64, ident=0, dont_fragment=True):
    total_len = 20 + len(payload)
    frag = 0x4000 if dont_fragment else 0
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total_len, ident & 0xFFFF,
                         frag, ttl, proto, 0,
                         ip_bytes(src_ip), ip_bytes(dst_ip))
    header = header[:10] + struct.pack('!H', checksum16(header)) + header[12:]
    return header + payload


def ipv6(payload, src_ip, dst_ip, next_header, hop_limit=64, flow_label=0):
    vtf = (6 << 28) | (flow_label & 0xFFFFF)
    header = struct.pack('!IHBB', vtf, len(payload), next_header, hop_limit)
    return header + _ipv6_bytes(src_ip) + _ipv6_bytes(dst_ip) + payload


def _ipv6_bytes(addr):
    head, _, tail = addr.partition('::')
    head_parts = [p for p in head.split(':') if p]
    tail_parts = [p for p in tail.split(':') if p]
    fill = 8 - len(head_parts) - len(tail_parts)
    parts = head_parts + ['0'] * fill + tail_parts
    return b''.join(struct.pack('!H', int(p, 16)) for p in parts[:8])


def _l4_checksum(src_ip, dst_ip, proto, segment):
    pseudo = ip_bytes(src_ip) + ip_bytes(dst_ip) + \
        struct.pack('!BBH', 0, proto, len(segment))
    return checksum16(pseudo + segment)


def tcp(payload, src_ip, dst_ip, src_port, dst_port, flags='ACK',
        seq=1, ack=1, window=65535):
    bits = flags_to_bits(flags)
    header = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack,
                         5 << 4, bits, window, 0, 0)
    segment = header + payload
    ck = _l4_checksum(src_ip, dst_ip, 6, segment)
    return segment[:16] + struct.pack('!H', ck) + segment[18:]


def udp(payload, src_ip, dst_ip, src_port, dst_port):
    length = 8 + len(payload)
    segment = struct.pack('!HHHH', src_port, dst_port, length, 0) + payload
    ck = _l4_checksum(src_ip, dst_ip, 17, segment) or 0xFFFF
    return segment[:6] + struct.pack('!H', ck) + segment[8:]


def icmp(payload, icmp_type=8, code=0, ident=1, seq=1):
    header = struct.pack('!BBHHH', icmp_type, code, 0, ident, seq)
    packet = header + payload
    ck = checksum16(packet)
    return packet[:2] + struct.pack('!H', ck) + packet[4:]


def arp(op, sender_mac, sender_ip, target_mac, target_ip):
    return struct.pack('!HHBBH', 1, ETHERTYPE_IPV4, 6, 4, op) + \
        mac_bytes(sender_mac) + ip_bytes(sender_ip) + \
        mac_bytes(target_mac) + ip_bytes(target_ip)


# ── application layer payloads ───────────────────────────────────────────────

def http_request(method='GET', uri='/', host='example.com',
                 user_agent='Mozilla/5.0', authorization=None, body=b'',
                 extra_headers=None):
    lines = ['%s %s HTTP/1.1' % (method, uri), 'Host: %s' % host,
             'User-Agent: %s' % user_agent]
    if authorization:
        lines.append('Authorization: %s' % authorization)
    if body:
        lines.append('Content-Length: %d' % len(body))
    for k, v in (extra_headers or {}).items():
        lines.append('%s: %s' % (k, v))
    return ('\r\n'.join(lines) + '\r\n\r\n').encode('utf-8') + body


def http_response(status=200, reason='OK', body=b'', server='nginx'):
    head = ['HTTP/1.1 %d %s' % (status, reason), 'Server: %s' % server,
            'Content-Length: %d' % len(body)]
    if status == 401:
        head.append('WWW-Authenticate: Basic realm="restricted"')
    return ('\r\n'.join(head) + '\r\n\r\n').encode('utf-8') + body


def _encode_name(name):
    out = b''
    for label in name.split('.'):
        if not label:
            continue
        encoded = label.encode('ascii', 'replace')[:63]
        out += bytes([len(encoded)]) + encoded
    return out + b'\x00'


def dns_query(qname, qtype='A', txid=0x1234, recursion=True):
    flags = 0x0100 if recursion else 0x0000
    header = struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
    qtype_val = DNS_QTYPE.get(qtype, qtype if isinstance(qtype, int) else 1)
    return header + _encode_name(qname) + struct.pack('!HH', qtype_val, 1)


def dns_response(qname, qtype='A', txid=0x1234, rcode=0, answers=1,
                 answer_payload=b''):
    flags = 0x8180 | (rcode & 0x0F)
    header = struct.pack('!HHHHHH', txid, flags, 1, answers, 0, 0)
    qtype_val = DNS_QTYPE.get(qtype, qtype if isinstance(qtype, int) else 1)
    body = _encode_name(qname) + struct.pack('!HH', qtype_val, 1)
    for _ in range(answers):
        body += b'\xc0\x0c' + struct.pack('!HHIH', qtype_val, 1, 300,
                                          len(answer_payload) or 4)
        body += answer_payload or b'\x5d\xb8\xd8\x22'
    return header + body


def tls_client_hello(sni=None, version=0x0303, cipher_count=16,
                     record_version=0x0301):
    ciphers = b''.join(struct.pack('!H', 0xC02F + i)
                       for i in range(cipher_count))
    extensions = b''
    if sni is not None:
        name = sni.encode('idna') if sni else b''
        sni_ext = struct.pack('!HBH', len(name) + 3, 0, len(name)) + name
        extensions += struct.pack('!HH', 0, len(sni_ext)) + sni_ext
    # supported_groups, kept so the hello looks structurally normal
    groups = struct.pack('!HHH', 2, 0x001D, 0)[:4]
    extensions += struct.pack('!HH', 10, len(groups)) + groups

    body = struct.pack('!H', version) + bytes(range(32))
    body += b'\x00'                                   # session id length
    body += struct.pack('!H', len(ciphers)) + ciphers
    body += b'\x01\x00'                               # compression: null
    body += struct.pack('!H', len(extensions)) + extensions

    handshake = b'\x01' + struct.pack('!I', len(body))[1:] + body
    return struct.pack('!BBBH', 0x16, 0x03, record_version & 0xFF,
                       len(handshake)) + handshake


def tls_application_data(size=512, record_version=0x0303):
    return struct.pack('!BBBH', 0x17, 0x03, record_version & 0xFF, size) + \
        bytes((i * 37 + 11) & 0xFF for i in range(size))


def ssh_banner(version='2.0', software='OpenSSH_9.3'):
    return ('SSH-%s-%s\r\n' % (version, software)).encode('ascii')


def ssh_binary(msg_type=20, size=64):
    payload = bytes((i * 53 + 7) & 0xFF for i in range(size))
    return struct.pack('!IB', len(payload) + 2, 4) + bytes([msg_type]) + payload


def line_protocol(text):
    return (text + '\r\n').encode('utf-8')


def snmp_message(community='public', version=1, pdu='get-request'):
    pdu_tag = {'get-request': 0xA0, 'get-next': 0xA1, 'response': 0xA2,
               'set-request': 0xA3, 'get-bulk': 0xA5}.get(pdu, 0xA0)
    comm = community.encode('ascii')
    body = b'\x02\x01' + bytes([version])
    body += b'\x04' + bytes([len(comm)]) + comm
    body += bytes([pdu_tag, 0x02, 0x02, 0x01, 0x00])
    return b'\x30' + bytes([len(body)]) + body


def ntp_client(version=4):
    return bytes([(version << 3) | 3]) + b'\x00' * 47


def ntp_monlist_request(version=2):
    # Mode 7 (private), implementation 3 (xntpd), request code 42 (MON_GETLIST)
    return bytes([(version << 3) | 7, 0, 3, 42]) + b'\x00' * 4


def ntp_monlist_response(entries=6, version=2):
    # High bit of byte 0 is the mode-7 response flag.
    header = bytes([0x80 | (version << 3) | 7, 0, 3, 42]) + b'\x00' * 4
    return header + b''.join(bytes((i + n) & 0xFF for i in range(72))
                             for n in range(entries))


def telnet_negotiation():
    return b'\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27'


def telnet_text(text):
    return text.encode('ascii', 'replace')


def smb2_header(command=1):
    return b'\x00\x00\x00\x40' + b'\xfeSMB' + b'\x00' * 4 + \
        struct.pack('<H', command) + b'\x00' * 40


def rdp_connection_request(cookie='administrator'):
    payload = ('Cookie: mstshash=%s\r\n' % cookie).encode('ascii')
    x224 = b'\xe0\x00\x00\x00\x00\x00' + payload
    total = 4 + 1 + len(x224)
    return struct.pack('!BBH', 0x03, 0x00, total) + bytes([len(x224)]) + x224


def dhcp_message(msg_type=1, client_mac='aa:bb:cc:dd:ee:ff', op=1):
    body = struct.pack('!BBBBIHH', op, 1, 6, 0, 0x3903F326, 0, 0x8000)
    body += b'\x00' * 16                       # ci/yi/si/gi addresses
    body += mac_bytes(client_mac) + b'\x00' * 10   # chaddr padded to 16
    body += b'\x00' * 192                      # sname + file
    body += b'\x63\x82\x53\x63'                # magic cookie
    body += bytes([53, 1, msg_type, 255])
    return body


def quic_initial(version=1, dcid_len=8):
    return bytes([0xC0]) + struct.pack('!I', version) + bytes([dcid_len]) + \
        bytes(range(dcid_len)) + b'\x00' * 32


# ── convenience assemblers ───────────────────────────────────────────────────

def tcp_frame(payload, src_ip, dst_ip, src_port, dst_port, flags='PSH|ACK',
              src_mac='02:00:00:00:00:01', dst_mac='02:00:00:00:00:02',
              seq=1, ack=1, ttl=64, ident=0):
    return ethernet(
        ipv4(tcp(payload, src_ip, dst_ip, src_port, dst_port, flags, seq, ack),
             src_ip, dst_ip, 6, ttl=ttl, ident=ident),
        src_mac, dst_mac)


def udp_frame(payload, src_ip, dst_ip, src_port, dst_port,
              src_mac='02:00:00:00:00:01', dst_mac='02:00:00:00:00:02',
              ttl=64, ident=0):
    return ethernet(
        ipv4(udp(payload, src_ip, dst_ip, src_port, dst_port),
             src_ip, dst_ip, 17, ttl=ttl, ident=ident),
        src_mac, dst_mac)


def icmp_frame(payload, src_ip, dst_ip, icmp_type=8, code=0, ident=1, seq=1,
               src_mac='02:00:00:00:00:01', dst_mac='02:00:00:00:00:02'):
    return ethernet(
        ipv4(icmp(payload, icmp_type, code, ident, seq), src_ip, dst_ip, 1),
        src_mac, dst_mac)


def arp_frame(op, sender_mac, sender_ip, target_mac, target_ip,
              dst_mac='ff:ff:ff:ff:ff:ff'):
    return ethernet(arp(op, sender_mac, sender_ip, target_mac, target_ip),
                    sender_mac, dst_mac, ETHERTYPE_ARP)
