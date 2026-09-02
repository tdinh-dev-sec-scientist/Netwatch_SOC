"""Deep packet inspection tests: every supported protocol, plus bad input."""

import pytest

from netwatch.analysis.protocol import (
    SUPPORTED_PROTOCOLS,
    ParseError,
    decode_tcp_flags,
    shannon_entropy,
)
from netwatch.capture import frames as F

SRC, DST = '10.0.1.20', '93.184.216.34'


def parse(analyzer, frame):
    pkt = analyzer.parse(frame, ts=1_700_000_000.0)
    assert pkt is not None
    return pkt


# ── layer 2 / 3 ──────────────────────────────────────────────────────────────

def test_ethernet_and_ipv4_headers(analyzer):
    pkt = parse(analyzer, F.tcp_frame(b'', SRC, DST, 40000, 80, 'SYN',
                                      ttl=57, ident=4242))
    assert pkt['src_ip'] == SRC and pkt['dst_ip'] == DST
    assert pkt['ttl'] == 57
    assert pkt['ip_id'] == 4242
    assert pkt['ip_proto'] == 6
    assert pkt['eth_src'] == '02:00:00:00:00:01'
    assert 'ETHERNET' in pkt['layers'] and 'IPv4' in pkt['layers']


def test_ipv6_header(analyzer):
    frame = F.ethernet(
        F.ipv6(F.udp(F.dns_query('example.com'), '10.0.0.1', '10.0.0.2',
                     40000, 53),
               '2001:db8::1', '2001:db8::2', 17, flow_label=0x12345),
        '02:00:00:00:00:01', '02:00:00:00:00:02', F.ETHERTYPE_IPV6)
    pkt = parse(analyzer, frame)
    assert pkt['flow_label'] == 0x12345
    assert pkt['next_header'] == 17
    assert 'IPv6' in pkt['layers']


def test_arp_fields_and_gratuitous_flag(analyzer):
    normal = parse(analyzer, F.arp_frame(1, 'aa:bb:cc:00:00:01', '10.0.1.5',
                                         '00:00:00:00:00:00', '10.0.1.1'))
    assert normal['protocol'] == 'ARP'
    assert normal['arp_op'] == 1
    assert normal['arp_sender_ip'] == '10.0.1.5'
    assert normal['arp_gratuitous'] is False

    grat = parse(analyzer, F.arp_frame(2, 'de:ad:be:ef:00:01', '10.0.1.1',
                                       'de:ad:be:ef:00:01', '10.0.1.1'))
    assert grat['arp_gratuitous'] is True


# ── layer 4 ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize('flags,expected', [
    ('SYN', 'SYN'), ('ACK', 'ACK'), ('SYN|ACK', 'SYN|ACK'),
    ('FIN|ACK', 'FIN|ACK'), ('RST', 'RST'), ('PSH|ACK', 'PSH|ACK'),
])
def test_tcp_flag_roundtrip(analyzer, flags, expected):
    pkt = parse(analyzer, F.tcp_frame(b'', SRC, DST, 40000, 80, flags))
    assert set(pkt['flags'].split('|')) == set(expected.split('|'))


def test_decode_tcp_flags_is_pure():
    assert decode_tcp_flags(0x02) == 'SYN'
    assert decode_tcp_flags(0x12) == 'SYN|ACK'
    assert decode_tcp_flags(0) == 'NONE'


def test_udp_and_icmp(analyzer):
    udp = parse(analyzer, F.udp_frame(b'x' * 40, SRC, DST, 40000, 9999))
    assert udp['src_port'] == 40000 and udp['dst_port'] == 9999
    assert udp['udp_len'] == 48

    icmp = parse(analyzer, F.icmp_frame(b'p' * 56, SRC, DST, ident=7, seq=3))
    assert icmp['protocol'] == 'ICMP'
    assert icmp['icmp_type'] == 8 and icmp['icmp_id'] == 7
    assert icmp['icmp_payload_len'] == 56


# ── layer 7: one assertion per protocol on extracted fields ──────────────────

def test_http_request_fields(analyzer):
    pkt = parse(analyzer, F.tcp_frame(
        F.http_request('POST', '/login?next=/admin', 'shop.example.com',
                       'curl/8.4.0', authorization='Basic YWRtaW46cw=='),
        SRC, DST, 40000, 80))
    assert pkt['protocol'] == 'HTTP'
    assert pkt['http_method'] == 'POST'
    assert pkt['http_uri'] == '/login?next=/admin'
    assert pkt['http_host'] == 'shop.example.com'
    assert pkt['http_user_agent'] == 'curl/8.4.0'
    assert pkt['http_auth'].startswith('Basic ')


def test_http_response_status(analyzer):
    pkt = parse(analyzer, F.tcp_frame(F.http_response(401, 'Unauthorized'),
                                      DST, SRC, 80, 40000))
    assert pkt['protocol'] == 'HTTP' and pkt['http_status'] == 401


def test_dns_query_extracts_name_and_qtype(analyzer):
    pkt = parse(analyzer, F.udp_frame(
        F.dns_query('very-long-subdomain.mail.example.com', 'TXT'),
        SRC, '8.8.8.8', 40000, 53))
    assert pkt['protocol'] == 'DNS'
    assert pkt['dns_qname'] == 'very-long-subdomain.mail.example.com'
    assert pkt['dns_qtype_name'] == 'TXT'
    assert pkt['dns_qr'] == 0
    assert pkt['dns_max_label_len'] == len('very-long-subdomain')


def test_dns_response_rcode(analyzer):
    pkt = parse(analyzer, F.udp_frame(
        F.dns_response('nope.example.com', rcode=3, answers=0),
        '8.8.8.8', SRC, 53, 40000))
    assert pkt['dns_qr'] == 1 and pkt['dns_rcode'] == 3


def test_tls_client_hello_sni_and_ciphers(analyzer):
    pkt = parse(analyzer, F.tcp_frame(
        F.tls_client_hello('secure.example.com', cipher_count=14),
        SRC, DST, 40000, 443))
    assert pkt['protocol'] == 'TLS'
    assert pkt['tls_sni'] == 'secure.example.com'
    assert pkt['tls_cipher_count'] == 14
    assert pkt['tls_has_sni'] is True
    assert pkt['tls_handshake_type'] == 1


def test_tls_obsolete_version_and_missing_sni(analyzer):
    pkt = parse(analyzer, F.tcp_frame(
        F.tls_client_hello(None, version=0x0301, cipher_count=2),
        SRC, DST, 40000, 443))
    assert pkt['tls_client_version'] == 'TLS1.0'
    assert pkt['tls_has_sni'] is False


def test_ssh_banner_and_binary(analyzer):
    banner = parse(analyzer, F.tcp_frame(F.ssh_banner('2.0', 'OpenSSH_9.3'),
                                         SRC, DST, 40000, 22))
    assert banner['protocol'] == 'SSH'
    assert banner['ssh_version'] == '2.0'
    assert banner['ssh_software'] == 'OpenSSH_9.3'

    binary = parse(analyzer, F.tcp_frame(F.ssh_binary(msg_type=21),
                                         SRC, DST, 40000, 22))
    assert binary['protocol'] == 'SSH' and binary['ssh_msg_type'] == 21


@pytest.mark.parametrize('proto,port,line,field,value', [
    ('FTP', 21, '530 Login incorrect', 'ftp_code', 530),
    ('SMTP', 25, '535 5.7.8 Auth failed', 'smtp_code', 535),
    ('POP3', 110, '-ERR invalid password', 'pop3_status', '-ERR'),
])
def test_line_protocol_responses(analyzer, proto, port, line, field, value):
    pkt = parse(analyzer, F.tcp_frame(F.line_protocol(line), DST, SRC,
                                      port, 40000))
    assert pkt['protocol'] == proto
    assert pkt[field] == value


def test_ftp_command_and_arg(analyzer):
    pkt = parse(analyzer, F.tcp_frame(F.line_protocol('USER alice'),
                                      SRC, DST, 40000, 21))
    assert pkt['ftp_command'] == 'USER' and pkt['ftp_arg'] == 'alice'


def test_imap_status_and_command(analyzer):
    fail = parse(analyzer, F.tcp_frame(F.line_protocol('a001 NO LOGIN failed'),
                                       DST, SRC, 143, 40000))
    assert fail['protocol'] == 'IMAP' and fail['imap_status'] == 'NO'

    cmd = parse(analyzer, F.tcp_frame(F.line_protocol('a002 LOGIN bob secret'),
                                      SRC, DST, 40000, 143))
    assert cmd['imap_command'] == 'LOGIN' and cmd['imap_arg'] == 'bob secret'


def test_snmp_community_and_pdu(analyzer):
    pkt = parse(analyzer, F.udp_frame(F.snmp_message('private', 1, 'get-bulk'),
                                      SRC, DST, 40000, 161))
    assert pkt['protocol'] == 'SNMP'
    assert pkt['snmp_community'] == 'private'
    assert pkt['snmp_version'] == 'v2c'
    assert pkt['snmp_pdu_type'] == 'get-bulk'


def test_ntp_modes(analyzer):
    client = parse(analyzer, F.udp_frame(F.ntp_client(), SRC, DST, 40000, 123))
    assert client['protocol'] == 'NTP' and client['ntp_mode'] == 3
    assert client['ntp_is_monlist'] is False

    req = parse(analyzer, F.udp_frame(F.ntp_monlist_request(), SRC, DST,
                                      40000, 123))
    assert req['ntp_mode'] == 7 and req['ntp_is_monlist'] is True
    assert req['ntp_response'] is False

    resp = parse(analyzer, F.udp_frame(F.ntp_monlist_response(), DST, SRC,
                                       123, 40000))
    assert resp['ntp_response'] is True


def test_telnet_smb_rdp_dhcp_quic(analyzer):
    telnet = parse(analyzer, F.tcp_frame(F.telnet_negotiation(), SRC, DST,
                                         40000, 23))
    assert telnet['protocol'] == 'TELNET' and telnet['telnet_negotiation'] == 4

    smb = parse(analyzer, F.tcp_frame(F.smb2_header(5), SRC, DST, 40000, 445))
    assert smb['protocol'] == 'SMB' and smb['smb_dialect'] == 'SMB2'

    rdp = parse(analyzer, F.tcp_frame(F.rdp_connection_request('svc_admin'),
                                      SRC, DST, 40000, 3389))
    assert rdp['protocol'] == 'RDP' and rdp['rdp_cookie'] == 'svc_admin'

    dhcp = parse(analyzer, F.udp_frame(F.dhcp_message(3, 'aa:bb:cc:dd:ee:01'),
                                       '0.0.0.0', '255.255.255.255', 68, 67))
    assert dhcp['protocol'] == 'DHCP' and dhcp['dhcp_msg_type'] == 'REQUEST'
    assert dhcp['dhcp_client_mac'] == 'aa:bb:cc:dd:ee:01'

    quic = parse(analyzer, F.udp_frame(F.quic_initial(version=1), SRC, DST,
                                       40000, 443))
    assert quic['protocol'] == 'QUIC' and quic['quic_version'] == 1


def test_every_supported_protocol_is_reachable(analyzer):
    """Guards the '15+ protocols' claim: each name must be produced by a
    real decode, not merely listed in a constant."""
    samples = [
        F.arp_frame(1, 'aa:bb:cc:00:00:01', '10.0.1.5',
                    '00:00:00:00:00:00', '10.0.1.1'),
        F.tcp_frame(b'', SRC, DST, 40000, 9999, 'SYN'),
        F.udp_frame(b'\x00' * 8, SRC, DST, 40000, 9999),
        F.icmp_frame(b'p' * 32, SRC, DST),
        F.udp_frame(F.dns_query('example.com'), SRC, '8.8.8.8', 40000, 53),
        F.tcp_frame(F.http_request(), SRC, DST, 40000, 80),
        F.tcp_frame(F.tls_client_hello('a.example.com'), SRC, DST, 40000, 443),
        F.tcp_frame(F.ssh_banner(), SRC, DST, 40000, 22),
        F.tcp_frame(F.line_protocol('USER bob'), SRC, DST, 40000, 21),
        F.tcp_frame(F.line_protocol('EHLO host'), SRC, DST, 40000, 25),
        F.tcp_frame(F.line_protocol('+OK ready'), DST, SRC, 110, 40000),
        F.tcp_frame(F.line_protocol('a1 OK done'), DST, SRC, 143, 40000),
        F.udp_frame(F.snmp_message(), SRC, DST, 40000, 161),
        F.udp_frame(F.ntp_client(), SRC, DST, 40000, 123),
        F.tcp_frame(F.telnet_negotiation(), SRC, DST, 40000, 23),
        F.tcp_frame(F.smb2_header(), SRC, DST, 40000, 445),
        F.tcp_frame(F.rdp_connection_request(), SRC, DST, 40000, 3389),
        F.udp_frame(F.dhcp_message(), '0.0.0.0', '255.255.255.255', 68, 67),
        F.udp_frame(F.quic_initial(), SRC, DST, 40000, 443),
    ]
    seen = set()
    for frame in samples:
        pkt = analyzer.safe_parse(frame, ts=1.0)
        assert pkt is not None
        seen.add(pkt['protocol'])
        seen.update(pkt['layers'])

    identified = {p for p in SUPPORTED_PROTOCOLS if p in seen}
    missing = set(SUPPORTED_PROTOCOLS) - seen - {'IPv6'}
    assert not missing, 'never produced by a real decode: %s' % sorted(missing)
    assert len(identified) >= 15


# ── robustness ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize('bad', [
    b'', b'\x00', b'\x01' * 13, 'not bytes', None, 12345,
])
def test_malformed_input_raises_parse_error(analyzer, bad):
    with pytest.raises((ParseError, TypeError, AttributeError)):
        analyzer.parse(bad, ts=1.0)


@pytest.mark.parametrize('bad', [
    b'', b'\x00' * 13, b'\xff' * 14, b'\x00' * 14 + b'\x45',
])
def test_safe_parse_never_raises(analyzer, bad):
    assert analyzer.safe_parse(bad, ts=1.0) is None
    assert analyzer.parse_errors > 0


def test_truncated_upper_layers_degrade_gracefully(analyzer):
    """A cut-short TCP header must not lose the IP layer already decoded."""
    frame = F.ethernet(F.ipv4(b'\x00\x50', SRC, DST, 6), '02:00:00:00:00:01',
                       '02:00:00:00:00:02')
    pkt = analyzer.parse(frame, ts=1.0)
    assert pkt['src_ip'] == SRC
    assert pkt['truncated'] is True


def test_truncated_dns_name_does_not_crash(analyzer):
    import struct
    header = struct.pack('!HHHHHH', 1, 0x0100, 1, 0, 0, 0)
    body = b'\x3fthisnameclaimsmorebytesthanarepresent'
    pkt = analyzer.safe_parse(
        F.udp_frame(header + body, SRC, '8.8.8.8', 40000, 53), ts=1.0)
    assert pkt is not None and pkt['protocol'] == 'DNS'
    assert pkt['truncated'] is True


def test_unsupported_ethertype_rejected(analyzer):
    with pytest.raises(ParseError):
        analyzer.parse(F.ethernet(b'\x00' * 20, '02:00:00:00:00:01',
                                  '02:00:00:00:00:02', 0x88CC), ts=1.0)


def test_wrong_port_does_not_force_wrong_protocol(analyzer):
    """Signature identification must beat the port hint."""
    pkt = parse(analyzer, F.tcp_frame(F.ssh_banner(), SRC, DST, 40000, 443))
    assert pkt['protocol'] == 'SSH'
    assert pkt['nonstandard_port'] is True


def test_standard_port_is_not_flagged_nonstandard(analyzer):
    pkt = parse(analyzer, F.tcp_frame(F.http_request(), SRC, DST, 40000, 80))
    assert pkt.get('nonstandard_port') is False


# ── entropy ──────────────────────────────────────────────────────────────────

def test_entropy_bounds_and_ordering():
    assert shannon_entropy(b'') == 0.0
    assert shannon_entropy(b'\x00' * 512) == 0.0
    uniform = shannon_entropy(bytes(range(256)) * 2)
    assert 7.9 <= uniform <= 8.0
    assert shannon_entropy(b'AAAA' * 64) < shannon_entropy(
        bytes(range(256)))


def test_icmp_payload_entropy_recorded(analyzer):
    low = parse(analyzer, F.icmp_frame(b'\x00' * 256, SRC, DST))
    high = parse(analyzer, F.icmp_frame(bytes(range(256)), SRC, DST))
    assert low['entropy'] == 0.0
    assert high['entropy'] > 7.0
