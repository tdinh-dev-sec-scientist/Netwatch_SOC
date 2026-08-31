"""
Detector registry.

Each entry maps a detector class to the config section that tunes it. The
engine instantiates every registered detector once and feeds it every packet.
Adding a threat type means adding a class and one line here.
"""

from .arp import ARPSpoofDetector
from .base import Detector, Finding, is_internal
from .c2 import C2BeaconDetector, TLSAnomalyDetector
from .credential import BruteForceDetector, CredentialAttackDetector
from .dns import DNSTunnelDetector, SuspiciousDNSDetector
from .dos import AmplificationDetector, SYNFloodDetector, UDPFloodDetector
from .exfil import DataExfiltrationDetector
from .lateral import LateralMovementDetector
from .recon import NetworkReconDetector, PortScanDetector
from .tunnel import ICMPTunnelDetector, ProtocolTunnelDetector
from .web import HTTPAnomalyDetector

# (detector class, config section name)
REGISTRY = [
    (PortScanDetector, 'port_scan'),
    (NetworkReconDetector, 'network_recon'),
    (BruteForceDetector, 'brute_force'),
    (CredentialAttackDetector, 'credential_attack'),
    (C2BeaconDetector, 'c2_beacon'),
    (TLSAnomalyDetector, 'tls_anomaly'),
    (DNSTunnelDetector, 'dns_tunnel'),
    (SuspiciousDNSDetector, 'suspicious_dns'),
    (ICMPTunnelDetector, 'icmp_tunnel'),
    (ProtocolTunnelDetector, 'protocol_tunnel'),
    (DataExfiltrationDetector, 'data_exfil'),
    (LateralMovementDetector, 'lateral_movement'),
    (SYNFloodDetector, 'syn_flood'),
    (UDPFloodDetector, 'udp_flood'),
    (AmplificationDetector, 'amplification'),
    (HTTPAnomalyDetector, 'http_anomaly'),
    (ARPSpoofDetector, 'arp_spoof'),
]

THREAT_TYPES = tuple(cls.threat_type for cls, _ in REGISTRY)


def build_all(cfg):
    """Instantiate every registered detector against the supplied config."""
    return [cls(cfg[section]) for cls, section in REGISTRY]


def catalog():
    """Machine-readable description of every detector, for the API."""
    return [
        {
            'name': cls.name,
            'threat_type': cls.threat_type,
            'description': cls.description,
            'techniques': list(cls.techniques),
            'config_section': section,
        }
        for cls, section in REGISTRY
    ]


__all__ = [
    'REGISTRY', 'THREAT_TYPES', 'build_all', 'catalog',
    'Detector', 'Finding', 'is_internal',
]
