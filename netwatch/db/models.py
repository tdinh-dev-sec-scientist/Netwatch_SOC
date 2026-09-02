"""
Normalized PostgreSQL schema for NetWatch, declared with SQLAlchemy 2.0.

Ten tables in three groups.

Reference data (small, seeded once, joined constantly)

    protocols          one row per protocol the analyzer can identify, with
                       its risk band and whether its payload is encrypted
    threat_types       one row per detection rule, with its owning detector
                       and default severity
    mitre_techniques   the ATT&CK catalog

Observations (written by the pipeline, one to three orders of magnitude larger)

    hosts              host inventory, geo enrichment and rollup counters
    packets            one row per processed packet with its decoded L7 fields
    flows              5-tuple flow records, upserted per batch
    alerts             detector findings — the event table the API is built on
    alert_techniques   many-to-many alert <-> ATT&CK technique

Derived / operational

    protocol_stats     per-minute protocol rollup backing the throughput charts
    pipeline_runs      measured pipeline metrics per window

Why these and not others
------------------------
`packets`, `flows` and `alerts` all reference `hosts` by surrogate key rather
than repeating a text IP on every row: at a million packets that is the
difference between storing an address once and storing it two million times,
and it makes "everything about this host" a single indexed join instead of a
string comparison across three tables. The same argument applies to
`protocols` and `threat_types`, which additionally carry attributes (risk,
default severity) that would otherwise be duplicated per row or, worse, live
only in Python.

There is deliberately no `threats` table. A "threat" is an aggregation over
alerts grouped by (source host, threat type); materialising it would be a
denormalised copy of rows `alerts` already holds. The repository derives it
with an indexed GROUP BY.

Index strategy is driven by measured query patterns, not by guesswork — see
``benchmarks/query_benchmark.py``, which measures every API-backing query with
and without the composite indexes defined at the bottom of this module.
"""

import datetime as dt

from sqlalchemy import (
    text as sa_text,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Double,
    Enum,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# A named PostgreSQL enum, so an impossible severity is rejected by the
# database rather than by a convention nobody enforces.
severity_enum = Enum(*SEVERITIES, name='severity_level', create_type=True)

TS = DateTime(timezone=True)


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


class Base(DeclarativeBase):
    pass


# ── reference tables ─────────────────────────────────────────────────────────

class Protocol(Base):
    """Protocols the analyzer can positively identify, plus their risk band."""

    __tablename__ = 'protocols'

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True,
                                    autoincrement=True)
    name: Mapped[str] = mapped_column(String(16), nullable=False, unique=True)
    layer: Mapped[str] = mapped_column(String(4), nullable=False)
    risk: Mapped[str] = mapped_column(String(8), nullable=False, default='INFO',
                                     server_default=sa_text("'INFO'"))
    is_encrypted: Mapped[bool] = mapped_column(Boolean, nullable=False,
                                               default=False,
                                     server_default=sa_text('false'))


class ThreatType(Base):
    """One row per detection rule. `alerts.threat_type_id` points here."""

    __tablename__ = 'threat_types'

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True,
                                    autoincrement=True)
    name: Mapped[str] = mapped_column(String(48), nullable=False, unique=True)
    detector: Mapped[str] = mapped_column(String(48), nullable=False)
    default_severity: Mapped[str] = mapped_column(severity_enum,
                                                  nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default='',
                                     server_default=sa_text("''"))

    __table_args__ = (Index('ix_threat_types_detector', 'detector'),)


class MitreTechnique(Base):
    """ATT&CK catalog. Natural key — the technique ID is the identity."""

    __tablename__ = 'mitre_techniques'

    technique_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    tactic: Mapped[str] = mapped_column(String(48), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=True)
    rationale: Mapped[str] = mapped_column(Text, nullable=True)

    __table_args__ = (Index('ix_mitre_tactic', 'tactic'),)


# ── observation tables ───────────────────────────────────────────────────────

class Host(Base):
    """Host inventory. Every IP the pipeline sees becomes exactly one row."""

    __tablename__ = 'hosts'

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                    autoincrement=True)
    ip: Mapped[str] = mapped_column(INET, nullable=False, unique=True)
    first_seen: Mapped[dt.datetime] = mapped_column(TS, nullable=False)
    last_seen: Mapped[dt.datetime] = mapped_column(TS, nullable=False)
    is_internal: Mapped[bool] = mapped_column(Boolean, nullable=False,
                                              default=False,
                                     server_default=sa_text('false'))
    country: Mapped[str] = mapped_column(String(32), nullable=False,
                                         default='UNKNOWN',
                                     server_default=sa_text("'UNKNOWN'"))
    latitude: Mapped[float] = mapped_column(Double, nullable=True)
    longitude: Mapped[float] = mapped_column(Double, nullable=True)
    packets_sent: Mapped[int] = mapped_column(BigInteger, nullable=False,
                                              default=0,
                                     server_default=sa_text('0'))
    packets_recv: Mapped[int] = mapped_column(BigInteger, nullable=False,
                                              default=0,
                                     server_default=sa_text('0'))
    bytes_sent: Mapped[int] = mapped_column(BigInteger, nullable=False,
                                            default=0,
                                     server_default=sa_text('0'))
    bytes_recv: Mapped[int] = mapped_column(BigInteger, nullable=False,
                                            default=0,
                                     server_default=sa_text('0'))
    alert_count: Mapped[int] = mapped_column(Integer, nullable=False,
                                             default=0,
                                     server_default=sa_text('0'))
    threat_score: Mapped[float] = mapped_column(Double, nullable=False,
                                                default=0.0,
                                     server_default=sa_text('0'))

    __table_args__ = (
        CheckConstraint('threat_score >= 0 AND threat_score <= 100',
                        name='ck_hosts_threat_score'),
        Index('ix_hosts_country', 'country'),
        Index('ix_hosts_packets_sent', packets_sent.desc()),
        Index('ix_hosts_threat_score', threat_score.desc()),
    )


class Packet(Base):
    """One processed packet. The largest table by row count."""

    __tablename__ = 'packets'

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                    autoincrement=True)
    ts: Mapped[dt.datetime] = mapped_column(TS, nullable=False)
    src_host_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey('hosts.id', ondelete='CASCADE'), nullable=False)
    dst_host_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey('hosts.id', ondelete='CASCADE'), nullable=False)
    src_port: Mapped[int] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=True)
    protocol_id: Mapped[int] = mapped_column(
        SmallInteger, ForeignKey('protocols.id'), nullable=False)
    frame_len: Mapped[int] = mapped_column(Integer, nullable=False)
    payload_len: Mapped[int] = mapped_column(Integer, nullable=False,
                                             default=0,
                                     server_default=sa_text('0'))
    tcp_flags: Mapped[str] = mapped_column(String(32), nullable=True)
    entropy: Mapped[float] = mapped_column(Double, nullable=False, default=0.0,
                                     server_default=sa_text('0'))
    is_malicious: Mapped[bool] = mapped_column(Boolean, nullable=False,
                                               default=False,
                                     server_default=sa_text('false'))
    l7: Mapped[dict] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        CheckConstraint('frame_len >= 0', name='ck_packets_frame_len'),
        Index('ix_packets_ts', ts.desc()),
    )


class Flow(Base):
    """5-tuple flow record, upserted once per batch rather than per packet."""

    __tablename__ = 'flows'

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                    autoincrement=True)
    src_host_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey('hosts.id', ondelete='CASCADE'), nullable=False)
    dst_host_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey('hosts.id', ondelete='CASCADE'), nullable=False)
    src_port: Mapped[int] = mapped_column(Integer, nullable=False, default=0,
                                     server_default=sa_text('0'))
    dst_port: Mapped[int] = mapped_column(Integer, nullable=False, default=0,
                                     server_default=sa_text('0'))
    protocol_id: Mapped[int] = mapped_column(
        SmallInteger, ForeignKey('protocols.id'), nullable=False)
    first_seen: Mapped[dt.datetime] = mapped_column(TS, nullable=False)
    last_seen: Mapped[dt.datetime] = mapped_column(TS, nullable=False)
    packets: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0,
                                     server_default=sa_text('0'))
    bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0,
                                     server_default=sa_text('0'))
    flags_seen: Mapped[str] = mapped_column(String(64), nullable=False,
                                            default='',
                                     server_default=sa_text("''"))
    state: Mapped[str] = mapped_column(String(16), nullable=False,
                                       default='ACTIVE',
                                     server_default=sa_text("'ACTIVE'"))

    __table_args__ = (
        UniqueConstraint('src_host_id', 'dst_host_id', 'src_port', 'dst_port',
                         'protocol_id', name='uq_flow_tuple'),
        Index('ix_flows_last_seen', last_seen.desc()),
        Index('ix_flows_bytes', bytes.desc()),
    )


class Alert(Base):
    """A detector finding. This is the event table the REST API is built on."""

    __tablename__ = 'alerts'

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                    autoincrement=True)
    ts: Mapped[dt.datetime] = mapped_column(TS, nullable=False)
    severity: Mapped[str] = mapped_column(severity_enum, nullable=False)
    threat_type_id: Mapped[int] = mapped_column(
        SmallInteger, ForeignKey('threat_types.id'), nullable=False)
    src_host_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey('hosts.id', ondelete='SET NULL'), nullable=True)
    dst_host_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey('hosts.id', ondelete='SET NULL'), nullable=True)
    src_port: Mapped[int] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=True)
    protocol_id: Mapped[int] = mapped_column(
        SmallInteger, ForeignKey('protocols.id'), nullable=True)
    confidence: Mapped[float] = mapped_column(Double, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=True)
    acknowledged: Mapped[bool] = mapped_column(Boolean, nullable=False,
                                               default=False,
                                     server_default=sa_text('false'))
    ack_ts: Mapped[dt.datetime] = mapped_column(TS, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        TS, nullable=False, server_default=func.now())

    techniques = relationship('AlertTechnique', back_populates='alert',
                              cascade='all, delete-orphan')

    __table_args__ = (
        CheckConstraint('confidence >= 0 AND confidence <= 1',
                        name='ck_alerts_confidence'),
        Index('ix_alerts_ts', ts.desc()),
    )


class AlertTechnique(Base):
    """Alert <-> ATT&CK technique. Composite primary key; no surrogate id."""

    __tablename__ = 'alert_techniques'

    alert_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey('alerts.id', ondelete='CASCADE'),
        primary_key=True)
    technique_id: Mapped[str] = mapped_column(
        String(16), ForeignKey('mitre_techniques.technique_id'),
        primary_key=True)
    confidence: Mapped[float] = mapped_column(Double, nullable=False)
    ts: Mapped[dt.datetime] = mapped_column(TS, nullable=False)

    alert = relationship('Alert', back_populates='techniques')

    __table_args__ = (Index('ix_at_technique_ts', 'technique_id', ts.desc()),)


# ── derived / operational tables ─────────────────────────────────────────────

class ProtocolStat(Base):
    """Per-minute rollup. Keeps the throughput chart off the packets table."""

    __tablename__ = 'protocol_stats'

    bucket: Mapped[dt.datetime] = mapped_column(TS, primary_key=True)
    protocol_id: Mapped[int] = mapped_column(
        SmallInteger, ForeignKey('protocols.id'), primary_key=True)
    packets: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0,
                                     server_default=sa_text('0'))
    bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0,
                                     server_default=sa_text('0'))
    alerts: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0,
                                     server_default=sa_text('0'))

    __table_args__ = (Index('ix_pstat_bucket', bucket.desc()),)


class PipelineRun(Base):
    """One measured pipeline window: throughput, loss and latency as observed.

    Nothing here is estimated. `packets_received` is counted at the capture
    stage, `packets_persisted` when a batch commits, and the drop/fail columns
    account for the difference, so `received == persisted + dropped + failed`
    can be asserted rather than assumed.
    """

    __tablename__ = 'pipeline_runs'

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                    autoincrement=True)
    ts: Mapped[dt.datetime] = mapped_column(TS, nullable=False,
                                            server_default=func.now())
    source: Mapped[str] = mapped_column(String(24), nullable=False,
                                        default='engine',
                                     server_default=sa_text("'engine'"))
    window_s: Mapped[float] = mapped_column(Double, nullable=False)
    packets_received: Mapped[int] = mapped_column(BigInteger, nullable=False,
                                                  default=0,
                                     server_default=sa_text('0'))
    packets_parsed: Mapped[int] = mapped_column(BigInteger, nullable=False,
                                                default=0,
                                     server_default=sa_text('0'))
    packets_persisted: Mapped[int] = mapped_column(BigInteger, nullable=False,
                                                   default=0,
                                     server_default=sa_text('0'))
    packets_dropped: Mapped[int] = mapped_column(BigInteger, nullable=False,
                                                 default=0,
                                     server_default=sa_text('0'))
    packets_failed: Mapped[int] = mapped_column(BigInteger, nullable=False,
                                                default=0,
                                     server_default=sa_text('0'))
    alerts_generated: Mapped[int] = mapped_column(BigInteger, nullable=False,
                                                  default=0,
                                     server_default=sa_text('0'))
    packets_per_s: Mapped[float] = mapped_column(Double, nullable=False,
                                                 default=0.0,
                                     server_default=sa_text('0'))
    latency_p50_ms: Mapped[float] = mapped_column(Double, nullable=False,
                                                  default=0.0,
                                     server_default=sa_text('0'))
    latency_p95_ms: Mapped[float] = mapped_column(Double, nullable=False,
                                                  default=0.0,
                                     server_default=sa_text('0'))
    latency_p99_ms: Mapped[float] = mapped_column(Double, nullable=False,
                                                  default=0.0,
                                     server_default=sa_text('0'))
    peak_rss_mb: Mapped[float] = mapped_column(Double, nullable=False,
                                               default=0.0,
                                     server_default=sa_text('0'))
    cpu_percent: Mapped[float] = mapped_column(Double, nullable=False,
                                               default=0.0,
                                     server_default=sa_text('0'))
    stage_json: Mapped[dict] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        CheckConstraint('window_s > 0', name='ck_run_window'),
        Index('ix_pipeline_runs_source_ts', 'source', ts.desc()),
    )


# ── composite indexes ────────────────────────────────────────────────────────
#
# These are the indexes the query benchmark toggles. Each one exists because a
# measured API query was doing a sequential scan plus a sort without it; the
# leading columns are the equality predicates, the trailing column is the
# ORDER BY, so PostgreSQL can walk the index backwards and stop at LIMIT
# instead of sorting the whole matching set.
#
# They are declared here rather than inline so the benchmark can drop and
# recreate exactly this set by name.

COMPOSITE_INDEXES = {
    # /api/alerts?severity=…  — filter on severity, newest first.
    'ix_alerts_severity_ts':
        Index('ix_alerts_severity_ts', Alert.severity, Alert.ts.desc()),
    # /api/alerts?threat_type=… and the per-type stats rollup.
    'ix_alerts_type_ts':
        Index('ix_alerts_type_ts', Alert.threat_type_id, Alert.ts.desc()),
    # /api/alerts?src_ip=… and /api/hosts/<ip> (recent alerts for a host).
    'ix_alerts_src_ts':
        Index('ix_alerts_src_ts', Alert.src_host_id, Alert.ts.desc()),
    # /api/alerts?acknowledged=false — the SOC triage queue.
    'ix_alerts_ack_ts':
        Index('ix_alerts_ack_ts', Alert.acknowledged, Alert.ts.desc()),
    # The threat summary groups by (src_host_id, threat_type_id) over a time
    # window; leading with ts lets the window restrict the scan first.
    'ix_alerts_ts_src_type':
        Index('ix_alerts_ts_src_type', Alert.ts.desc(), Alert.src_host_id,
              Alert.threat_type_id),
    # /api/packets?src_ip=… and the host detail page.
    'ix_packets_src_ts':
        Index('ix_packets_src_ts', Packet.src_host_id, Packet.ts.desc()),
    'ix_packets_dst_ts':
        Index('ix_packets_dst_ts', Packet.dst_host_id, Packet.ts.desc()),
    # /api/packets?protocol=…
    'ix_packets_proto_ts':
        Index('ix_packets_proto_ts', Packet.protocol_id, Packet.ts.desc()),
    # Per-host protocol breakdown: covering, so the GROUP BY never touches
    # the heap.
    'ix_packets_src_proto_len':
        Index('ix_packets_src_proto_len', Packet.src_host_id,
              Packet.protocol_id, Packet.frame_len),
    # /api/connections?src_ip=… and the per-host peer rollup.
    'ix_flows_src_last':
        Index('ix_flows_src_last', Flow.src_host_id, Flow.last_seen.desc()),
    'ix_flows_src_dst':
        Index('ix_flows_src_dst', Flow.src_host_id, Flow.dst_host_id,
              Flow.packets, Flow.bytes),
}

TABLES = tuple(sorted(Base.metadata.tables))
TABLE_COUNT = len(TABLES)
