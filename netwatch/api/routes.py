"""
REST endpoints.

Conventions every endpoint follows:

  * Collections return a pagination envelope — ``total``, ``count``,
    ``limit``, ``offset``, ``has_more``, ``next_offset`` — alongside the named
    array of items. A caller can page without guessing when to stop.
  * Filters and sort keys are validated against allow-lists before they reach
    the repository; an unknown value is a 400 naming what was allowed.
  * Errors are the single contract from ``netwatch.api.errors``.
  * Timestamps appear twice: ``ts`` as a unix float for charting, ``ts_iso``
    as RFC 3339 for humans.
"""

from flask import Blueprint, current_app, jsonify, render_template

from netwatch import detectors, mitre
from netwatch.analysis.protocol import SUPPORTED_PROTOCOLS, ProtocolAnalyzer
from netwatch.api.errors import NotFoundError, ServiceUnavailable, ValidationError
from netwatch.api.params import (
    bool_arg,
    choice_arg,
    float_arg,
    int_arg,
    ip_arg,
    json_body,
    pagination,
    sort_args,
    str_arg,
)
from netwatch.db.repository import (
    ALERT_SORTS,
    FLOW_SORTS,
    HOST_SORTS,
    PACKET_SORTS,
)
from netwatch.db.models import SEVERITIES

bp = Blueprint('api', __name__)
ui = Blueprint('ui', __name__)

THREAT_TYPES = tuple(sorted(detectors.THREAT_TYPES))


def repo():
    return current_app.repository


def _pipeline():
    return getattr(current_app, 'pipeline', None)


# ── dashboard ────────────────────────────────────────────────────────────────

@ui.route('/')
def index():
    return render_template('Dashboard.html')


# ── 1. health ────────────────────────────────────────────────────────────────

@bp.route('/health')
def health():
    """Liveness plus enough substance to be worth probing.

    A process that is listening but cannot reach its database, or whose schema
    is incomplete, is not healthy — so the check counts rows in every table
    and reports the pipeline's own accounting alongside.
    """
    try:
        info = repo().health()
    except Exception as exc:      # noqa: BLE001 - reported, not raised
        raise ServiceUnavailable('database unavailable',
                                 {'reason': type(exc).__name__}) from exc
    info['schema_complete'] = info['table_count'] == 10
    info['detectors'] = len(current_app.rules_engine.detectors)
    info['protocols_supported'] = len(SUPPORTED_PROTOCOLS)
    pipeline = _pipeline()
    info['pipeline_running'] = bool(pipeline and pipeline.capture.alive())
    return jsonify(info)


# ── 2-6. aggregate statistics ────────────────────────────────────────────────

@bp.route('/stats/overview')
def stats_overview():
    return jsonify(repo().get_overview())


@bp.route('/stats/throughput')
def stats_throughput():
    minutes = int_arg('minutes', 60, 1, 10080)
    rows = repo().get_throughput(minutes=minutes)
    return jsonify({'minutes': minutes, 'count': len(rows), 'buckets': rows})


@bp.route('/stats/protocols')
def stats_protocols():
    minutes = int_arg('minutes', 1440, 1, 10080)
    rows = repo().get_protocol_distribution(minutes=minutes)
    return jsonify({'minutes': minutes, 'count': len(rows),
                    'protocols': rows})


@bp.route('/stats/severity')
def stats_severity():
    hours = int_arg('hours', 24, 1, 720)
    rows = repo().get_severity_breakdown(hours=hours)
    return jsonify({'hours': hours, 'count': len(rows), 'severities': rows})


@bp.route('/stats/timeline')
def stats_timeline():
    hours = int_arg('hours', 24, 1, 720)
    bucket = int_arg('bucket_s', 3600, 60, 86400)
    rows = repo().get_alert_timeline(hours=hours, bucket_s=bucket)
    return jsonify({'hours': hours, 'bucket_s': bucket, 'count': len(rows),
                    'buckets': rows})


# ── 7-11. alerts ─────────────────────────────────────────────────────────────

@bp.route('/alerts')
def alerts_list():
    limit, offset = pagination(50)
    sort, order = sort_args(tuple(ALERT_SORTS), 'ts')
    return jsonify(repo().get_alerts(
        limit=limit, offset=offset, sort=sort, order=order,
        severity=choice_arg('severity', SEVERITIES),
        threat_type=choice_arg('threat_type', THREAT_TYPES),
        src_ip=ip_arg('src_ip'), dst_ip=ip_arg('dst_ip'),
        acknowledged=bool_arg('acknowledged'),
        since=float_arg('since', None, 0, 4e9),
        until=float_arg('until', None, 0, 4e9),
        min_confidence=float_arg('min_confidence', None, 0.0, 1.0)))


@bp.route('/alerts/stats')
def alert_stats():
    hours = int_arg('hours', 24, 1, 720)
    rows = repo().get_alert_stats_by_type(hours=hours)
    return jsonify({'hours': hours, 'count': len(rows), 'threat_types': rows})


@bp.route('/alerts/<int:alert_id>')
def alert_detail(alert_id):
    alert = repo().get_alert(alert_id)
    if alert is None:
        raise NotFoundError('alert %d not found' % alert_id,
                            {'alert_id': alert_id})
    return jsonify(alert)


@bp.route('/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def alert_acknowledge(alert_id):
    if repo().acknowledge_alert(alert_id) == 0:
        raise NotFoundError('alert %d not found' % alert_id,
                            {'alert_id': alert_id})
    return jsonify({'id': alert_id, 'acknowledged': True})


@bp.route('/alerts/acknowledge', methods=['POST'])
def alerts_bulk_acknowledge():
    """Acknowledge a batch of alerts in one statement.

    A triage UI acknowledges a screenful at a time; making that N requests
    and N transactions would be the API forcing its own inefficiency on the
    caller.
    """
    body = json_body(required_keys=('ids',))
    ids = body['ids']
    if not isinstance(ids, list) or not ids:
        raise ValidationError("'ids' must be a non-empty array",
                              {'received': type(ids).__name__})
    if len(ids) > 500:
        raise ValidationError('at most 500 ids per request',
                              {'received': len(ids)})
    if not all(isinstance(i, int) for i in ids):
        raise ValidationError("'ids' must contain integers only")
    acknowledged = bool(body.get('acknowledged', True))
    updated = repo().acknowledge_alerts(ids, acknowledged=acknowledged)
    return jsonify({'requested': len(ids), 'updated': updated,
                    'acknowledged': acknowledged,
                    'not_found': len(set(ids)) - updated})


# ── 12-13. threats ───────────────────────────────────────────────────────────

@bp.route('/threats/summary')
def threats_summary():
    hours = int_arg('hours', 24, 1, 720)
    limit = int_arg('limit', 50, 1, 500)
    rows = repo().get_threat_summary(hours=hours, limit=limit)
    return jsonify({'hours': hours, 'count': len(rows), 'threats': rows})


@bp.route('/threats/types')
def threat_types():
    """The detector catalog joined with how often each has actually fired."""
    observed = {row['threat_type']: row for row in repo().get_threat_types()}
    out = []
    for entry in detectors.catalog():
        seen = observed.get(entry['threat_type'], {})
        out.append({**entry,
                    'alert_count': seen.get('alert_count', 0),
                    'avg_confidence': seen.get('avg_confidence'),
                    'last_seen': seen.get('last_seen')})
    return jsonify({'count': len(out), 'threat_types': out})


# ── 14-16. MITRE ATT&CK ──────────────────────────────────────────────────────

@bp.route('/mitre/techniques')
def mitre_techniques():
    hours = int_arg('hours', 0, 0, 8760) or None
    rows = repo().get_mitre_techniques(hours=hours)
    return jsonify({'hours': hours, 'count': len(rows), 'techniques': rows})


@bp.route('/mitre/techniques/<technique_id>')
def mitre_technique_detail(technique_id):
    tech = repo().get_mitre_technique(
        technique_id, limit=int_arg('limit', 25, 1, 200))
    if tech is None:
        raise NotFoundError('technique %s is not in the catalog'
                            % technique_id, {'technique_id': technique_id})
    return jsonify(tech)


@bp.route('/mitre/coverage')
def mitre_coverage():
    return jsonify({'catalogued_techniques': mitre.technique_count(),
                    'tactics': mitre.tactics(),
                    'coverage': repo().get_mitre_coverage()})


# ── 17-19. hosts and geography ───────────────────────────────────────────────

@bp.route('/hosts')
def hosts_list():
    limit, offset = pagination(25, max_limit=200)
    return jsonify(repo().get_hosts(
        limit=limit, offset=offset,
        order=choice_arg('order', tuple(HOST_SORTS), 'packets_sent'),
        country=str_arg('country', max_len=32),
        internal=bool_arg('internal'),
        min_threat_score=float_arg('min_threat_score', None, 0.0, 100.0)))


@bp.route('/hosts/<ip>')
def host_detail(ip):
    host = repo().get_host(ip)
    if host is None:
        raise NotFoundError('host %s has not been observed' % ip, {'ip': ip})
    return jsonify(host)


@bp.route('/geo')
def geo():
    rows = repo().get_geo_distribution()
    return jsonify({'count': len(rows), 'countries': rows})


# ── 20-21. raw telemetry ─────────────────────────────────────────────────────

@bp.route('/flows')
def flows():
    limit, offset = pagination(50)
    return jsonify(repo().get_flows(
        limit=limit, offset=offset,
        order=choice_arg('order', tuple(FLOW_SORTS), 'last_seen'),
        src_ip=ip_arg('src_ip'), dst_ip=ip_arg('dst_ip'),
        protocol=choice_arg('protocol', SUPPORTED_PROTOCOLS),
        min_bytes=int_arg('min_bytes', None, 0, 2 ** 40)))


@bp.route('/packets')
def packets():
    limit, offset = pagination(100, max_limit=500)
    sort, order = sort_args(tuple(PACKET_SORTS), 'ts')
    return jsonify(repo().get_packets(
        limit=limit, offset=offset, sort=sort, order=order,
        protocol=choice_arg('protocol', SUPPORTED_PROTOCOLS),
        src_ip=ip_arg('src_ip'), dst_ip=ip_arg('dst_ip'),
        malicious_only=bool_arg('malicious_only', False),
        since=float_arg('since', None, 0, 4e9),
        until=float_arg('until', None, 0, 4e9),
        min_entropy=float_arg('min_entropy', None, 0.0, 8.0)))


# ── 22-24. pipeline observability ────────────────────────────────────────────

@bp.route('/pipeline/metrics')
def pipeline_metrics():
    """Live stage-by-stage view: queue depths, service times, loss ledger.

    Answers, without a query: how many packets entered, how many were
    processed, how many were dropped, which stage is slow, how full the queues
    are, and what the end-to-end latency distribution looks like.
    """
    pipeline = _pipeline()
    if pipeline is None:
        return jsonify({'running': False,
                        'reason': 'no pipeline in this process',
                        'feed': current_app.feed.snapshot()
                        if getattr(current_app, 'feed', None) else None})
    return jsonify(pipeline.snapshot())


@bp.route('/pipeline/runs')
def pipeline_runs():
    limit, offset = pagination(50, max_limit=500)
    return jsonify(repo().get_pipeline_runs(
        limit=limit, offset=offset,
        source=choice_arg('source', ('engine', 'benchmark', 'soak'))))


@bp.route('/live/alerts')
def live_alerts():
    """The most recent alerts straight from the in-memory feed.

    Bounded and lossy by design — it is a live tail, not a query. The durable
    copy of every alert is in PostgreSQL behind /api/alerts, and the response
    says how many entries the ring has evicted so a reader is never misled
    into thinking this is complete.
    """
    feed = getattr(current_app, 'feed', None)
    if feed is None:
        raise ServiceUnavailable('no live feed in this process')
    alerts = feed.recent_alerts(
        limit=int_arg('limit', 50, 1, 500),
        severity=choice_arg('severity', SEVERITIES),
        threat_type=choice_arg('threat_type', THREAT_TYPES))
    return jsonify({**feed.snapshot(), 'count': len(alerts),
                    'alerts': alerts})


# ── 25-27. engine introspection ──────────────────────────────────────────────

@bp.route('/detectors')
def detector_stats():
    return jsonify(current_app.rules_engine.stats())


@bp.route('/protocols')
def protocol_catalog():
    rows = repo().get_protocol_catalog()
    return jsonify({'count': len(rows), 'protocols': rows})


@bp.route('/scenarios')
def scenarios():
    """Attack scenarios the traffic generator can replay, with ground truth."""
    from netwatch.capture.generator import TrafficGenerator
    return jsonify({
        'count': len(TrafficGenerator.SCENARIOS),
        'scenarios': [{'name': name, 'expected_threats': expected}
                      for name, (_m, expected)
                      in sorted(TrafficGenerator.SCENARIOS.items())]})
