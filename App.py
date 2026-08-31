"""
NetWatch SOC — Flask application and REST API.

Every endpoint reads from SQLite through DatabaseManager. Nothing returns
hardcoded or synthesised data: if the database is empty, endpoints return
empty collections rather than filler.

Run:
    python App.py                      # dashboard + live simulation on :5001
    NETWATCH_SIMULATE=0 python App.py  # API only, no traffic generation
"""

import os
import threading

from flask import Flask, jsonify, render_template, request

import config as config_module
import detectors
import mitre
from DB_Manager import DatabaseManager
from PacketSimulator import PacketSimulator, TrafficGenerator
from ProtocolAnalyzer import SUPPORTED_PROTOCOLS, ProtocolAnalyzer
from ThreatDetector import ThreatDetector

SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')


class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status


def _int_arg(name, default, low, high):
    raw = request.args.get(name)
    if raw is None or raw == '':
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ApiError("'%s' must be an integer, got %r" % (name, raw))
    if not low <= value <= high:
        raise ApiError("'%s' must be between %d and %d, got %d"
                       % (name, low, high, value))
    return value


def _choice_arg(name, allowed, default=None):
    raw = request.args.get(name)
    if raw is None or raw == '':
        return default
    if raw not in allowed:
        raise ApiError("'%s' must be one of %s, got %r"
                       % (name, ', '.join(sorted(allowed)), raw))
    return raw


def _bool_arg(name, default=None):
    raw = request.args.get(name)
    if raw is None or raw == '':
        return default
    if raw.lower() in ('1', 'true', 'yes'):
        return True
    if raw.lower() in ('0', 'false', 'no'):
        return False
    raise ApiError("'%s' must be a boolean, got %r" % (name, raw))


def create_app(db=None, engine=None, simulator=None, start_simulation=None):
    """Build the Flask app. Tests inject their own db/engine and no simulator."""
    app = Flask(__name__)
    cfg = config_module.load()

    app.db = db or DatabaseManager()
    app.engine = engine or ThreatDetector(app.db, cfg=cfg)
    app.analyzer = ProtocolAnalyzer()
    app.simulator = simulator
    app.cfg = cfg

    if start_simulation is None:
        start_simulation = os.environ.get('NETWATCH_SIMULATE', '1') != '0'
    if start_simulation and app.simulator is None:
        app.simulator = PacketSimulator(app.db, app.engine, app.analyzer)
        threading.Thread(target=app.simulator.run, daemon=True).start()

    _register(app)
    return app


def _register(app):
    db = app.db
    engine = app.engine

    @app.errorhandler(ApiError)
    def _api_error(err):
        return jsonify({'error': err.message, 'status': err.status}), err.status

    @app.errorhandler(404)
    def _not_found(_err):
        return jsonify({'error': 'resource not found', 'status': 404}), 404

    @app.errorhandler(500)
    def _server_error(_err):
        return jsonify({'error': 'internal server error', 'status': 500}), 500

    # ── dashboard ────────────────────────────────────────────────────────────

    @app.route('/')
    def index():
        return render_template('Dashboard.html')

    # ── 1. system health ─────────────────────────────────────────────────────

    @app.route('/api/health')
    def health():
        info = db.health()
        info['engine'] = {
            'detectors': len(engine.detectors),
            'threat_types': len(set(engine.threat_types())),
            'techniques': len(engine.techniques_covered()),
            'protocols_supported': len(SUPPORTED_PROTOCOLS),
            'packets_analyzed': engine.packets_analyzed,
            'findings_total': engine.findings_total,
            'detector_errors': engine.detector_errors,
        }
        info['simulation_running'] = bool(
            app.simulator and app.simulator._running)
        return jsonify(info)

    # ── 2-6. aggregate statistics ────────────────────────────────────────────

    @app.route('/api/stats/overview')
    def stats_overview():
        return jsonify(db.get_overview())

    @app.route('/api/stats/throughput')
    def stats_throughput():
        minutes = _int_arg('minutes', 60, 1, 10080)
        return jsonify(db.get_throughput(minutes=minutes))

    @app.route('/api/stats/protocols')
    def stats_protocols():
        minutes = _int_arg('minutes', 1440, 1, 10080)
        return jsonify(db.get_protocol_distribution(minutes=minutes))

    @app.route('/api/stats/severity')
    def stats_severity():
        hours = _int_arg('hours', 24, 1, 720)
        return jsonify(db.get_severity_breakdown(hours=hours))

    @app.route('/api/stats/timeline')
    def stats_timeline():
        hours = _int_arg('hours', 24, 1, 720)
        bucket = _int_arg('bucket_s', 3600, 60, 86400)
        return jsonify(db.get_alert_timeline(hours=hours, bucket_s=bucket))

    # ── 7-10. alerts ─────────────────────────────────────────────────────────

    @app.route('/api/alerts')
    def alerts_list():
        return jsonify(db.get_alerts(
            limit=_int_arg('limit', 50, 1, 500),
            offset=_int_arg('offset', 0, 0, 1_000_000),
            severity=_choice_arg('severity', SEVERITIES),
            threat_type=request.args.get('threat_type') or None,
            src_ip=request.args.get('src_ip') or None,
            acknowledged=_bool_arg('acknowledged'),
        ))

    @app.route('/api/alerts/<int:alert_id>')
    def alert_detail(alert_id):
        alert = db.get_alert(alert_id)
        if alert is None:
            raise ApiError('alert %d not found' % alert_id, 404)
        return jsonify(alert)

    @app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
    def alert_acknowledge(alert_id):
        if db.acknowledge_alert(alert_id) == 0:
            raise ApiError('alert %d not found' % alert_id, 404)
        return jsonify({'id': alert_id, 'acknowledged': True})

    @app.route('/api/alerts/stats')
    def alert_stats():
        hours = _int_arg('hours', 24, 1, 720)
        return jsonify(db.get_alert_stats_by_type(hours=hours))

    # ── 11-12. threats ───────────────────────────────────────────────────────

    @app.route('/api/threats/summary')
    def threats_summary():
        return jsonify(db.get_threat_summary(
            hours=_int_arg('hours', 24, 1, 720),
            limit=_int_arg('limit', 50, 1, 500)))

    @app.route('/api/threats/types')
    def threat_types():
        """Detector catalog joined with how often each has actually fired."""
        counts = {r['threat_type']: r
                  for r in db.get_alert_stats_by_type(hours=24 * 365)}
        out = []
        for entry in detectors.catalog():
            seen = counts.get(entry['threat_type'], {})
            out.append({**entry,
                        'alert_count': seen.get('count', 0),
                        'avg_confidence': seen.get('avg_conf'),
                        'last_seen': seen.get('last_seen')})
        return jsonify(out)

    # ── 13-15. MITRE ATT&CK ──────────────────────────────────────────────────

    @app.route('/api/mitre/techniques')
    def mitre_techniques():
        hours = _int_arg('hours', 0, 0, 8760) or None
        return jsonify(db.get_mitre_techniques(hours=hours))

    @app.route('/api/mitre/techniques/<technique_id>')
    def mitre_technique_detail(technique_id):
        tech = db.get_mitre_technique(
            technique_id, limit=_int_arg('limit', 25, 1, 200))
        if tech is None:
            raise ApiError('technique %s not in catalog' % technique_id, 404)
        return jsonify(tech)

    @app.route('/api/mitre/coverage')
    def mitre_coverage():
        return jsonify({
            'catalogued_techniques': mitre.technique_count(),
            'tactics': mitre.tactics(),
            'coverage': db.get_mitre_coverage(),
        })

    # ── 16-18. hosts and geography ───────────────────────────────────────────

    @app.route('/api/hosts/top')
    def hosts_top():
        return jsonify(db.get_top_hosts(
            limit=_int_arg('limit', 15, 1, 200),
            order=_choice_arg(
                'order',
                ('packets_sent', 'bytes_sent', 'threat_score', 'alert_count',
                 'packets_recv'), 'packets_sent')))

    @app.route('/api/hosts/<ip>')
    def host_detail(ip):
        host = db.get_host(ip)
        if host is None:
            raise ApiError('host %s not observed' % ip, 404)
        return jsonify(host)

    @app.route('/api/geo')
    def geo():
        return jsonify(db.get_geo_distribution())

    # ── 19-20. raw telemetry ─────────────────────────────────────────────────

    @app.route('/api/connections')
    def connections():
        return jsonify(db.get_connections(
            limit=_int_arg('limit', 50, 1, 500),
            order=_choice_arg('order',
                              ('last_seen', 'bytes', 'packets', 'first_seen'),
                              'last_seen'),
            src_ip=request.args.get('src_ip') or None))

    @app.route('/api/packets')
    def packets():
        return jsonify(db.get_packets(
            limit=_int_arg('limit', 100, 1, 1000),
            protocol=_choice_arg('protocol', SUPPORTED_PROTOCOLS),
            src_ip=request.args.get('src_ip') or None,
            dst_ip=request.args.get('dst_ip') or None,
            malicious_only=_bool_arg('malicious_only', False)))

    # ── 21-23. engine introspection ──────────────────────────────────────────

    @app.route('/api/performance')
    def performance():
        rows = db.get_performance(
            limit=_int_arg('limit', 120, 1, 1000),
            source=_choice_arg('source', ('engine', 'benchmark')))
        live = app.simulator.stats() if app.simulator else None
        return jsonify({'history': rows, 'live': live})

    @app.route('/api/detectors')
    def detector_stats():
        return jsonify(engine.stats())

    @app.route('/api/protocols')
    def protocol_catalog():
        analyzer = app.analyzer
        seen = analyzer.stats
        return jsonify([
            {'protocol': name,
             'risk': ProtocolAnalyzer.get_risk(name),
             'encrypted': ProtocolAnalyzer.is_encrypted(name),
             'packets_parsed': seen.get(name, 0)}
            for name in SUPPORTED_PROTOCOLS
        ])

    @app.route('/api/scenarios')
    def scenarios():
        """Attack scenarios the simulator can replay, with expected outcomes."""
        return jsonify([
            {'name': name, 'expected_threats': expected}
            for name, (_m, expected) in TrafficGenerator.SCENARIOS.items()
        ])

    return app


if __name__ == '__main__':
    application = create_app()
    debug = os.environ.get('SOC_DEBUG', 'false').lower() == 'true'
    # Never expose the Werkzeug debugger beyond loopback.
    host = '127.0.0.1' if debug else os.environ.get('NETWATCH_HOST',
                                                    '127.0.0.1')
    port = int(os.environ.get('NETWATCH_PORT', '5001'))
    print('NetWatch SOC  |  detectors=%d  techniques=%d  protocols=%d'
          % (len(application.engine.detectors),
             len(application.engine.techniques_covered()),
             len(SUPPORTED_PROTOCOLS)))
    print('Dashboard: http://%s:%d   debug=%s' % (host, port, debug))
    application.run(debug=debug, host=host, port=port, threaded=True,
                    use_reloader=False)
