"""
NetWatch SOC Dashboard - Network Security Monitoring & Threat Detection
Real-time packet analysis with MITRE ATT&CK framework integration
"""

import os
import json
import time
import random
import threading
import datetime
from flask import Flask, render_template, jsonify, request
from database.db_manager import DatabaseManager
from modules.threat_detector import ThreatDetector
from modules.protocol_analyzer import ProtocolAnalyzer
from modules.packet_simulator import PacketSimulator

app = Flask(__name__)
app.config['SECRET_KEY'] = 'netwatch-soc-2024'

# Initialize core components
db = DatabaseManager()
threat_detector = ThreatDetector(db)
protocol_analyzer = ProtocolAnalyzer()
simulator = PacketSimulator(db, threat_detector, protocol_analyzer)

# Start background simulation (replaces Scapy in demo mode)
sim_thread = threading.Thread(target=simulator.run, daemon=True)
sim_thread.start()

# ─── Dashboard Routes ──────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('dashboard.html')

# ─── API: Live Stats ───────────────────────────────────────────────────────────

@app.route('/api/stats/overview')
def stats_overview():
    stats = db.get_overview_stats()
    return jsonify(stats)

@app.route('/api/stats/packets_per_minute')
def packets_per_minute():
    data = db.get_packets_per_minute(minutes=30)
    return jsonify(data)

@app.route('/api/stats/protocol_distribution')
def protocol_distribution():
    data = db.get_protocol_distribution()
    return jsonify(data)

@app.route('/api/stats/top_talkers')
def top_talkers():
    data = db.get_top_talkers(limit=10)
    return jsonify(data)

@app.route('/api/stats/geo_traffic')
def geo_traffic():
    data = db.get_geo_traffic()
    return jsonify(data)

@app.route('/api/stats/threat_timeline')
def threat_timeline():
    data = db.get_threat_timeline(hours=24)
    return jsonify(data)

@app.route('/api/stats/severity_breakdown')
def severity_breakdown():
    data = db.get_severity_breakdown()
    return jsonify(data)

# ─── API: Alerts ──────────────────────────────────────────────────────────────

@app.route('/api/alerts/recent')
def recent_alerts():
    limit = request.args.get('limit', 50, type=int)
    severity = request.args.get('severity', None)
    data = db.get_recent_alerts(limit=limit, severity=severity)
    return jsonify(data)

@app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    db.acknowledge_alert(alert_id)
    return jsonify({'status': 'acknowledged', 'id': alert_id})

@app.route('/api/alerts/stats')
def alert_stats():
    data = db.get_alert_stats()
    return jsonify(data)

# ─── API: MITRE ATT&CK ────────────────────────────────────────────────────────

@app.route('/api/mitre/techniques')
def mitre_techniques():
    data = db.get_mitre_technique_counts()
    return jsonify(data)

@app.route('/api/mitre/heatmap')
def mitre_heatmap():
    data = db.get_mitre_heatmap()
    return jsonify(data)

# ─── API: Network Events ──────────────────────────────────────────────────────

@app.route('/api/events/stream')
def event_stream():
    events = db.get_recent_events(limit=100)
    return jsonify(events)

@app.route('/api/events/search')
def search_events():
    query = request.args.get('q', '')
    protocol = request.args.get('protocol', '')
    src_ip = request.args.get('src_ip', '')
    dst_ip = request.args.get('dst_ip', '')
    limit = request.args.get('limit', 100, type=int)
    results = db.search_events(query=query, protocol=protocol,
                                src_ip=src_ip, dst_ip=dst_ip, limit=limit)
    return jsonify(results)

# ─── API: Performance ─────────────────────────────────────────────────────────

@app.route('/api/performance/db')
def db_performance():
    data = db.get_performance_stats()
    return jsonify(data)

if __name__ == '__main__':
    print("🔐 NetWatch SOC Dashboard starting...")
    print("📡 Packet simulation engine: ACTIVE")
    print("🛡️  Threat detection engine: ACTIVE")
    print("🌐 Dashboard: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)