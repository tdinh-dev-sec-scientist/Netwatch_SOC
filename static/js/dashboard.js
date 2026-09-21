/* ══════════════════════════════════════════════════════════════════
   NetWatch SOC dashboard.

   Every module below is driven by a REST call to the Flask API, which
   reads from PostgreSQL. There is no seeded, mocked or placeholder data in
   this file: if an endpoint returns nothing, the module renders an
   explicit empty state so a missing pipeline is visible rather than
   disguised.
══════════════════════════════════════════════════════════════════ */

const SEV_COLOR = { CRITICAL:'#ff2d55', HIGH:'#ff6b2b', MEDIUM:'#ffd60a', LOW:'#00ff88', INFO:'#00d4ff' };
const PALETTE = ['#00d4ff','#00ff88','#ffd60a','#bf5af2','#ff9f0a','#ff2d55','#00aacc','#00cc6a','#ff6b2b','#7899b0'];
const charts = {};
let currentView = 'overview';
let alertFilters = { severity: '', src_ip: '' };
let pktFilters = { protocol: '', src_ip: '', malicious_only: false };

/* ── API helper ── */
async function api(path, params) {
  const qs = params ? '?' + new URLSearchParams(
    Object.entries(params).filter(([, v]) => v !== '' && v != null)) : '';
  const res = await fetch(path + qs);
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).error || detail; } catch (e) { /* non-JSON body */ }
    throw new Error(path + ' → ' + res.status + ': ' + detail);
  }
  return res.json();
}

function showError(err) {
  const el = document.getElementById('err-banner');
  el.textContent = '⚠ ' + err.message;
  el.style.display = 'block';
  setTimeout(() => { el.style.display = 'none'; }, 8000);
}

/* ── formatting ── */
const fmtInt = n => (n == null ? '—' : Math.round(n).toLocaleString());
const fmtTime = ts => new Date(ts * 1000).toLocaleTimeString('en-GB');
const fmtDateTime = ts => new Date(ts * 1000).toLocaleString('en-GB');
function fmtBytes(b) {
  if (!b) return '0 B';
  const u = ['B','KB','MB','GB','TB'];
  const i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), u.length - 1);
  return (b / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + u[i];
}
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g,
    c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}
const empty = msg => `<div class="empty-state">${esc(msg)}</div>`;

/* ── chart defaults ── */
Chart.defaults.color = '#7899b0';
Chart.defaults.font.family = "'Share Tech Mono', monospace";
Chart.defaults.font.size = 10;
Chart.defaults.animation.duration = 400;
const GRID = { color: 'rgba(0,212,255,0.06)' };

function upsertChart(key, canvasId, config) {
  const el = document.getElementById(canvasId);
  if (!el) return;
  if (charts[key]) { charts[key].destroy(); }
  charts[key] = new Chart(el.getContext('2d'), config);
}

/* ══════════════ MODULE 1 — Threat Overview ══════════════ */
async function loadOverview() {
  const [stats, throughput, severity, threats, alerts] = await Promise.all([
    api('/api/stats/overview'),
    api('/api/stats/throughput', { minutes: 60 }),
    api('/api/stats/severity', { hours: 24 }),
    api('/api/threats/summary', { hours: 24, limit: 12 }),
    api('/api/alerts', { limit: 8 }),
  ]);

  document.getElementById('kpi-ppm').textContent = fmtInt(stats.packets_per_min);
  document.getElementById('kpi-open').textContent = fmtInt(stats.unacknowledged);
  document.getElementById('kpi-crit-sub').textContent = fmtInt(stats.critical_open) + ' critical';
  document.getElementById('kpi-types').textContent = fmtInt(stats.distinct_threat_types);
  document.getElementById('kpi-tech').textContent = fmtInt(stats.techniques_observed);
  document.getElementById('kpi-total').textContent = fmtInt(stats.total_packets);
  document.getElementById('kpi-hosts-sub').textContent = fmtInt(stats.hosts_tracked) + ' hosts tracked';
  document.getElementById('kpi-conf').textContent =
    stats.mean_confidence ? (stats.mean_confidence * 100).toFixed(1) + '%' : '—';

  document.getElementById('alert-ticker').textContent = fmtInt(stats.unacknowledged) + ' OPEN';
  document.getElementById('nav-alert-badge').textContent = fmtInt(stats.unacknowledged);
  const dot = document.getElementById('alert-dot');
  const counter = document.getElementById('threat-counter');
  if (stats.critical_open > 0) {
    dot.style.display = 'block';
    counter.style.display = 'block';
    document.getElementById('tc-count').textContent = stats.critical_open;
  } else {
    dot.style.display = 'none';
    counter.style.display = 'none';
  }

  upsertChart('throughput', 'chart-throughput', {
    type: 'line',
    data: {
      labels: throughput.map(r => fmtTime(r.bucket)),
      datasets: [{
        label: 'packets/min', data: throughput.map(r => r.packets),
        borderColor: '#00d4ff', backgroundColor: 'rgba(0,212,255,0.12)',
        fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2,
      }, {
        label: 'alerts', data: throughput.map(r => r.alerts),
        borderColor: '#ff2d55', backgroundColor: 'rgba(255,45,85,0.1)',
        fill: true, tension: 0.35, pointRadius: 0, borderWidth: 1.5, yAxisID: 'y1',
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: true, labels: { boxWidth: 10 } } },
      scales: {
        x: { grid: GRID, ticks: { maxTicksLimit: 10 } },
        y: { grid: GRID, beginAtZero: true, title: { display: true, text: 'packets' } },
        y1: { position: 'right', grid: { display: false }, beginAtZero: true, title: { display: true, text: 'alerts' } },
      },
    },
  });
  document.getElementById('tp-badge').textContent =
    throughput.length ? throughput.length + ' MIN' : 'NO DATA';

  upsertChart('severity', 'chart-severity', {
    type: 'doughnut',
    data: {
      labels: severity.map(r => r.severity),
      datasets: [{
        data: severity.map(r => r.count),
        backgroundColor: severity.map(r => SEV_COLOR[r.severity] || '#7899b0'),
        borderColor: '#060f1e', borderWidth: 2,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '58%',
      plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, padding: 8 } } },
    },
  });

  document.getElementById('threat-summary-list').innerHTML = threats.length
    ? threats.map(t => `
        <div class="bar-row clickable" data-action="open-host" data-ip="${esc(t.src_ip)}">
          <span class="lbl">${esc(t.src_ip)}</span>
          <span class="chip">${esc(t.threat_type)}</span>
          <span class="track"><span class="fill ${t.open_alerts > 0 ? 'crit' : ''}"
            style="width:${Math.min(100, t.alert_count * 12)}%"></span></span>
          <span class="val">${t.alert_count} alert${t.alert_count === 1 ? '' : 's'}</span>
        </div>`).join('')
    : empty('NO THREATS IN WINDOW');

  document.getElementById('overview-alerts').innerHTML = alerts.alerts.length
    ? alerts.alerts.map(a => `
        <div class="bar-row clickable" data-action="open-alert" data-alert-id="${a.id}">
          <span class="sev-badge sev-${esc(a.severity)}">${esc(a.severity)}</span>
          <span class="lbl" style="flex:1">${esc(a.threat_type)} · ${esc(a.src_ip || '—')}</span>
          <span class="val">${fmtTime(a.ts)}</span>
        </div>`).join('')
    : empty('NO ALERTS YET');
}

/* ══════════════ MODULE 2 — Recent Alerts ══════════════ */
async function loadAlerts() {
  const data = await api('/api/alerts', { limit: 100, ...alertFilters });
  document.getElementById('alerts-count-badge').textContent =
    `${data.count} OF ${data.total}`;
  const tbody = document.getElementById('alerts-tbody');
  if (!data.alerts.length) {
    tbody.innerHTML = `<tr><td colspan="9">${empty('NO MATCHING ALERTS')}</td></tr>`;
    return;
  }
  tbody.innerHTML = data.alerts.map(a => `
    <tr>
      <td>${fmtTime(a.ts)}</td>
      <td><span class="sev-badge sev-${esc(a.severity)}">${esc(a.severity)}</span></td>
      <td class="clickable" data-action="open-alert" data-alert-id="${a.id}" style="color:var(--cyan)">${esc(a.threat_type)}</td>
      <td class="clickable" data-action="open-host" data-ip="${esc(a.src_ip)}">${esc(a.src_ip || '—')}</td>
      <td>${esc(a.dst_ip || '—')}${a.dst_port ? ':' + a.dst_port : ''}</td>
      <td><span class="proto-tag proto-${esc(a.protocol)}">${esc(a.protocol || '—')}</span></td>
      <td class="num">${(a.confidence * 100).toFixed(0)}%</td>
      <td>${(a.evidence && a.evidence.__t) || ''}<span class="chip tech" id="tech-${a.id}">…</span></td>
      <td>${a.acknowledged
        ? '<span class="ack-btn acked">ACKED</span>'
        : `<button class="ack-btn" data-action="ack-alert" data-alert-id="${a.id}">ACK</button>`}</td>
    </tr>`).join('');

  // Technique chips come from the alert detail endpoint, which resolves the
  // join through mitre_techniques.
  data.alerts.forEach(async a => {
    try {
      const detail = await api('/api/alerts/' + a.id);
      const el = document.getElementById('tech-' + a.id);
      if (el) el.textContent = detail.techniques.map(t => t.technique_id).join(' ') || '—';
    } catch (e) { /* chip stays as-is */ }
  });
}

async function ackAlert(id, btn) {
  try {
    const res = await fetch(`/api/alerts/${id}/acknowledge`, { method: 'POST' });
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = (await res.json()).error || detail; } catch (e) { /* non-JSON body */ }
      throw new Error('acknowledge → ' + res.status + ': ' + detail);
    }
    btn.outerHTML = '<span class="ack-btn acked">ACKED</span>';
    loadOverview().catch(() => {});
  } catch (e) { showError(e); }
}

/* ══════════════ MODULE 3 — Threat Distribution ══════════════ */
async function loadThreats() {
  const [types, stats] = await Promise.all([
    api('/api/threats/types'),
    api('/api/alerts/stats', { hours: 720 }),
  ]);

  const fired = stats.filter(s => s.count > 0);
  upsertChart('threatTypes', 'chart-threat-types', {
    type: 'bar',
    data: {
      labels: fired.map(s => s.threat_type),
      datasets: [{
        label: 'alerts', data: fired.map(s => s.count),
        backgroundColor: fired.map((_, i) => PALETTE[i % PALETTE.length]),
        borderRadius: 3,
      }],
    },
    options: {
      indexAxis: 'y', responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { x: { grid: GRID, beginAtZero: true }, y: { grid: { display: false } } },
    },
  });

  document.getElementById('detector-count-badge').textContent = types.length + ' DETECTORS';
  document.getElementById('detector-catalog').innerHTML = types.map(t => `
    <div style="padding:9px 0;border-bottom:1px solid rgba(0,212,255,0.06)">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span style="font-family:var(--mono);font-size:11px;color:var(--cyan)">${esc(t.threat_type)}</span>
        <span style="font-family:var(--mono);font-size:10px;color:${t.alert_count ? 'var(--green)' : 'var(--text3)'}">
          ${t.alert_count} alert${t.alert_count === 1 ? '' : 's'}</span>
      </div>
      <div style="font-size:10px;color:var(--text2);margin:3px 0;line-height:1.4">${esc(t.description)}</div>
      <div>${t.techniques.map(x => `<span class="chip tech">${esc(x)}</span>`).join(' ')}</div>
    </div>`).join('');
}

/* ══════════════ MODULE 4 — MITRE ATT&CK Coverage ══════════════ */
async function loadMitre() {
  const [coverage, techniques] = await Promise.all([
    api('/api/mitre/coverage'),
    api('/api/mitre/techniques'),
  ]);

  const observed = techniques.filter(t => t.alert_count > 0).length;
  document.getElementById('mitre-badge').textContent =
    `${observed}/${coverage.catalogued_techniques} OBSERVED`;

  document.getElementById('mitre-matrix').innerHTML = coverage.coverage.map(tactic => `
    <div class="tactic-block">
      <div class="tactic-head">
        <span>${esc(tactic.tactic)}</span>
        <span>${tactic.observed}/${tactic.catalogued} observed · ${tactic.total_alerts} alerts</span>
      </div>
      <div class="tactic-cells">
        ${tactic.techniques.map(t => `
          <div class="mitre-cell ${t.alert_count ? 'active' : ''} clickable"
               data-action="open-technique" data-technique-id="${esc(t.technique_id)}">
            <div class="mitre-id">${esc(t.technique_id)}</div>
            <div class="mitre-name">${esc(t.name)}</div>
            <div class="mitre-count">${t.alert_count} alerts</div>
            <div class="mitre-bar"><div class="mitre-bar-fill"
              style="width:${Math.min(100, t.alert_count * 8)}%"></div></div>
          </div>`).join('')}
      </div>
    </div>`).join('');

  const ranked = techniques.filter(t => t.alert_count > 0)
    .sort((a, b) => b.alert_count - a.alert_count);
  upsertChart('mitre', 'chart-mitre', {
    type: 'bar',
    data: {
      labels: ranked.map(t => t.technique_id),
      datasets: [{
        label: 'alerts', data: ranked.map(t => t.alert_count),
        backgroundColor: '#ff9f0a', borderRadius: 3,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { title: items => {
          const t = ranked[items[0].dataIndex];
          return t.technique_id + ' — ' + t.name;
        } } },
      },
      scales: { x: { grid: { display: false } }, y: { grid: GRID, beginAtZero: true } },
    },
  });
}

/* ══════════════ MODULE 5 — Protocol Analysis ══════════════ */
async function loadProtocols() {
  const [dist, catalog] = await Promise.all([
    api('/api/stats/protocols', { minutes: 1440 }),
    api('/api/protocols'),
  ]);
  const byName = Object.fromEntries(dist.map(d => [d.protocol, d]));

  upsertChart('protocols', 'chart-protocols', {
    type: 'bar',
    data: {
      labels: dist.map(d => d.protocol),
      datasets: [{
        label: 'packets', data: dist.map(d => d.packets),
        backgroundColor: '#00d4ff', borderRadius: 3,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { x: { grid: { display: false } }, y: { grid: GRID, beginAtZero: true } },
    },
  });

  upsertChart('protoDonut', 'chart-proto-donut', {
    type: 'doughnut',
    data: {
      labels: dist.map(d => d.protocol),
      datasets: [{
        data: dist.map(d => d.packets),
        backgroundColor: dist.map((_, i) => PALETTE[i % PALETTE.length]),
        borderColor: '#060f1e', borderWidth: 2,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '55%',
      plugins: { legend: { position: 'right', labels: { boxWidth: 9, padding: 5, font: { size: 9 } } } },
    },
  });

  const parsed = catalog.filter(c => c.packets_parsed > 0).length;
  document.getElementById('dpi-badge').textContent =
    `${catalog.length} SUPPORTED · ${parsed} SEEN`;
  document.getElementById('protocol-tbody').innerHTML = catalog.map(c => {
    const d = byName[c.protocol] || {};
    return `<tr>
      <td><span class="proto-tag proto-${esc(c.protocol)}">${esc(c.protocol)}</span></td>
      <td style="color:${c.risk === 'HIGH' ? 'var(--red)' : c.risk === 'MEDIUM' ? 'var(--orange)' : 'var(--text2)'}">${esc(c.risk)}</td>
      <td>${c.encrypted ? '<span class="chip">YES</span>' : '<span class="chip muted">NO</span>'}</td>
      <td class="num">${fmtInt(d.packets || 0)}</td>
      <td class="num">${fmtBytes(d.bytes || 0)}</td>
      <td class="num" style="color:${d.alerts ? 'var(--red)' : 'var(--text3)'}">${fmtInt(d.alerts || 0)}</td>
    </tr>`;
  }).join('');
}

/* ══════════════ MODULE 6 — Source / Destination IP Analysis ══════════════ */
async function loadHosts() {
  const [talkers, risky, geo, flows] = await Promise.all([
    api('/api/hosts/top', { limit: 12, order: 'packets_sent' }),
    api('/api/hosts/top', { limit: 12, order: 'threat_score' }),
    api('/api/geo'),
    api('/api/connections', { limit: 25, order: 'bytes' }),
  ]);

  const maxPkts = Math.max(1, ...talkers.map(h => h.packets_sent));
  document.getElementById('top-talkers').innerHTML = talkers.length
    ? talkers.map(h => `
        <div class="bar-row clickable" data-action="open-host" data-ip="${esc(h.ip)}">
          <span class="lbl" style="color:var(--cyan)">${esc(h.ip)}</span>
          <span class="track"><span class="fill ${h.alert_count ? 'warn' : ''}"
            style="width:${(h.packets_sent / maxPkts * 100).toFixed(1)}%"></span></span>
          <span class="val">${fmtInt(h.packets_sent)}</span>
        </div>`).join('')
    : empty('NO HOSTS OBSERVED');

  const scored = risky.filter(h => h.threat_score > 0);
  document.getElementById('top-threat-hosts').innerHTML = scored.length
    ? scored.map(h => `
        <div class="bar-row clickable" data-action="open-host" data-ip="${esc(h.ip)}">
          <span class="lbl" style="color:var(--red)">${esc(h.ip)}</span>
          <span class="chip muted">${esc(h.country)}</span>
          <span class="track"><span class="fill crit" style="width:${h.threat_score}%"></span></span>
          <span class="val">${h.alert_count} alerts</span>
        </div>`).join('')
    : empty('NO SCORED HOSTS');

  const maxGeo = Math.max(1, ...geo.map(g => g.packets));
  document.getElementById('geo-list').innerHTML = geo.length
    ? geo.map(g => `
        <div class="bar-row">
          <span class="lbl">${esc(g.country)}</span>
          <span class="track"><span class="fill ${g.alerts ? 'crit' : ''}"
            style="width:${(g.packets / maxGeo * 100).toFixed(1)}%"></span></span>
          <span class="val">${fmtInt(g.packets)}</span>
        </div>`).join('')
    : empty('NO GEO DATA');

  document.getElementById('flows-tbody').innerHTML = flows.length
    ? flows.map(f => `
        <tr>
          <td>${esc(f.src_ip)}:${f.src_port}</td>
          <td>${esc(f.dst_ip)}:${f.dst_port}</td>
          <td><span class="proto-tag proto-${esc(f.protocol)}">${esc(f.protocol)}</span></td>
          <td class="num">${fmtInt(f.packets)}</td>
          <td class="num">${fmtBytes(f.bytes)}</td>
        </tr>`).join('')
    : `<tr><td colspan="5">${empty('NO FLOWS')}</td></tr>`;
}

/* ══════════════ MODULE 7 — Activity Trends ══════════════ */
async function loadTimeline() {
  const [timeline, throughput] = await Promise.all([
    api('/api/stats/timeline', { hours: 24, bucket_s: 3600 }),
    api('/api/stats/throughput', { minutes: 1440 }),
  ]);

  const buckets = [...new Set(timeline.map(r => r.bucket))].sort((a, b) => a - b);
  const severities = [...new Set(timeline.map(r => r.severity))];
  upsertChart('timeline', 'chart-timeline', {
    type: 'bar',
    data: {
      labels: buckets.map(b => fmtTime(b)),
      datasets: severities.map(sev => ({
        label: sev,
        data: buckets.map(b => {
          const row = timeline.find(r => r.bucket === b && r.severity === sev);
          return row ? row.count : 0;
        }),
        backgroundColor: SEV_COLOR[sev] || '#7899b0',
      })),
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { boxWidth: 10 } } },
      scales: {
        x: { stacked: true, grid: { display: false } },
        y: { stacked: true, grid: GRID, beginAtZero: true },
      },
    },
  });

  upsertChart('volume', 'chart-volume', {
    type: 'line',
    data: {
      labels: throughput.map(r => fmtTime(r.bucket)),
      datasets: [{
        label: 'bytes', data: throughput.map(r => r.bytes),
        borderColor: '#bf5af2', backgroundColor: 'rgba(191,90,242,0.1)',
        fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: GRID, ticks: { maxTicksLimit: 12 } },
        y: { grid: GRID, beginAtZero: true, ticks: { callback: v => fmtBytes(v) } },
      },
    },
  });
}

/* ══════════════ MODULE 8 — Detection Performance / Health ══════════════ */
async function loadPerformance() {
  const [perf, health] = await Promise.all([
    api('/api/performance', { limit: 120 }),
    api('/api/health'),
  ]);
  const history = perf.history.slice().reverse();
  const latest = perf.history[0] || {};
  const live = perf.live || {};

  document.getElementById('perf-strip').innerHTML = `
    ${gauge('THROUGHPUT', fmtInt(latest.packets_per_min), 'packets/min',
            Math.min(100, (latest.packets_per_min || 0) / 5000 * 100))}
    ${gauge('QUERY p50', (latest.query_p50_ms || 0).toFixed(2), 'ms (target <50)',
            Math.min(100, (latest.query_p50_ms || 0) / 50 * 100))}
    ${gauge('QUERY p95', (latest.query_p95_ms || 0).toFixed(2), 'ms (target <50)',
            Math.min(100, (latest.query_p95_ms || 0) / 50 * 100))}
    ${gauge('PARSE', (live.parse_us_avg != null ? live.parse_us_avg : latest.parse_us_avg || 0).toFixed(1), 'µs/packet', 40)}
    ${gauge('DETECT', (live.detect_us_avg != null ? live.detect_us_avg : latest.detect_us_avg || 0).toFixed(1), 'µs/packet', 40)}
    ${gauge('PARSE ERRORS', fmtInt(live.parse_errors != null ? live.parse_errors : latest.parse_errors), 'frames rejected', 0)}`;

  upsertChart('perfTp', 'chart-perf-tp', {
    type: 'line',
    data: {
      labels: history.map(r => fmtTime(r.ts)),
      datasets: [{
        label: 'packets/min', data: history.map(r => r.packets_per_min),
        borderColor: '#00ff88', backgroundColor: 'rgba(0,255,136,0.1)',
        fill: true, tension: 0.3, pointRadius: 0, borderWidth: 2,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { x: { grid: GRID, ticks: { maxTicksLimit: 8 } }, y: { grid: GRID, beginAtZero: true } },
    },
  });

  upsertChart('perfQ', 'chart-perf-q', {
    type: 'line',
    data: {
      labels: history.map(r => fmtTime(r.ts)),
      datasets: [
        { label: 'p50 ms', data: history.map(r => r.query_p50_ms),
          borderColor: '#00d4ff', pointRadius: 0, borderWidth: 2, tension: 0.3 },
        { label: 'p95 ms', data: history.map(r => r.query_p95_ms),
          borderColor: '#ffd60a', pointRadius: 0, borderWidth: 1.5, tension: 0.3 },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { boxWidth: 10 } } },
      scales: { x: { grid: GRID, ticks: { maxTicksLimit: 8 } }, y: { grid: GRID, beginAtZero: true } },
    },
  });

  document.getElementById('db-health').innerHTML = `
    <dl class="kv">
      <dt>Backend</dt><dd>${esc(health.backend)} ${esc(health.server_version)}</dd>
      <dt>Write-ahead log</dt><dd>${esc(health.journal_mode)}</dd>
      <dt>Tables</dt><dd>${health.table_count}</dd>
      <dt>Indexes</dt><dd>${health.index_count}</dd>
      <dt>Database size</dt><dd>${fmtBytes(health.db_size_bytes)}</dd>
      <dt>Detectors loaded</dt><dd>${health.engine.detectors}</dd>
      <dt>Threat types</dt><dd>${health.engine.threat_types}</dd>
      <dt>ATT&CK techniques</dt><dd>${health.engine.techniques}</dd>
      <dt>Protocols supported</dt><dd>${health.engine.protocols_supported}</dd>
      <dt>Packets analyzed</dt><dd>${fmtInt(health.engine.packets_analyzed)}</dd>
      <dt>Detector errors</dt><dd style="color:${health.engine.detector_errors ? 'var(--red)' : 'var(--green)'}">${health.engine.detector_errors}</dd>
    </dl>
    <h4 style="margin-top:16px">Row counts</h4>
    <dl class="kv">
      ${Object.entries(health.tables).map(([t, n]) =>
        `<dt>${esc(t)}</dt><dd style="color:${n > 0 ? 'var(--green)' : 'var(--red)'}">${fmtInt(n)}</dd>`).join('')}
    </dl>`;
}

function gauge(label, value, unit, pct) {
  return `<div class="perf-gauge">
    <div class="gauge-label">${esc(label)}</div>
    <div class="gauge-val">${esc(value)}</div>
    <div class="gauge-unit">${esc(unit)}</div>
    <div class="gauge-bar"><div class="gauge-fill" style="width:${Math.max(0, Math.min(100, pct))}%"></div></div>
  </div>`;
}

/* ══════════════ MODULE 9 — Live Packet Log ══════════════ */
async function loadPackets() {
  const packets = await api('/api/packets', { limit: 120, ...pktFilters });
  const tbody = document.getElementById('pkt-tbody');
  document.getElementById('pkt-badge').textContent = packets.length + ' ROWS';
  if (!packets.length) {
    tbody.innerHTML = `<tr><td colspan="7">${empty('NO PACKETS MATCH')}</td></tr>`;
    return;
  }
  tbody.innerHTML = packets.map(p => {
    const l7 = Object.entries(p.l7 || {}).slice(0, 3)
      .map(([k, v]) => `${k}=${String(v).slice(0, 40)}`).join('  ');
    return `<tr class="${p.is_malicious ? 'pkt-row mal' : ''}">
      <td>${fmtTime(p.ts)}</td>
      <td>${esc(p.src_ip)}${p.src_port ? ':' + p.src_port : ''}</td>
      <td>${esc(p.dst_ip)}${p.dst_port ? ':' + p.dst_port : ''}</td>
      <td><span class="proto-tag proto-${esc(p.protocol)}">${esc(p.protocol)}</span></td>
      <td class="num">${p.frame_len}</td>
      <td>${esc(p.flags || '—')}</td>
      <td style="color:var(--text2)">${esc(l7) || '—'}</td>
    </tr>`;
  }).join('');
}

/* ══════════════ Detail drawer ══════════════ */
function openDrawer(html) {
  document.getElementById('drawer-body').innerHTML = html;
  document.getElementById('drawer').classList.add('open');
}
document.getElementById('drawer-close').addEventListener('click',
  () => document.getElementById('drawer').classList.remove('open'));

async function openAlert(id) {
  try {
    const a = await api('/api/alerts/' + id);
    openDrawer(`
      <h3>${esc(a.threat_type)}</h3>
      <div style="font-family:var(--mono);font-size:11px;color:var(--text2);margin-bottom:10px">
        alert #${a.id} · ${fmtDateTime(a.ts)}
      </div>
      <span class="sev-badge sev-${esc(a.severity)}">${esc(a.severity)}</span>
      <span class="chip">confidence ${(a.confidence * 100).toFixed(0)}%</span>
      <span class="chip">detector: ${esc(a.detector)}</span>
      <h4>What was detected</h4>
      <div style="font-size:12px;line-height:1.6;color:var(--text)">${esc(a.description)}</div>
      <h4>Connection</h4>
      <dl class="kv">
        <dt>Source</dt><dd>${esc(a.src_ip)}${a.src_port ? ':' + a.src_port : ''}</dd>
        <dt>Destination</dt><dd>${esc(a.dst_ip)}${a.dst_port ? ':' + a.dst_port : ''}</dd>
        <dt>Protocol</dt><dd>${esc(a.protocol)}</dd>
        <dt>Acknowledged</dt><dd>${a.acknowledged ? 'yes' : 'no'}</dd>
      </dl>
      <h4>MITRE ATT&CK mapping</h4>
      ${a.techniques.map(t => `
        <div style="margin-bottom:10px">
          <a href="${esc(t.url)}" target="_blank" rel="noopener"
             style="color:var(--orange);font-family:var(--mono);font-size:11px;text-decoration:none">
            ${esc(t.technique_id)} — ${esc(t.name)}</a>
          <span class="chip muted">${esc(t.tactic)}</span>
          <div style="font-size:11px;color:var(--text2);margin-top:4px;line-height:1.5">${esc(t.rationale)}</div>
        </div>`).join('')}
      <h4>Supporting evidence</h4>
      <pre>${esc(JSON.stringify(a.evidence, null, 2))}</pre>
      <h4>Related packets (${a.related_packets.length})</h4>
      <pre>${a.related_packets.length
        ? esc(a.related_packets.map(p =>
            `${fmtTime(p.ts)}  ${p.src_ip}:${p.src_port || 0} → ${p.dst_ip}:${p.dst_port || 0}  ${p.protocol}  ${p.frame_len}B  ${p.flags || ''}`
          ).join('\n'))
        : 'none within the alert window'}</pre>`);
  } catch (e) { showError(e); }
}

async function openHost(ip) {
  if (!ip || ip === 'null') return;
  try {
    const h = await api('/api/hosts/' + encodeURIComponent(ip));
    openDrawer(`
      <h3>${esc(h.ip)}</h3>
      <div style="margin-bottom:10px">
        <span class="chip">${h.is_internal ? 'INTERNAL' : 'EXTERNAL'}</span>
        <span class="chip muted">${esc(h.country)}</span>
        <span class="chip ${h.threat_score > 0 ? 'tech' : 'muted'}">threat score ${h.threat_score}</span>
      </div>
      <h4>Traffic</h4>
      <dl class="kv">
        <dt>First seen</dt><dd>${fmtDateTime(h.first_seen)}</dd>
        <dt>Last seen</dt><dd>${fmtDateTime(h.last_seen)}</dd>
        <dt>Packets sent</dt><dd>${fmtInt(h.packets_sent)}</dd>
        <dt>Packets received</dt><dd>${fmtInt(h.packets_recv)}</dd>
        <dt>Bytes sent</dt><dd>${fmtBytes(h.bytes_sent)}</dd>
        <dt>Bytes received</dt><dd>${fmtBytes(h.bytes_recv)}</dd>
        <dt>Alerts raised</dt><dd>${fmtInt(h.alert_count)}</dd>
      </dl>
      <h4>Protocols used</h4>
      ${h.top_protocols.length ? h.top_protocols.map(p => `
        <div class="bar-row"><span class="lbl">${esc(p.protocol)}</span>
        <span class="val">${fmtInt(p.packets)} pkts · ${fmtBytes(p.bytes)}</span></div>`).join('')
        : empty('NONE')}
      <h4>Top peers</h4>
      ${h.top_peers.length ? h.top_peers.map(p => `
        <div class="bar-row"><span class="lbl">${esc(p.peer)}</span>
        <span class="val">${fmtBytes(p.bytes)}</span></div>`).join('')
        : empty('NONE')}
      <h4>Recent alerts (${h.recent_alerts.length})</h4>
      ${h.recent_alerts.length ? h.recent_alerts.map(a => `
        <div class="bar-row clickable" data-action="open-alert" data-alert-id="${a.id}">
          <span class="sev-badge sev-${esc(a.severity)}">${esc(a.severity)}</span>
          <span class="lbl" style="flex:1">${esc(a.threat_type)}</span>
          <span class="val">${fmtTime(a.ts)}</span>
        </div>`).join('') : empty('NONE')}`);
  } catch (e) { showError(e); }
}

async function openTechnique(id) {
  try {
    const t = await api('/api/mitre/techniques/' + encodeURIComponent(id));
    openDrawer(`
      <h3>${esc(t.technique_id)} — ${esc(t.name)}</h3>
      <div style="margin-bottom:10px">
        <span class="chip muted">${esc(t.tactic)}</span>
        <span class="chip tech">${t.alert_count} alerts</span>
        <a href="${esc(t.url)}" target="_blank" rel="noopener" class="chip">attack.mitre.org ↗</a>
      </div>
      <h4>Why this mapping</h4>
      <div style="font-size:12px;line-height:1.6;color:var(--text)">${esc(t.rationale)}</div>
      <h4>Detectors that raise it</h4>
      ${t.detectors.length ? t.detectors.map(d => `
        <div class="bar-row"><span class="lbl">${esc(d.detector)}</span>
        <span class="val">${d.count} alerts</span></div>`).join('') : empty('NOT YET OBSERVED')}
      <h4>Recent alerts</h4>
      ${t.recent_alerts.length ? t.recent_alerts.map(a => `
        <div class="bar-row clickable" data-action="open-alert" data-alert-id="${a.id}">
          <span class="sev-badge sev-${esc(a.severity)}">${esc(a.severity)}</span>
          <span class="lbl" style="flex:1">${esc(a.src_ip)} → ${esc(a.dst_ip)}</span>
          <span class="val">${fmtTime(a.ts)}</span>
        </div>`).join('') : empty('NONE')}`);
  } catch (e) { showError(e); }
}

/* ══════════════ Delegated row actions ══════════════
   Alert rows, host rows, MITRE cells and ACK buttons are rebuilt from the API
   on every refresh, so nothing can be bound to them once at load. One listener
   on the document resolves the target's data-action at click time instead,
   which also keeps the generated markup free of inline handlers — the Content
   Security Policy would refuse to run those. */
const ACTIONS = {
  'open-alert':     el => openAlert(Number(el.dataset.alertId)),
  'open-host':      el => openHost(el.dataset.ip),
  'open-technique': el => openTechnique(el.dataset.techniqueId),
  'ack-alert':      el => ackAlert(Number(el.dataset.alertId), el),
};

document.addEventListener('click', event => {
  const target = event.target.closest('[data-action]');
  const action = target && ACTIONS[target.dataset.action];
  if (action) action(target);
});

/* ══════════════ Navigation & refresh ══════════════ */
const LOADERS = {
  overview: loadOverview, alerts: loadAlerts, threats: loadThreats,
  mitre: loadMitre, protocols: loadProtocols, hosts: loadHosts,
  timeline: loadTimeline, performance: loadPerformance, packets: loadPackets,
};

async function showView(name) {
  currentView = name;
  document.querySelectorAll('#main section').forEach(s => { s.style.display = 'none'; });
  document.getElementById('view-' + name).style.display = 'block';
  document.querySelectorAll('.nav-item').forEach(n =>
    n.classList.toggle('active', n.dataset.view === name));
  try { await LOADERS[name](); } catch (e) { showError(e); }
}

document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => showView(item.dataset.view));
});

document.querySelectorAll('#severity-filters .filter-btn[data-sev]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#severity-filters .filter-btn[data-sev]')
      .forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    alertFilters.severity = btn.dataset.sev;
    loadAlerts().catch(showError);
  });
});
document.getElementById('alert-search-btn').addEventListener('click', () => {
  alertFilters.src_ip = document.getElementById('alert-ip-filter').value.trim();
  loadAlerts().catch(showError);
});
document.getElementById('pkt-filter-btn').addEventListener('click', () => {
  pktFilters.protocol = document.getElementById('pkt-proto-filter').value.trim().toUpperCase();
  pktFilters.src_ip = document.getElementById('pkt-ip-filter').value.trim();
  loadPackets().catch(showError);
});
document.getElementById('pkt-mal-btn').addEventListener('click', (e) => {
  pktFilters.malicious_only = !pktFilters.malicious_only;
  e.target.classList.toggle('active', pktFilters.malicious_only);
  loadPackets().catch(showError);
});

async function loadEngineBadges() {
  try {
    const h = await api('/api/health');
    document.getElementById('side-detectors').textContent = h.engine.detectors;
    document.getElementById('side-protocols').textContent = h.engine.protocols_supported;
    document.getElementById('side-techniques').textContent = h.engine.techniques;
    document.getElementById('side-tables').textContent = h.table_count;
    document.getElementById('engine-status').textContent =
      'ENGINE ' + (h.simulation_running ? 'LIVE' : 'IDLE');
    document.body.classList.toggle('demo', Boolean(h.demo));
  } catch (e) { document.getElementById('engine-status').textContent = 'ENGINE OFFLINE'; }
}

setInterval(() => {
  document.getElementById('clock').textContent =
    new Date().toLocaleTimeString('en-GB');
}, 1000);

// Refresh whichever module is on screen; the others reload on navigation.
setInterval(() => { LOADERS[currentView]().catch(() => {}); }, 10000);
setInterval(loadEngineBadges, 30000);

loadEngineBadges();
showView('overview');