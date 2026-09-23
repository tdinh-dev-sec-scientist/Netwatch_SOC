/* ══════════════════════════════════════════════════════════════════
   NetWatch SOC dashboard.

   Every module below is driven by a REST call to the Flask API, which
   reads from PostgreSQL. There is no seeded, mocked or placeholder data in
   this file: if an endpoint returns nothing, the module renders an
   explicit empty state so a missing pipeline is visible rather than
   disguised.
══════════════════════════════════════════════════════════════════ */

/* ── design tokens ──────────────────────────────────────────────────
   Colour lives in one place: the :root block in Dashboard.html. Charts
   read it at runtime rather than carrying their own hex literals, so a
   theme change repaints every mark from the same source as the rest of
   the interface. See DESIGN.md §1. */
const tokenCache = new Map();
function token(name) {
  if (!tokenCache.has(name)) {
    tokenCache.set(name, getComputedStyle(document.documentElement)
      .getPropertyValue(name).trim());
  }
  return tokenCache.get(name);
}
function retheme() { tokenCache.clear(); }

/* Severity is an ordered attention scale, not a set of identities: the
   mark steps run loud to quiet, and LOW/INFO are deliberately neutral. */
const sevColor = sev => token({
  CRITICAL: '--mark-crit', HIGH: '--mark-high', MEDIUM: '--mark-med',
  LOW: '--mark-low', INFO: '--mark-info',
}[sev] || '--other');

/* Two validated categorical slots and a de-emphasis grey. Anything past
   the second entity folds into "Other" rather than generating a hue. */
const SERIES = ['--s-1', '--s-2'];
const seriesColor = i => token(i < SERIES.length ? SERIES[i] : '--other');

/* One hue, five ordinal steps, for magnitude. */
const SEQ = ['--seq-1', '--seq-2', '--seq-3', '--seq-4', '--seq-5'];
const seqColor = step => token(SEQ[Math.max(0, Math.min(SEQ.length - 1, step))]);

/* Area fills are a wash of the series hue, never a saturated block. */
function alpha(name, a) {
  const hex = token(name).replace('#', '');
  if (hex.length !== 6) return token(name);
  const n = parseInt(hex, 16);
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${a})`;
}

const charts = {};
let currentView = 'alerts';
let isDemo = false;
let engineState = 'live';
let booted = false;
let shellOnce = null;
const REFRESH_MS = 10000;
const SHELL_REFRESH_MS = 15000;
let alertFilters = { severity: '', src_ip: '', threat_type: '', acknowledged: '' };
let pktFilters = { protocol: '', src_ip: '', malicious_only: false };

/* ── API helper ── */
async function api(path, params) {
  const qs = params ? '?' + new URLSearchParams(
    Object.entries(params).filter(([, v]) => v !== '' && v != null)) : '';
  let res;
  try {
    res = await fetch(path + qs);
  } catch (e) {
    /* fetch rejects with a bare "Failed to fetch" on a network error, which
       tells an analyst nothing about which call died. */
    throw new Error(path + ' → unreachable: ' + e.message);
  }
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).error || detail; } catch (e) { /* non-JSON body */ }
    throw new Error(path + ' → ' + res.status + ': ' + detail);
  }
  return res.json();
}

/* Errors persist until dismissed. The banner this replaced hid itself after
   eight seconds, which loses the one piece of information an analyst needs
   to tell a broken endpoint from a quiet network. */
let lastFailure = null;

function showError(err) {
  const el = document.getElementById('err-banner');
  lastFailure = err;
  el.innerHTML = '';
  const text = document.createElement('span');
  text.className = 'err-text';
  text.textContent = err.message;
  const retry = document.createElement('button');
  retry.type = 'button';
  retry.className = 'filter-btn';
  retry.textContent = 'Retry';
  retry.addEventListener('click', () => {
    clearError();
    runLoader(currentView);
  });
  const dismiss = document.createElement('button');
  dismiss.type = 'button';
  dismiss.className = 'filter-btn';
  dismiss.textContent = 'Dismiss';
  dismiss.addEventListener('click', clearError);
  el.append(text, retry, dismiss);
  el.hidden = false;
}

function clearError() {
  lastFailure = null;
  document.getElementById('err-banner').hidden = true;
}

/* One component renders every empty, loading and failed state, so "nothing
   is wrong" and "we stopped being able to see" cannot drift apart. */
function stateBlock(kind, title, body, action) {
  return `<div class="state${kind === 'attention' ? ' attention' : ''}">
    <div class="state-title">${esc(title)}</div>
    <div class="state-body">${body}</div>
    ${action || ''}
  </div>`;
}

/* An empty panel says whether the pipeline is running, because those are
   different facts and only one of them is good news. */
function emptyPanel(what) {
  if (engineState === 'idle' || engineState === 'offline') {
    return stateBlock('attention', 'The capture pipeline is not running',
      `No packets are being analysed, so there is no ${esc(what)} to show. `
      + 'This is not an all-clear.');
  }
  return stateBlock('', 'No ' + what + ' yet',
    'The engine is running. This fills in as traffic is analysed.');
}

function skeleton(rows) {
  return Array.from({ length: rows || 3 }, () =>
    '<div class="skeleton-row"><span></span><span></span><span></span>'
    + '<span></span><span></span></div>').join('');
}

/* A refetch holds the previous render rather than flashing a skeleton. */
function holding(view, on) {
  const section = document.getElementById('view-' + view);
  if (section) section.classList.toggle('refetching', Boolean(on));
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
function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

/* A rail figure flashes on the digits when it changes. tabular-nums is off
   on these, so there is no width jitter and nothing to animate but colour. */
function setValue(id, value) {
  const el = document.getElementById(id);
  if (!el || el.textContent === value) return;
  el.textContent = value;
  el.classList.remove('changed');
  void el.offsetWidth;
  el.classList.add('changed');
}

/* ── chart defaults ──────────────────────────────────────────────────
   Chart text never wears the data colour: values, labels and legends use
   ink tokens, and the coloured mark beside them carries identity.
   Gridlines are solid hairlines one step off the surface, never dashed. */
function applyChartDefaults() {
  Chart.defaults.color = token('--ink-3');
  Chart.defaults.borderColor = token('--hair');
  Chart.defaults.font.family = 'IBM Plex Mono, ui-monospace, monospace';
  Chart.defaults.font.size = 11;
  Chart.defaults.animation.duration = 200;
  Chart.defaults.plugins.legend.labels.boxWidth = 10;
  Chart.defaults.plugins.legend.labels.boxHeight = 10;
  Chart.defaults.plugins.tooltip.backgroundColor = token('--s3');
  Chart.defaults.plugins.tooltip.titleColor = token('--ink-1');
  Chart.defaults.plugins.tooltip.bodyColor = token('--ink-2');
  Chart.defaults.plugins.tooltip.borderColor = token('--rule');
  Chart.defaults.plugins.tooltip.borderWidth = 1;
  Chart.defaults.plugins.tooltip.displayColors = true;
  Chart.defaults.plugins.tooltip.padding = 8;
}
applyChartDefaults();

const grid = () => ({ color: token('--hair'), borderDash: [] });

function upsertChart(key, canvasId, config) {
  const el = document.getElementById(canvasId);
  if (!el) return;
  if (charts[key]) { charts[key].destroy(); }
  charts[key] = new Chart(el.getContext('2d'), config);
}

/* ══════════════ Chart building blocks ══════════════
   Every chart in the console is one of four forms. Nothing cycles hues,
   nothing carries two y-scales, and no mark is thicker than 24px. */

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

/* Magnitude over an ordered set of names: one hue, ranked, value at the tip. */
function rankedBar(key, canvasId, rows, opts) {
  const options = opts || {};
  upsertChart(key, canvasId, {
    type: 'bar',
    data: {
      labels: rows.map(r => r.label),
      datasets: [{
        label: options.unit || 'count',
        data: rows.map(r => r.value),
        backgroundColor: rows.map(r => r.muted ? token('--other') : token('--s-1')),
        borderRadius: { topLeft: 0, bottomLeft: 0, topRight: 4, bottomRight: 4 },
        maxBarThickness: 24,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: item => options.format
          ? options.format(item.parsed.x) : fmtInt(item.parsed.x) } },
      },
      scales: {
        x: { grid: grid(), beginAtZero: true,
             ticks: { callback: v => options.format ? options.format(v) : fmtInt(v) } },
        y: { grid: { display: false } },
      },
    },
  });
}

/* Past the eighth row the tail is noise: fold it into one honest bucket
   rather than drawing thirteen more bars nobody reads. */
function topNWithOther(rows, n) {
  if (rows.length <= n + 1) return rows;
  const head = rows.slice(0, n);
  const tail = rows.slice(n);
  const sum = tail.reduce((acc, r) => acc + r.value, 0);
  return head.concat([{
    label: `Other (${tail.length})`, value: sum, muted: true,
  }]);
}

/* One series over time. Area is a 10% wash of the hue, never a block. */
function timeSeries(key, canvasId, labels, values, colorToken, opts) {
  const options = opts || {};
  upsertChart(key, canvasId, {
    type: options.type || 'line',
    data: {
      labels: labels.map(l => l),
      datasets: [{
        label: options.unit || 'value',
        data: values.map(v => v),
        borderColor: token(colorToken),
        backgroundColor: options.type === 'bar'
          ? token(colorToken) : alpha(colorToken, 0.10),
        fill: options.type !== 'bar',
        tension: 0.3,
        pointRadius: 0,
        pointHitRadius: 12,
        borderWidth: 2,
        maxBarThickness: 14,
        borderRadius: options.type === 'bar' ? 3 : 0,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: {
          grid: options.showX ? grid() : { display: false },
          ticks: { display: Boolean(options.showX), maxTicksLimit: 10 },
        },
        y: {
          grid: grid(), beginAtZero: true,
          ticks: { maxTicksLimit: 4,
                   callback: v => options.format ? options.format(v) : fmtInt(v) },
        },
      },
    },
  });
}

/* ══════════════ MODULE 1 — Threat Overview ══════════════ */
async function loadOverview() {
  const [stats, throughput, severity, threats, alerts] = await Promise.all([
    api('/api/stats/overview'),
    api('/api/stats/throughput', { minutes: Math.min(720, windowMinutes()) }),
    api('/api/stats/severity', { hours: windowHours() }),
    api('/api/threats/summary', { hours: windowHours(), limit: 12 }),
    api('/api/alerts', { limit: 8 }),
  ]);

  /* The posture figures themselves live in the status rail, which is pinned
     above every view. What belongs here is the 24-hour shape of the data. */
  setText('posture-summary',
    `${fmtInt(stats.alerts_24h)} alerts in the last 24 hours across `
    + `${fmtInt(stats.distinct_threat_types)} detectors, `
    + `${fmtInt(stats.hosts_tracked)} hosts tracked, `
    + `${fmtInt(stats.total_packets)} packets analysed in total`
    + (stats.mean_confidence
        ? `. Mean confidence ${(stats.mean_confidence * 100).toFixed(1)}%.`
        : '.'));

  /* Two rows on one time axis rather than two y-scales on one plot: the
     alignment of two scales is arbitrary, so a dual-axis chart invents a
     correlation the data does not contain. */
  const tpLabels = throughput.map(r => fmtTime(r.bucket));
  timeSeries('throughput', 'chart-throughput',
    tpLabels, throughput.map(r => r.packets), '--s-1', { unit: 'packets/min' });
  timeSeries('throughputAlerts', 'chart-throughput-alerts',
    tpLabels, throughput.map(r => r.alerts), '--mark-crit',
    { unit: 'alerts', type: 'bar', showX: true });
  setText('tp-badge', throughput.length
    ? throughput.length + ' minutes' : 'No traffic recorded');

  /* Severity is an ordered scale, so it is ranked in its own order rather
     than sliced into a donut, where the ordering is lost and small counts
     disappear. */
  const bySeverity = SEV_ORDER
    .map(name => severity.find(r => r.severity === name))
    .filter(Boolean);
  upsertChart('severity', 'chart-severity', {
    type: 'bar',
    data: {
      labels: bySeverity.map(r => r.severity),
      datasets: [{
        label: 'alerts',
        data: bySeverity.map(r => r.count),
        backgroundColor: bySeverity.map(r => sevColor(r.severity)),
        borderRadius: { topLeft: 0, bottomLeft: 0, topRight: 4, bottomRight: 4 },
        maxBarThickness: 24,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: grid(), beginAtZero: true, ticks: { precision: 0 } },
        y: { grid: { display: false } },
      },
    },
  });

  const maxThreat = Math.max(1, ...threats.map(t => t.alert_count));
  document.getElementById('threat-summary-list').innerHTML = threats.length
    ? threats.map(t => `
        <button type="button" class="bar-row clickable" data-action="open-host" data-ip="${esc(t.src_ip)}">
          <span class="lbl">${esc(t.src_ip)}</span>
          <span class="chip">${esc(t.threat_type)}</span>
          <span class="track"><span class="fill"
            style="width:${(t.alert_count / maxThreat * 100).toFixed(1)}%"></span></span>
          <span class="val">${fmtInt(t.alert_count)} ${t.alert_count === 1 ? 'alert' : 'alerts'}</span>
        </button>`).join('')
    : emptyPanel('threat activity');

  document.getElementById('overview-alerts').innerHTML = alerts.alerts.length
    ? alerts.alerts.map(a => `
        <button type="button" class="bar-row clickable" data-action="open-alert" data-alert-id="${a.id}">
          <span class="sev-badge sev-${esc(a.severity)}">${esc(a.severity)}</span>
          <span class="lbl" style="flex:1">${esc(a.threat_type)} · ${esc(a.src_ip || '—')}</span>
          <span class="val">${fmtTime(a.ts)}</span>
        </button>`).join('')
    : emptyPanel('alerts');
}

/* ══════════════ MODULE 2 — Alert queue ══════════════
   The surface an analyst spends a shift on, and the one rule it cannot
   break: never move a row someone is looking at. Refreshes merge by alert
   id, so existing rows update in place; genuinely new alerts wait in a
   pending buffer until the analyst asks for them. Sorting, filtering and
   paging are explicit actions, so those are allowed to move rows. */

const PAGE = 100;

const queue = {
  rows: [],          // rendered, in display order
  known: new Set(),  // every alert id currently on screen
  pending: [],       // arrived since the last render, not yet shown
  sort: { key: 'ts', dir: 'desc' },
  limit: PAGE,
  loaded: 0,
  outside: 0,
  total: 0,
  selected: null,
  stale: false,
  first: true,
  merge: false,
  updatedAt: 0,
};

/* The detector catalog maps a threat type to the techniques it can emit.
   Fetching it once replaces the per-row /api/alerts/{id} call the queue
   used to make for every row on every refresh. The exact per-alert set
   still comes from the detail endpoint when the drawer opens. */
let techniqueMap = null;
async function loadTechniqueMap() {
  if (techniqueMap) return techniqueMap;
  const types = await api('/api/threats/types');
  techniqueMap = {};
  types.forEach(t => { techniqueMap[t.threat_type] = t.techniques || []; });
  populateDetectorFilter(types);
  return techniqueMap;
}

function populateDetectorFilter(types) {
  const select = document.getElementById('alert-detector');
  if (!select || select.options.length > 1) return;
  types.slice().sort((a, b) => a.threat_type.localeCompare(b.threat_type))
    .forEach(t => {
      const option = document.createElement('option');
      option.value = t.threat_type;
      option.textContent = t.threat_type;
      select.appendChild(option);
    });
}

/* Relative in the cell, absolute UTC in the title: analysts read the first
   and paste the second into a ticket. */
function relTime(ts) {
  const secs = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (secs < 60) return secs + ' s ago';
  if (secs < 3600) return Math.round(secs / 60) + ' m ago';
  if (secs < 86400) return Math.round(secs / 3600) + ' h ago';
  return Math.round(secs / 86400) + ' d ago';
}

const isPrivate = ip => /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip || '');

function connCell(a) {
  const src = a.src_ip
    ? `<span class="${isPrivate(a.src_ip) ? '' : 'ext'}">${esc(a.src_ip)}</span>` : '—';
  const dst = a.dst_ip
    ? `<span class="${isPrivate(a.dst_ip) ? '' : 'ext'}">${esc(a.dst_ip)}</span>`
      + (a.dst_port ? ':' + a.dst_port : '') : '—';
  return `${src}<span class="arrow" aria-hidden="true">&rarr;</span>${dst}`;
}

function techniqueCell(a) {
  const ids = (techniqueMap && techniqueMap[a.threat_type]) || [];
  if (!ids.length) return '<span class="chip muted">—</span>';
  return ids.map(id => `<span class="chip tech">${esc(id)}</span>`).join(' ');
}

function confidenceCell(a) {
  const pct = Math.round((a.confidence || 0) * 100);
  return `<span class="conf"><span class="track" aria-hidden="true">`
    + `<span class="fill" style="width:${pct}%"></span></span>`
    + `<span class="v">${pct}%</span></span>`;
}

function stateCell(a) {
  if (a.acknowledged) return '<span class="ack-btn acked">Acknowledged</span>';
  if (isDemo) {
    return '<button class="ack-btn" type="button" disabled '
      + 'title="The public demo is read-only">Acknowledge</button>';
  }
  return `<button class="ack-btn" type="button" data-action="ack-alert" `
    + `data-alert-id="${a.id}">Acknowledge</button>`;
}

/* data-label carries the column header into the card layout below 768px,
   where the real header row is hidden. */
function rowHtml(a) {
  return `
      <td data-label="Sev"><span class="sev-badge sev-${esc(a.severity)}">${esc(a.severity)}</span></td>
      <td data-label="When" class="cell-when" title="${esc(fmtDateTime(a.ts))}">${esc(relTime(a.ts))}</td>
      <td data-label="Detection" class="cell-detection">${esc(a.threat_type)}</td>
      <td data-label="Connection" class="cell-conn">${connCell(a)}</td>
      <td data-label="Proto" class="col-proto"><span class="proto-tag">${esc(a.protocol || '—')}</span></td>
      <td data-label="ATT&CK">${techniqueCell(a)}</td>
      <td data-label="Confidence" class="col-conf">${confidenceCell(a)}</td>
      <td>${stateCell(a)}</td>`;
}

/* Keyed merge. A row that is already on screen is updated in place, so the
   analyst's scroll position, selection and reading spot all survive. */
function paintRows(alerts, opts) {
  const tbody = document.getElementById('alerts-tbody');
  const existing = new Map();
  tbody.querySelectorAll('tr[data-alert-id]').forEach(tr =>
    existing.set(tr.dataset.alertId, tr));

  const order = [];
  alerts.forEach(a => {
    const key = String(a.id);
    let tr = existing.get(key);
    if (tr) {
      existing.delete(key);
    } else {
      tr = document.createElement('tr');
      tr.dataset.alertId = key;
      tr.tabIndex = -1;
      if (opts && opts.animate) tr.classList.add('entering');
      if (opts && opts.animate && a.severity === 'CRITICAL') {
        window.setTimeout(() => {
          const chip = tr.querySelector('.sev-badge');
          if (chip) chip.classList.add('arrived');
        }, 0);
      }
    }
    tr.innerHTML = rowHtml(a);
    order.push(tr);
  });

  existing.forEach(tr => tr.remove());
  order.forEach((tr, i) => {
    if (tbody.children[i] !== tr) tbody.insertBefore(tr, tbody.children[i] || null);
  });

  queue.rows = alerts;
  queue.known = new Set(alerts.map(a => String(a.id)));
  if (queue.selected && !queue.known.has(queue.selected)) queue.selected = null;
  markSelected();
}

function markSelected() {
  document.querySelectorAll('#alerts-tbody tr').forEach(tr =>
    tr.classList.toggle('selected', tr.dataset.alertId === queue.selected));
}

function activeFilterCount() {
  return (alertFilters.severity ? 1 : 0) + (alertFilters.src_ip ? 1 : 0)
    + (alertFilters.threat_type ? 1 : 0)
    + (alertFilters.acknowledged !== '' && alertFilters.acknowledged != null ? 1 : 0);
}

/* The four empty states an analyst must be able to tell apart at a glance.
   "Nothing is wrong" and "we stopped being able to see" are the pair that
   matters: a monitoring console that conflates them manufactures
   confidence. */
function queueState(total) {
  const host = document.getElementById('alerts-state');
  const table = document.getElementById('alerts-table');
  if (total > 0) { host.innerHTML = ''; table.hidden = false; return; }
  table.hidden = true;

  if (engineState === 'idle' || engineState === 'offline') {
    host.innerHTML = `<div class="state attention">
      <div class="state-title">The capture pipeline is not running</div>
      <div class="state-body">No packets are being analysed, so no alerts can appear.
        This is not an all-clear. Start the simulator, or attach a live capture,
        and the queue will fill.</div>
    </div>`;
    return;
  }
  if (queue.outside > 0) {
    host.innerHTML = `<div class="state">
      <div class="state-title">Nothing in ${esc(rangeLabel().toLowerCase())}</div>
      <div class="state-body">${fmtInt(queue.outside)} loaded
        ${queue.outside === 1 ? 'alert falls' : 'alerts fall'} outside this
        window. Widen the time window in the header to see them.</div>
    </div>`;
    return;
  }
  if (activeFilterCount()) {
    host.innerHTML = `<div class="state">
      <div class="state-title">No alerts match these filters</div>
      <div class="state-body">${esc(rangeLabel())} is selected along with
        ${activeFilterCount()} other filter${activeFilterCount() === 1 ? '' : 's'}.</div>
      <button type="button" class="filter-btn" id="alerts-clear-empty">Clear filters</button>
    </div>`;
    return;
  }
  host.innerHTML = `<div class="state">
    <div class="state-title">No alerts in ${esc(rangeLabel().toLowerCase())}</div>
    <div class="state-body">The engine is running and detecting:
      <span id="state-detectors">&mdash;</span> detectors active,
      <span id="state-ppm">—</span> packets/min. Alerts appear here as they are raised.</div>
  </div>`;
  const facts = document.getElementById('side-detectors');
  if (facts) setText('state-detectors', facts.textContent);
  const ppm = document.getElementById('rail-ppm');
  if (ppm) setText('state-ppm', ppm.textContent);
}

/* One time window drives the whole console. /api/alerts has no time
   parameter, so the queue applies the window to the page it fetched and the
   badge says exactly that rather than implying the server filtered. */
function windowHours() {
  const select = document.getElementById('time-window');
  return (select && Number(select.value)) || 24;
}
function windowMinutes() {
  return Math.min(10080, Math.max(1, windowHours() * 60));
}
function windowBucket() {
  const h = windowHours();
  if (h <= 1) return 300;
  if (h <= 24) return 3600;
  if (h <= 168) return 21600;
  return 86400;
}
function rangeLabel() {
  const select = document.getElementById('time-window');
  return select ? select.options[select.selectedIndex].text : 'Last 24 hours';
}
function windowCutoff() {
  return Date.now() / 1000 - windowHours() * 3600;
}

function showSkeleton() {
  const host = document.getElementById('alerts-state');
  document.getElementById('alerts-table').hidden = true;
  host.innerHTML = Array.from({ length: 8 }, () =>
    '<div class="skeleton-row"><span></span><span></span><span></span><span></span><span></span></div>'
  ).join('');
}

function setPending(alerts) {
  queue.pending = alerts;
  const button = document.getElementById('alerts-pending');
  button.hidden = alerts.length === 0;
  setText('alerts-pending-label',
    alerts.length === 1 ? '1 new alert' : alerts.length + ' new alerts');
}

function setStale(on, reason) {
  queue.stale = on;
  const mark = document.getElementById('alerts-stale');
  mark.hidden = !on;
  if (on) mark.textContent = reason;
}

async function loadAlerts() {
  /* queue.merge is set by the background refresh. A merge keeps the rows
     that are already on screen exactly where they are and routes anything
     new to the pending pill; a replace is what an explicit action (filter,
     sort, page, navigation) gets. */
  const merge = queue.merge;
  queue.merge = false;
  if (queue.first) showSkeleton();
  const table = document.getElementById('alerts-table');
  if (!queue.first && !merge) table.classList.add('refetching');

  let data;
  try {
    await Promise.all([loadTechniqueMap(), shellOnce]);
    data = await api('/api/alerts', {
      limit: queue.limit,
      severity: alertFilters.severity,
      src_ip: alertFilters.src_ip,
      threat_type: alertFilters.threat_type,
      acknowledged: alertFilters.acknowledged,
    });
  } catch (e) {
    table.classList.remove('refetching');
    /* A failed refetch keeps the last good render and marks it. Stale
       numbers are never presented as live. A failed *first* load has nothing
       to keep, so the skeleton is replaced by the reason — a skeleton that
       never resolves reads as "still loading" forever. */
    if (queue.rows.length) {
      setStale(true, 'Last updated ' + relTime(queue.updatedAt) + ', retrying');
    } else {
      document.getElementById('alerts-table').hidden = true;
      document.getElementById('alerts-state').innerHTML = stateBlock('attention',
        'The queue could not be loaded',
        'The dashboard could not reach <code>/api/alerts</code>. This is a '
        + 'reporting failure, not an all-clear: alerts may be firing that '
        + 'this console cannot see.');
    }
    throw e;
  }
  table.classList.remove('refetching');
  setStale(false);
  queue.updatedAt = Date.now() / 1000;
  queue.total = data.total;

  const cutoff = windowCutoff();
  const inWindow = data.alerts.filter(a => a.ts >= cutoff);
  queue.loaded = data.alerts.length;
  queue.outside = data.alerts.length - inWindow.length;
  const sorted = sortAlerts(inWindow);
  if (merge) {
    paintRows(sorted.filter(a => queue.known.has(String(a.id))), { animate: false });
    setPending(sorted.filter(a => !queue.known.has(String(a.id))));
  } else {
    setPending([]);
    paintRows(sorted, { animate: !queue.first });
  }
  queue.first = false;
  afterQueueRender(data.total);
}

function afterQueueRender(total) {
  const shown = document.querySelectorAll('#alerts-tbody tr').length;
  setText('alerts-count-badge', queue.outside
    ? `${shown} in window \u00b7 ${queue.outside} outside \u00b7 ${queue.loaded} of ${total} loaded`
    : (queue.loaded < total
        ? `${shown} of ${total} alerts`
        : `${shown} ${shown === 1 ? 'alert' : 'alerts'}`));
  setText('alerts-scope', rangeLabel()
    + (alertFilters.severity ? ' \u00b7 ' + alertFilters.severity.toLowerCase() : '')
    + (alertFilters.threat_type ? ' \u00b7 ' + alertFilters.threat_type : ''));
  document.getElementById('alert-clear').hidden = activeFilterCount() === 0;
  document.getElementById('alerts-footer').hidden = total <= queue.loaded;
  queueState(shown);
  applySortIndicators();
}

function sortAlerts(alerts) {
  const { key, dir } = queue.sort;
  const sign = dir === 'asc' ? 1 : -1;
  return alerts.slice().sort((a, b) => sign * ((a[key] || 0) - (b[key] || 0)));
}

function applySortIndicators() {
  document.querySelectorAll('#alerts-table th[scope="col"]').forEach(th => {
    const button = th.querySelector('.th-sort');
    if (!button) return;
    if (button.dataset.sort === queue.sort.key) {
      th.setAttribute('aria-sort', queue.sort.dir === 'asc' ? 'ascending' : 'descending');
    } else {
      th.removeAttribute('aria-sort');
    }
  });
}

/* Optimistic: the row reads as acknowledged the instant it is clicked, and
   reverts to a working button if the POST fails. A queue that blocks on a
   round trip per acknowledgement is unusable at shift volume. */
async function ackAlert(id, btn) {
  const host = btn.parentNode;
  const restore = btn.cloneNode(true);
  const done = document.createElement('span');
  done.className = 'ack-btn acked';
  done.textContent = 'Acknowledging…';
  host.replaceChild(done, btn);
  announce('Alert ' + id + ' acknowledged');
  try {
    const res = await fetch(`/api/alerts/${id}/acknowledge`, { method: 'POST' });
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = (await res.json()).error || detail; } catch (e) { /* non-JSON body */ }
      throw new Error('acknowledge → ' + res.status + ': ' + detail);
    }
    done.textContent = 'Acknowledged';
    loadShell();
  } catch (e) {
    if (done.parentNode) done.parentNode.replaceChild(restore, done);
    announce('Acknowledging alert ' + id + ' failed');
    showError(e);
  }
}

/* Throttled so a burst of alerts does not flood a screen reader. */
let announceAt = 0;
let announceTimer = null;
function announce(message) {
  const region = document.getElementById('live-region');
  if (!region) return;
  const since = Date.now() - announceAt;
  window.clearTimeout(announceTimer);
  const emit = () => { announceAt = Date.now(); region.textContent = message; };
  if (since > 1500) emit();
  else announceTimer = window.setTimeout(emit, 1500 - since);
}

/* ══════════════ MODULE 3 — Detector catalog ══════════════ */
async function loadThreats() {
  const [types, stats] = await Promise.all([
    api('/api/threats/types'),
    api('/api/alerts/stats', { hours: windowHours() }),
  ]);

  /* Bar length already encodes magnitude, so hue is free and is spent on
     nothing. The tail folds into one honest bucket. */
  const fired = stats.filter(x => x.count > 0)
    .sort((a, b) => b.count - a.count)
    .map(x => ({ label: x.threat_type, value: x.count }));
  if (fired.length) {
    rankedBar('threatTypes', 'chart-threat-types', topNWithOther(fired, 8));
  } else {
    upsertChart('threatTypes', 'chart-threat-types', {
      type: 'bar',
      data: { labels: stats.map(x => x.threat_type).slice(0, 1),
              datasets: [{ data: stats.map(() => 0).slice(0, 1),
                           backgroundColor: token('--other') }] },
      options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false,
                 plugins: { legend: { display: false } },
                 scales: { x: { grid: grid(), beginAtZero: true },
                           y: { grid: { display: false } } } },
    });
  }

  const seen = types.filter(t => t.alert_count > 0).length;
  setText('detector-count-badge', `${seen} of ${types.length} detectors have fired`);
  document.getElementById('detector-catalog').innerHTML = types.map(t => `
    <div class="catalog-row">
      <div class="catalog-head">
        <span class="catalog-name">${esc(t.threat_type)}</span>
        <span class="catalog-count${t.alert_count ? ' seen' : ''}">${
          t.alert_count ? fmtInt(t.alert_count) + (t.alert_count === 1 ? ' alert' : ' alerts')
                        : 'none seen'}</span>
      </div>
      <p class="catalog-desc">${esc(t.description)}</p>
      <div class="catalog-tech">${t.techniques.map(x =>
        `<a class="chip tech" href="#/technique/${encodeURIComponent(x)}">${esc(x)}</a>`).join(' ')}</div>
    </div>`).join('');
}

/* ══════════════ MODULE 4 — ATT&CK coverage ══════════════
   The layout every analyst already knows: tactics as columns in kill-chain
   order, techniques stacked beneath. Cell fill is a quintile bin of the
   alert count on the validated sequential ramp, with the count as a direct
   label in every cell, so the fill is never the only encoding. */

/* Cells are bins on a five-step ramp, so the shading reads as a scale
   rather than as an arbitrary bar width. */
function heatStep(count, max) {
  if (!count) return 0;
  if (max <= 1) return 3;
  return Math.max(1, Math.min(5, Math.ceil((count / max) * 5)));
}

async function loadMitre() {
  /* Two reads of the same catalog: the coverage endpoint gives the structure
     and the all-time count, and the technique list scoped to the selected
     window gives what actually fired inside it. That is what separates "a
     detector covers this and nothing happened" from "this was seen" — a
     distinction a coverage matrix has to make or it is just a list of things
     somebody once mapped. */
  const [coverage, techniques] = await Promise.all([
    api('/api/mitre/coverage'),
    api('/api/mitre/techniques', { hours: windowHours() }),
  ]);

  const inWindow = {};
  techniques.forEach(t => { inWindow[t.technique_id] = t.alert_count; });
  const observed = techniques.filter(t => t.alert_count > 0).length;
  const everSeen = coverage.coverage.reduce((acc, tactic) =>
    acc + tactic.techniques.filter(t => t.alert_count > 0).length, 0);
  const max = Math.max(1, ...techniques.map(t => t.alert_count));
  setText('mitre-badge',
    `${observed} of ${coverage.catalogued_techniques} techniques seen in `
    + `${rangeLabel().toLowerCase()} \u00b7 ${everSeen} ever \u00b7 `
    + `${coverage.coverage.length} tactics`);

  const order = coverage.tactics || [];
  const byKillChain = coverage.coverage.slice().sort((a, b) => {
    const ai = order.indexOf(a.tactic), bi = order.indexOf(b.tactic);
    return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi);
  });

  document.getElementById('mitre-matrix').innerHTML = byKillChain.map(tactic => {
    const seenHere = tactic.techniques
      .filter(t => (inWindow[t.technique_id] || 0) > 0).length;
    return `
    <div class="mitre-col">
      <div class="mitre-col-head">${esc(tactic.tactic)}
        <span class="n">${seenHere}/${tactic.catalogued} seen</span>
      </div>
      ${tactic.techniques.map(t => {
        const here = inWindow[t.technique_id] || 0;
        const label = here
          ? fmtInt(here) + (here === 1 ? ' alert' : ' alerts')
          : (t.alert_count ? 'none in window' : 'covered, never seen');
        return `
        <button type="button" class="mitre-cell q${heatStep(here, max)}"
                data-action="open-technique" data-technique-id="${esc(t.technique_id)}"
                title="${esc(t.name)} — ${esc(label)}">
          <span class="id">${esc(t.technique_id)}</span>
          <span class="nm">${esc(t.name)}</span>
          <span class="ct">${esc(label)}</span>
        </button>`;
      }).join('')}
    </div>`;
  }).join('');

  const legend = document.getElementById('mitre-legend');
  legend.hidden = false;
  legend.querySelector('.scale-steps').innerHTML = SEQ.map((_, i) =>
    `<span style="background:${seqColor(i)}"></span>`).join('');
  setText('mitre-scale-max', fmtInt(max));

  /* The matrix already answers "which technique"; this answers the
     different question of which stage of the kill chain this network is
     seeing most. One hue, ranked by the tactics' own order. */
  const tactics = byKillChain;
  upsertChart('mitre', 'chart-mitre', {
    type: 'bar',
    data: {
      labels: tactics.map(t => t.tactic),
      datasets: [{
        label: 'alerts', data: tactics.map(t => t.techniques.reduce(
          (acc, x) => acc + (inWindow[x.technique_id] || 0), 0)),
        backgroundColor: token('--s-1'),
        borderRadius: { topLeft: 4, topRight: 4, bottomLeft: 0, bottomRight: 0 },
        maxBarThickness: 24,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { maxRotation: 45, minRotation: 0 } },
        y: { grid: grid(), beginAtZero: true, title: { display: true, text: 'alerts' } },
      },
    },
  });
}

/* ══════════════ MODULE 5 — Protocols ══════════════ */
async function loadProtocols() {
  const [dist, catalog] = await Promise.all([
    api('/api/stats/protocols', { minutes: windowMinutes() }),
    api('/api/protocols'),
  ]);
  const byName = Object.fromEntries(dist.map(d => [d.protocol, d]));

  /* Two ranked bars answering two different questions, rather than a bar
     and a donut answering the same one. A 21-slice donut is unreadable at
     any size. */
  const byPackets = dist.slice().sort((a, b) => b.packets - a.packets)
    .map(d => ({ label: d.protocol, value: d.packets }));
  rankedBar('protocols', 'chart-protocols', topNWithOther(byPackets, 8),
    { unit: 'packets' });

  const byBytes = dist.slice().sort((a, b) => b.bytes - a.bytes)
    .map(d => ({ label: d.protocol, value: d.bytes }));
  rankedBar('protoBytes', 'chart-proto-bytes', topNWithOther(byBytes, 8),
    { unit: 'bytes', format: fmtBytes });

  const parsed = catalog.filter(c => c.packets_parsed > 0).length;
  setText('dpi-badge', `${parsed} of ${catalog.length} supported protocols seen`);
  document.getElementById('protocol-tbody').innerHTML = catalog.map(c => {
    const d = byName[c.protocol] || {};
    const riskInk = c.risk === 'HIGH' ? 'var(--sev-high)'
      : c.risk === 'MEDIUM' ? 'var(--sev-med)' : 'var(--ink-3)';
    return `<tr>
      <td><span class="proto-tag">${esc(c.protocol)}</span></td>
      <td style="color:${riskInk}">${esc(c.risk.toLowerCase())}</td>
      <td>${c.encrypted
        ? '<span class="chip">encrypted</span>'
        : '<span class="chip muted">cleartext</span>'}</td>
      <td class="num">${fmtInt(d.packets || 0)}</td>
      <td class="num">${esc(fmtBytes(d.bytes || 0))}</td>
      <td class="num" style="color:${d.alerts ? 'var(--ink-1)' : 'var(--ink-3)'}">${fmtInt(d.alerts || 0)}</td>
    </tr>`;
  }).join('');
}

/* ══════════════ MODULE 6 — Hosts and flows ══════════════
   Every bar here answers a magnitude question, so every bar takes the one
   magnitude hue. Severity steps are reserved for severity: painting a
   high-volume talker orange would make the chart claim a severity the data
   never asserted. Where a host has raised alerts, the alert count beside
   the bar says so in words. */
async function loadHosts() {
  const [talkers, risky, geo, flows] = await Promise.all([
    api('/api/hosts/top', { limit: 25, order: 'packets_sent' }),
    api('/api/hosts/top', { limit: 12, order: 'threat_score' }),
    api('/api/geo'),
    api('/api/connections', { limit: 25, order: 'bytes' }),
  ]);

  const maxPkts = Math.max(1, ...talkers.map(h => h.packets_sent));
  document.getElementById('top-talkers').innerHTML = talkers.length
    ? talkers.slice(0, 12).map(h => `
        <button type="button" class="bar-row clickable" data-action="open-host" data-ip="${esc(h.ip)}">
          <span class="lbl">${esc(h.ip)}</span>
          <span class="track"><span class="fill"
            style="width:${(h.packets_sent / maxPkts * 100).toFixed(1)}%"></span></span>
          <span class="val">${fmtInt(h.packets_sent)} pkts${
            h.alert_count ? ' · ' + fmtInt(h.alert_count) + (h.alert_count === 1 ? ' alert' : ' alerts') : ''}</span>
        </button>`).join('')
    : emptyPanel('hosts');

  const scored = risky.filter(h => h.threat_score > 0);
  const maxScore = Math.max(1, ...scored.map(h => h.threat_score));
  document.getElementById('top-threat-hosts').innerHTML = scored.length
    ? scored.map(h => `
        <button type="button" class="bar-row clickable" data-action="open-host" data-ip="${esc(h.ip)}">
          <span class="lbl">${esc(h.ip)}</span>
          <span class="chip muted">${esc(h.country)}</span>
          <span class="track"><span class="fill"
            style="width:${(h.threat_score / maxScore * 100).toFixed(1)}%"></span></span>
          <span class="val">${fmtInt(h.alert_count)} ${h.alert_count === 1 ? 'alert' : 'alerts'}</span>
        </button>`).join('')
    : stateBlock('', 'No host has scored yet',
        'Threat score accrues as alerts are raised against an address.');

  /* The bars rank one measure; the table carries all of them side by side,
     which is what an analyst needs to tell a busy host from a bad one. */
  setText('talkers-badge', talkers.length
    ? talkers.length + ' addresses by packets sent' : 'No hosts observed');
  document.getElementById('talkers-tbody').innerHTML = talkers.length
    ? talkers.map(h => `
        <tr>
          <td data-label="Address">${ipLink(h.ip)}</td>
          <td data-label="Zone"><span class="chip muted">${h.is_internal ? 'internal' : 'external'}</span></td>
          <td data-label="Pkts sent" class="num">${fmtInt(h.packets_sent)}</td>
          <td data-label="Pkts recv" class="num">${fmtInt(h.packets_recv)}</td>
          <td data-label="Bytes sent" class="num">${esc(fmtBytes(h.bytes_sent))}</td>
          <td data-label="Alerts" class="num"${h.alert_count ? '' : ' style="color:var(--ink-3)"'}>${fmtInt(h.alert_count)}</td>
          <td data-label="Threat" class="num"${h.threat_score ? '' : ' style="color:var(--ink-3)"'}>${esc(fmtScore(h.threat_score))}</td>
        </tr>`).join('')
    : `<tr><td colspan="7">${emptyPanel('hosts')}</td></tr>`;

  /* A country with no packets is not a row; it is an absence. */
  const seenGeo = geo.filter(g => g.packets > 0);
  const maxGeo = Math.max(1, ...seenGeo.map(g => g.packets));
  document.getElementById('geo-list').innerHTML = seenGeo.length
    ? seenGeo.map(g => `
        <div class="bar-row">
          <span class="lbl">${esc(g.country)}</span>
          <span class="track"><span class="fill"
            style="width:${(g.packets / maxGeo * 100).toFixed(1)}%"></span></span>
          <span class="val">${fmtInt(g.packets)} pkts${
            g.alerts ? ' · ' + fmtInt(g.alerts) + (g.alerts === 1 ? ' alert' : ' alerts') : ''}</span>
        </div>`).join('')
    : stateBlock('', 'No geography recorded',
        'Enrichment is prefix-based and only resolves public addresses.');

  document.getElementById('flows-tbody').innerHTML = flows.length
    ? flows.map(f => `
        <tr>
          <td data-label="Source">${ipLink(f.src_ip)}<span class="ink-3">:${esc(f.src_port)}</span></td>
          <td data-label="Dest">${ipLink(f.dst_ip)}<span class="ink-3">:${esc(f.dst_port)}</span></td>
          <td data-label="Proto"><span class="proto-tag">${esc(f.protocol)}</span></td>
          <td data-label="Pkts" class="num">${fmtInt(f.packets)}</td>
          <td data-label="Bytes" class="num">${esc(fmtBytes(f.bytes))}</td>
        </tr>`).join('')
    : `<tr><td colspan="5">${emptyPanel('flows')}</td></tr>`;
}

/* Every address in the console is a way into its dossier. A real anchor, so
   it is keyboard reachable and can be opened in a new tab. */
function ipLink(ip) {
  if (!ip) return '<span class="unavailable">—</span>';
  return `<a class="ip-link" href="#/host/${encodeURIComponent(ip)}">${esc(ip)}</a>`;
}

function fmtScore(v) {
  if (v == null) return '—';
  return Number.isInteger(v) ? String(v) : v.toFixed(1);
}


/* ══════════════ MODULE 7 — Activity Trends ══════════════ */
async function loadTimeline() {
  const [timeline, throughput] = await Promise.all([
    api('/api/stats/timeline', { hours: windowHours(), bucket_s: windowBucket() }),
    api('/api/stats/throughput', { minutes: windowMinutes() }),
  ]);

  const buckets = [...new Set(timeline.map(r => r.bucket))].sort((a, b) => a - b);
  const labels = buckets.map(b => fmtTime(b));
  const countFor = names => buckets.map(b => timeline
    .filter(r => r.bucket === b && names.includes(r.severity))
    .reduce((acc, r) => acc + r.count, 0));

  /* Under deuteranopia, adjacent severity hues in a stack collapse into
     each other, so severity is faceted into one row per band. Each row
     carries a single colour, and nothing has to be told apart by hue. */
  timeSeries('timeline', 'chart-timeline',
    labels, countFor(['CRITICAL']), '--mark-crit', { unit: 'alerts', type: 'bar' });
  timeSeries('timelineHigh', 'chart-timeline-high',
    labels, countFor(['HIGH']), '--mark-high', { unit: 'alerts', type: 'bar' });
  timeSeries('timelineRest', 'chart-timeline-rest',
    labels, countFor(['MEDIUM', 'LOW', 'INFO']), '--mark-med',
    { unit: 'alerts', type: 'bar', showX: true });

  timeSeries('volume', 'chart-volume',
    throughput.map(r => fmtTime(r.bucket)), throughput.map(r => r.bytes),
    '--s-1', { unit: 'bytes', format: fmtBytes, showX: true });
}

/* ══════════════ MODULE 8 — Detection Performance / Health ══════════════ */
async function loadPerformance() {
  const [perf, health, engine] = await Promise.all([
    api('/api/performance', { limit: 120 }),
    api('/api/health'),
    api('/api/detectors'),
  ]);
  const history = perf.history.slice().reverse();
  const latest = perf.history[0] || {};
  const live = perf.live || {};

  /* A meter needs a threshold the number is actually measured against.
     The query-latency target of 50 ms is real and documented; there is no
     such target for parse or detect cost, so those show the number and no
     bar rather than a fill invented to look like data. */
  const parseUs = live.parse_us_avg != null ? live.parse_us_avg : (latest.parse_us_avg || 0);
  const detectUs = live.detect_us_avg != null ? live.detect_us_avg : (latest.detect_us_avg || 0);
  const errors = live.parse_errors != null ? live.parse_errors : (latest.parse_errors || 0);

  document.getElementById('perf-strip').innerHTML = [
    meter('Throughput', fmtInt(latest.packets_per_min), 'packets/min',
          { value: latest.packets_per_min || 0, target: 5000, higherIsBetter: true }),
    meter('Query p50', (latest.query_p50_ms || 0).toFixed(2), 'ms, target under 50',
          { value: latest.query_p50_ms || 0, target: 50 }),
    meter('Query p95', (latest.query_p95_ms || 0).toFixed(2), 'ms, target under 50',
          { value: latest.query_p95_ms || 0, target: 50 }),
    meter('Parse', parseUs.toFixed(1), 'microseconds per packet', null),
    meter('Detect', detectUs.toFixed(1), 'microseconds per packet', null),
    meter('Rejected frames', fmtInt(errors), 'malformed, since start', null,
          errors > 0 ? 'warn' : ''),
  ].join('');

  upsertChart('perfTp', 'chart-perf-tp', {
    type: 'line',
    data: {
      labels: history.map(r => fmtTime(r.ts)),
      datasets: [{
        label: 'packets/min', data: history.map(r => r.packets_per_min),
        borderColor: token('--s-1'), backgroundColor: alpha('--s-1', 0.10),
        fill: true, tension: 0.3, pointRadius: 0, borderWidth: 2,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { x: { grid: grid(), ticks: { maxTicksLimit: 8 } }, y: { grid: grid(), beginAtZero: true } },
    },
  });

  upsertChart('perfQ', 'chart-perf-q', {
    type: 'line',
    data: {
      labels: history.map(r => fmtTime(r.ts)),
      datasets: [
        { label: 'p50 ms', data: history.map(r => r.query_p50_ms),
          borderColor: token('--seq-2'), pointRadius: 0, borderWidth: 2, tension: 0.3 },
        { label: 'p95 ms', data: history.map(r => r.query_p95_ms),
          borderColor: token('--seq-4'), pointRadius: 0, borderWidth: 2, tension: 0.3 },
        { label: 'target 50 ms', data: history.map(() => 50),
          borderColor: token('--ink-3'), pointRadius: 0, borderWidth: 1,
          fill: false, tension: 0 },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { boxWidth: 10 } } },
      scales: { x: { grid: grid(), ticks: { maxTicksLimit: 8 } }, y: { grid: grid(), beginAtZero: true } },
    },
  });

  /* Per-detector cost and yield is a table, not a chart: seventeen
     categories against two unrelated measures is exactly the case a chart
     communicates worse than rows do. */
  const detectors = engine.detectors.slice()
    .sort((a, b) => b.findings_emitted - a.findings_emitted);
  const firing = detectors.filter(d => d.findings_emitted > 0).length;
  setText('detperf-badge',
    `${firing} of ${engine.detector_count} detectors have fired · `
    + `${fmtInt(engine.packets_analyzed)} packets analysed`);
  document.getElementById('detperf-tbody').innerHTML = detectors.map(d => {
    const rate = d.packets_seen
      ? (d.findings_emitted / d.packets_seen * 10000).toFixed(2)
      : null;
    return `<tr>
      <td data-label="Detector">${esc(d.name)}</td>
      <td data-label="Threat type">${esc(d.threat_type)}</td>
      <td data-label="Pkts seen" class="num">${fmtInt(d.packets_seen)}</td>
      <td data-label="Findings" class="num"${d.findings_emitted ? '' : ' style="color:var(--ink-3)"'}>${fmtInt(d.findings_emitted)}</td>
      <td data-label="Per 10k" class="num">${rate === null
        ? '<span class="unavailable">no packets seen</span>' : esc(rate)}</td>
    </tr>`;
  }).join('');

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
      <dt>Detector errors</dt><dd style="color:${health.engine.detector_errors ? 'var(--sev-crit)' : 'var(--ok)'}">${health.engine.detector_errors}</dd>
    </dl>
    <h4 style="margin-top:16px">Row counts</h4>
    <dl class="kv">
      ${Object.entries(health.tables).map(([t, n]) =>
        `<dt>${esc(t)}</dt><dd${n > 0 ? '' : ' style="color:var(--ink-3)"'}>${
          n > 0 ? fmtInt(n) : 'empty'}</dd>`).join('')}
    </dl>`;
}

/* threshold === null renders the number alone: no bar without a target. */
function meter(label, value, unit, threshold, tone) {
  let bar = '';
  if (threshold) {
    const ratio = threshold.higherIsBetter
      ? Math.min(1, threshold.value / threshold.target)
      : Math.min(1, threshold.value / threshold.target);
    const over = !threshold.higherIsBetter && threshold.value > threshold.target;
    bar = `<div class="gauge-bar"><div class="gauge-fill${over ? ' crit' : ''}"
      style="width:${(ratio * 100).toFixed(1)}%"></div></div>`;
  }
  return `<div class="perf-gauge">
    <div class="gauge-label">${esc(label)}</div>
    <div class="gauge-val${tone ? ' ' + tone : ''}">${esc(value)}</div>
    <div class="gauge-unit">${esc(unit)}</div>
    ${bar}
  </div>`;
}

/* ══════════════ MODULE 9 — Packet log ══════════════
   A live stream, so it obeys the two rules a live stream has: it never moves
   what someone is reading, and it never grows without bound. New frames land
   at the top only while the view is actually at the top and not paused;
   otherwise they queue behind a jump control that says how many are waiting. */

const PKT_MAX = 400;
const stream = {
  rows: [],           // rendered frames, newest first
  held: [],           // arrived while paused or scrolled away
  known: new Set(),   // ids in rows or held, so a poll cannot duplicate
  paused: false,
  follow: true,       // the view is at the top, so new frames may land
};

function resetStream() {
  stream.rows = [];
  stream.held = [];
  stream.known = new Set();
  stream.follow = true;
  setPktPending();
}

async function loadPackets() {
  const packets = await api('/api/packets', { limit: 120, ...pktFilters });

  const fresh = packets.filter(p => !stream.known.has(p.id));
  if (!stream.rows.length && !stream.held.length) {
    stream.rows = packets.slice(0, PKT_MAX);
  } else if (stream.paused || !stream.follow) {
    stream.held = fresh.concat(stream.held).slice(0, PKT_MAX);
  } else {
    stream.rows = fresh.concat(stream.rows).slice(0, PKT_MAX);
    if (fresh.length) announce(fresh.length + ' new packets');
  }
  stream.known = new Set(stream.rows.concat(stream.held).map(p => p.id));
  setPktPending();
  renderPackets();
}

function setPktPending() {
  const button = document.getElementById('pkt-jump');
  if (!button) return;
  button.hidden = stream.held.length === 0;
  setText('pkt-jump-label', stream.held.length === 1
    ? '1 new packet' : stream.held.length + ' new packets');
}

function releaseHeld() {
  if (stream.held.length) {
    stream.rows = stream.held.concat(stream.rows).slice(0, PKT_MAX);
    stream.held = [];
    stream.known = new Set(stream.rows.map(p => p.id));
  }
  setPktPending();
  renderPackets();
  const host = document.getElementById('pkt-scroll');
  if (host) host.scrollTop = 0;
  stream.follow = true;
}

function packetRow(p) {
  const l7 = Object.entries(p.l7 || {}).slice(0, 4)
    .map(([k, v]) => `${k}=${String(v).slice(0, 48)}`).join('  ');
  return `<tr${p.is_malicious ? ' class="flagged"' : ''} data-ip="${esc(p.src_ip)}">
    <td data-label="Time">${esc(fmtTime(p.ts))}</td>
    <td data-label="Source">${ipLink(p.src_ip)}${p.src_port ? ':' + esc(p.src_port) : ''}</td>
    <td data-label="Dest">${ipLink(p.dst_ip)}${p.dst_port ? ':' + esc(p.dst_port) : ''}</td>
    <td data-label="Proto"><span class="proto-tag">${esc(p.protocol)}</span></td>
    <td data-label="Len" class="num">${esc(p.frame_len)}</td>
    <td data-label="Flags">${esc(p.flags || '—')}</td>
    <td data-label="L7" class="cell-l7">${esc(l7) || '—'}</td>
  </tr>`;
}

function renderPackets() {
  const tbody = document.getElementById('pkt-tbody');
  setText('pkt-badge', stream.paused ? 'PAUSED'
    : stream.follow ? 'LIVE' : 'HOLDING');
  setText('pkt-buffer', stream.rows.length
    ? `${stream.rows.length} of ${PKT_MAX} frames buffered`
    : '');
  if (!stream.rows.length) {
    const reason = (pktFilters.protocol || pktFilters.src_ip || pktFilters.malicious_only)
      ? stateBlock('', 'No packets match these filters',
          'Widen the protocol or address filter, or turn off the flagged-only view.')
      : emptyPanel('packets');
    tbody.innerHTML = `<tr><td colspan="7">${reason}</td></tr>`;
    return;
  }
  tbody.innerHTML = stream.rows.map(packetRow).join('');
}

/* ══════════════ Investigation drawer ══════════════
   A real dialog: focus is trapped while it is open, Escape closes it, and
   focus returns to whatever opened it. It is also routed, because analysts
   paste evidence into tickets and a console whose state cannot be linked
   forces them to paste screenshots instead. */

const drawer = document.getElementById('drawer');
const drawerBackdrop = document.getElementById('drawer-backdrop');
let drawerReturnFocus = null;
let drawerCloseTimer = null;

/* Pivoting is the point of the drawer, so it keeps a trail. Each pivot
   pushes where you were; Back walks it. Closing clears it, because the next
   investigation starts from the surface you opened it from. */
let drawerCurrent = null;
const drawerStack = [];

function enterDrawer(kind, value, opts) {
  const same = drawerCurrent && drawerCurrent.kind === kind
    && String(drawerCurrent.value) === String(value);
  if (opts && opts.back) {
    drawerCurrent = { kind: kind, value: value };
  } else {
    if (drawerCurrent && !same && drawer.classList.contains('open')) {
      drawerStack.push(drawerCurrent);
    }
    drawerCurrent = { kind: kind, value: value };
  }
  const back = document.getElementById('drawer-back');
  back.hidden = drawerStack.length === 0;
  if (!back.hidden) {
    const prev = drawerStack[drawerStack.length - 1];
    back.setAttribute('aria-label', 'Back to ' + prev.kind + ' ' + prev.value);
  }
}

function reopenDrawer(entry, opts) {
  if (entry.kind === 'alert') return openAlert(entry.value, opts);
  if (entry.kind === 'host') return openHost(entry.value, opts);
  return openTechnique(entry.value, opts);
}

document.getElementById('drawer-back').addEventListener('click', () => {
  const prev = drawerStack.pop();
  if (prev) reopenDrawer(prev, { back: true });
});

const FOCUSABLE = 'a[href], button:not([disabled]), input, select, textarea, [tabindex]:not([tabindex="-1"])';

function openDrawer(kicker, title, html) {
  window.clearTimeout(drawerCloseTimer);
  if (!drawer.classList.contains('open')) {
    drawerReturnFocus = document.activeElement;
  }
  setText('drawer-kicker', kicker);
  setText('drawer-title', title);
  document.getElementById('drawer-body').innerHTML = html;
  drawer.hidden = false;
  drawerBackdrop.hidden = false;
  drawer.classList.remove('closing');
  /* One frame so the transition has a start value to animate from. */
  window.requestAnimationFrame(() => {
    drawer.classList.add('open');
    drawerBackdrop.classList.add('open');
    document.getElementById('drawer-title').focus();
  });
}

function closeDrawer() {
  if (!drawer.classList.contains('open')) return;
  drawer.classList.add('closing');
  drawer.classList.remove('open');
  drawerBackdrop.classList.remove('open');
  if (window.location.hash) {
    window.history.replaceState(null, '', window.location.pathname);
  }
  drawerStack.length = 0;
  drawerCurrent = null;
  document.getElementById('drawer-back').hidden = true;
  drawerCloseTimer = window.setTimeout(() => {
    drawer.hidden = true;
    drawerBackdrop.hidden = true;
    drawer.classList.remove('closing');
  }, 165);
  /* The trigger can be gone by the time the drawer closes — a search result
     the panel has since discarded, or a queue row a refresh replaced. Falling
     back to <body> would strand a keyboard user at the top of the document,
     so focus goes to the main region instead. */
  if (drawerReturnFocus && document.contains(drawerReturnFocus)) {
    drawerReturnFocus.focus({ preventScroll: true });
  } else {
    document.getElementById('main').focus({ preventScroll: true });
  }
  drawerReturnFocus = null;
}

document.getElementById('drawer-close').addEventListener('click', closeDrawer);
drawerBackdrop.addEventListener('click', closeDrawer);

drawer.addEventListener('keydown', event => {
  if (event.key !== 'Tab') return;
  const items = Array.from(drawer.querySelectorAll(FOCUSABLE))
    .filter(el => el.offsetParent !== null);
  if (!items.length) return;
  const first = items[0];
  const last = items[items.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault(); last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault(); first.focus();
  }
});

/* ── routing ──────────────────────────────────────────────────────────── */

function route(hash) {
  const match = /^#\/(alert|host|technique|view)\/(.+)$/.exec(hash || '');
  if (!match) { return false; }
  const [, kind, raw] = match;
  const value = decodeURIComponent(raw);
  if (kind === 'view') { showView(value); return true; }
  if (kind === 'alert') openAlert(Number(value), { silent: true });
  else if (kind === 'host') openHost(value, { silent: true });
  else openTechnique(value, { silent: true });
  return true;
}

function setRoute(kind, value) {
  const hash = `#/${kind}/${encodeURIComponent(value)}`;
  if (window.location.hash !== hash) {
    window.history.replaceState(null, '', hash);
  }
}

window.addEventListener('hashchange', () => {
  if (!route(window.location.hash)) closeDrawer();
});

/* ── evidence rendering ───────────────────────────────────────────────── */

/* Evidence is the detector's own record, so it is shown verbatim — but a
   raw `byte_count: 221600` under a label of "Window s" is the detector's
   variable name leaking into the interface. Units come off the key, the key
   loses the suffix that encoded them, and long integers get separators. */
const UNITS = {
  entropy: 'bits/byte', label_entropy: 'bits/byte',
  payload_len: 'B', frame_len: 'B', mbps: 'Mbps', pps: 'pps',
};

const UNIT_SUFFIXES = [
  ['_per_s', 'per second'], ['_us', '\u00b5s'], ['_ms', 'ms'], ['_s', 's'],
  ['_bytes', 'B'], ['_pct', '%'],
];

function unitFor(key) {
  if (UNITS[key]) return { unit: UNITS[key], label: key };
  for (const pair of UNIT_SUFFIXES) {
    if (key.endsWith(pair[0]) && key.length > pair[0].length) {
      return { unit: pair[1], label: key.slice(0, -pair[0].length) };
    }
  }
  if (/byte/.test(key)) return { unit: 'B', label: key };
  return { unit: '', label: key };
}

function humanKey(key) {
  return key.replace(/_/g, ' ').replace(/^./, c => c.toUpperCase());
}

function evidenceValue(value) {
  if (typeof value !== 'number') return String(value);
  if (Number.isInteger(value)) return value.toLocaleString();
  return value.toFixed(3).replace(/0+$/, '').replace(/\.$/, '');
}

function evidenceHtml(evidence) {
  if (!evidence || typeof evidence !== 'object') {
    return `<p class="drawer-note">The detector recorded no structured evidence.</p>`;
  }
  const rows = [];
  const nested = {};
  Object.entries(evidence).forEach(([key, value]) => {
    if (value === null || value === undefined) return;
    if (Array.isArray(value) && value.every(v => typeof v !== 'object')) {
      rows.push([key, value.map(v => `<span class="chip">${esc(v)}</span>`).join(' ')]);
    } else if (typeof value === 'object') {
      nested[key] = value;
    } else {
      const meta = unitFor(key);
      rows.push([meta.label, esc(evidenceValue(value))
        + (meta.unit ? ` <span class="unit">${esc(meta.unit)}</span>` : '')]);
    }
  });
  let html = rows.length
    ? '<dl class="evidence">' + rows.map(([k, v]) =>
        `<dt>${esc(humanKey(k))}</dt><dd>${v}</dd>`).join('') + '</dl>'
    : '<p class="drawer-note">The detector recorded no scalar evidence.</p>';
  if (Object.keys(nested).length) {
    html += `<pre>${esc(JSON.stringify(nested, null, 2))}</pre>`;
  }
  return html;
}

function hostRef(ip, port) {
  if (!ip) return '&mdash;';
  const zone = isPrivate(ip) ? 'internal' : 'external';
  return `<a href="#/host/${encodeURIComponent(ip)}" class="mono">${esc(ip)}</a>`
    + (port ? `<span class="mono">:${esc(port)}</span>` : '')
    + ` <span class="chip muted">${zone}</span>`;
}

/* ── alert ────────────────────────────────────────────────────────────── */

async function openAlert(id, opts) {
  try {
    const a = await api('/api/alerts/' + id);
    setRoute('alert', id);
    enterDrawer('alert', id, opts);
    openDrawer(`Alert ${a.id} · ${fmtDateTime(a.ts)}`, a.threat_type, `
      <div class="verdict">
        <span class="sev-badge sev-${esc(a.severity)}">${esc(a.severity)}</span>
        <span class="chip">${Math.round(a.confidence * 100)}% confidence</span>
        <span class="chip muted">${esc(a.detector)}</span>
      </div>
      <p class="verdict-body">${esc(a.description)}</p>

      <h4>Connection</h4>
      <dl class="evidence">
        <dt>Source</dt><dd>${hostRef(a.src_ip, a.src_port)}</dd>
        <dt>Destination</dt><dd>${hostRef(a.dst_ip, a.dst_port)}</dd>
        <dt>Protocol</dt><dd>${esc(a.protocol || '—')}</dd>
        <dt>Raised</dt><dd>${esc(fmtDateTime(a.ts))}</dd>
      </dl>

      <h4>Why this fired</h4>
      ${evidenceHtml(a.evidence)}

      <h4>ATT&amp;CK mapping</h4>
      ${a.techniques.length ? a.techniques.map(t => `
        <div class="technique">
          <div class="technique-head">
            <span class="technique-id">${esc(t.technique_id)}</span>
            <span class="technique-name">${esc(t.name)}</span>
            <span class="chip muted">${esc(t.tactic)}</span>
          </div>
          <p class="rationale">${esc(t.rationale)}</p>
          <p style="margin-top:var(--sp-2)">
            <a class="technique-link" href="${esc(t.url)}" target="_blank" rel="noopener">
              Read the technique on attack.mitre.org</a>
          </p>
        </div>`).join('')
        : '<p class="drawer-note">No technique is mapped to this alert.</p>'}

      <h4>Supporting packets (${a.related_packets.length})</h4>
      ${a.related_packets.length ? `<div class="tbl-wrap"><table class="data-tbl">
        <thead><tr><th scope="col">Time</th><th scope="col">Connection</th>
          <th scope="col">Proto</th><th scope="col" class="num">Bytes</th>
          <th scope="col">Flags</th></tr></thead>
        <tbody>${a.related_packets.map(p => `<tr>
          <td>${esc(fmtTime(p.ts))}</td>
          <td>${esc(p.src_ip)}:${esc(p.src_port || 0)} &rarr; ${esc(p.dst_ip)}:${esc(p.dst_port || 0)}</td>
          <td><span class="proto-tag">${esc(p.protocol)}</span></td>
          <td class="num">${esc(p.frame_len)}</td>
          <td>${esc(p.flags || '—')}</td></tr>`).join('')}</tbody>
      </table></div>`
        : '<p class="drawer-note">No packets were retained inside the alert window.</p>'}

      <h4>Pivot</h4>
      <div class="pivots">
        ${a.src_ip ? `<a class="filter-btn" href="#/host/${encodeURIComponent(a.src_ip)}">This source&rsquo;s dossier</a>` : ''}
        ${a.src_ip ? `<button type="button" class="filter-btn" data-action="filter-source" data-ip="${esc(a.src_ip)}">All alerts from this source</button>` : ''}
        ${a.techniques.length ? `<a class="filter-btn" href="#/technique/${encodeURIComponent(a.techniques[0].technique_id)}">Other alerts on ${esc(a.techniques[0].technique_id)}</a>` : ''}
      </div>

      <div class="drawer-actions">
        ${a.acknowledged
          ? '<span class="ack-btn acked">Acknowledged</span>'
          : isDemo
            ? '<button class="ack-btn" type="button" disabled>Acknowledge</button>'
              + '<p class="drawer-note">The public demo is read-only.</p>'
            : `<button class="ack-btn" type="button" data-action="ack-alert" data-alert-id="${a.id}">Acknowledge</button>`}
      </div>`);
  } catch (e) { showError(e); }
}

/* ── host ─────────────────────────────────────────────────────────────── */

async function openHost(ip, opts) {
  if (!ip || ip === 'null') return;
  try {
    const h = await api('/api/hosts/' + encodeURIComponent(ip));
    setRoute('host', ip);
    enterDrawer('host', ip, opts);
    openDrawer(h.is_internal ? 'Internal host' : 'External host', h.ip, `
      <div class="verdict">
        <span class="chip">${esc(h.country)}</span>
        <span class="chip ${h.threat_score > 0 ? 'tech' : 'muted'}">threat score ${esc(h.threat_score)}</span>
        <span class="chip muted">${fmtInt(h.alert_count)} alert${h.alert_count === 1 ? '' : 's'}</span>
      </div>

      <h4>Traffic</h4>
      <dl class="evidence">
        <dt>First seen</dt><dd>${esc(fmtDateTime(h.first_seen))}</dd>
        <dt>Last seen</dt><dd>${esc(fmtDateTime(h.last_seen))}</dd>
        <dt>Packets sent</dt><dd>${fmtInt(h.packets_sent)}</dd>
        <dt>Packets received</dt><dd>${fmtInt(h.packets_recv)}</dd>
        <dt>Bytes sent</dt><dd>${esc(fmtBytes(h.bytes_sent))}</dd>
        <dt>Bytes received</dt><dd>${esc(fmtBytes(h.bytes_recv))}</dd>
      </dl>

      <h4>Protocols used</h4>
      ${h.top_protocols.length ? h.top_protocols.map(p => `
        <div class="bar-row"><span class="lbl">${esc(p.protocol)}</span>
        <span class="val">${fmtInt(p.packets)} pkts · ${esc(fmtBytes(p.bytes))}</span></div>`).join('')
        : '<p class="drawer-note">No protocol breakdown recorded.</p>'}

      <h4>Top peers</h4>
      ${h.top_peers.length ? h.top_peers.map(p => `
        <div class="bar-row">
          <span class="lbl"><a href="#/host/${encodeURIComponent(p.peer)}">${esc(p.peer)}</a></span>
          <span class="val">${esc(fmtBytes(p.bytes))}</span></div>`).join('')
        : '<p class="drawer-note">No peers recorded.</p>'}

      <h4>Recent alerts (${h.recent_alerts.length})</h4>
      ${h.recent_alerts.length ? h.recent_alerts.map(a => `
        <button type="button" class="bar-row clickable" data-action="open-alert" data-alert-id="${a.id}">
          <span class="sev-badge sev-${esc(a.severity)}">${esc(a.severity)}</span>
          <span class="lbl" style="flex:1">${esc(a.threat_type)}</span>
          <span class="val">${esc(fmtTime(a.ts))}</span>
        </button>`).join('')
        : '<p class="drawer-note">This host has raised no alerts.</p>'}

      <h4>Pivot</h4>
      <div class="pivots">
        <button type="button" class="filter-btn" data-action="filter-source" data-ip="${esc(h.ip)}">All alerts from this source</button>
      </div>`);
  } catch (e) { showError(e); }
}

/* ── technique ────────────────────────────────────────────────────────── */

async function openTechnique(id, opts) {
  try {
    const t = await api('/api/mitre/techniques/' + encodeURIComponent(id));
    setRoute('technique', id);
    enterDrawer('technique', id, opts);
    openDrawer(`${t.tactic} · ${t.technique_id}`, t.name, `
      <div class="verdict">
        <span class="chip ${t.alert_count ? 'tech' : 'muted'}">${fmtInt(t.alert_count)} alert${t.alert_count === 1 ? '' : 's'}</span>
        <a class="chip" href="${esc(t.url)}" target="_blank" rel="noopener">attack.mitre.org</a>
      </div>

      <h4>Why NetWatch maps this</h4>
      <p class="rationale">${esc(t.rationale)}</p>

      <h4>Detectors that raise it</h4>
      ${t.detectors.length ? t.detectors.map(d => `
        <div class="bar-row"><span class="lbl">${esc(d.detector)}</span>
        <span class="val">${fmtInt(d.count)} alert${d.count === 1 ? '' : 's'}</span></div>`).join('')
        : '<p class="drawer-note">Covered by a detector, but not yet observed in traffic. That is coverage waiting on traffic, not a gap in detection.</p>'}

      <h4>Recent alerts</h4>
      ${t.recent_alerts.length ? t.recent_alerts.map(a => `
        <button type="button" class="bar-row clickable" data-action="open-alert" data-alert-id="${a.id}">
          <span class="sev-badge sev-${esc(a.severity)}">${esc(a.severity)}</span>
          <span class="lbl" style="flex:1">${esc(a.src_ip)} &rarr; ${esc(a.dst_ip)}</span>
          <span class="val">${esc(fmtTime(a.ts))}</span>
        </button>`).join('')
        : '<p class="drawer-note">Nothing raised yet.</p>'}`);
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
  'filter-source':  el => {
    closeDrawer();
    document.getElementById('alert-ip-filter').value = el.dataset.ip;
    alertFilters.src_ip = el.dataset.ip;
    showView('alerts', { focus: true });
  },
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

/* Hiding with display alone leaves the hidden sections in the accessibility
   tree and leaves focus wherever it was. Both are fixed here, and focus is
   moved to the new view so a keyboard user lands in the content they asked
   for rather than back at the top of the rail. */
const seenViews = new Set();

async function showView(name, opts) {
  if (!LOADERS[name]) name = 'alerts';
  currentView = name;
  document.querySelectorAll('#main section[id^="view-"]').forEach(section => {
    const on = section.id === 'view-' + name;
    section.hidden = !on;
    section.setAttribute('aria-hidden', String(!on));
  });
  document.querySelectorAll('.nav-item').forEach(item => {
    const on = item.dataset.view === name;
    item.classList.toggle('active', on);
    item.setAttribute('aria-current', on ? 'page' : 'false');
  });
  const heading = document.querySelector('#view-' + name + ' [data-view-title]');
  if (heading && opts && opts.focus) { heading.focus(); }
  document.getElementById('main').scrollTop = 0;
  await runLoader(name);
}

async function runLoader(name) {
  const repeat = seenViews.has(name);
  if (repeat) holding(name, true);
  try {
    await LOADERS[name]();
    seenViews.add(name);
    markRefreshed(true);
    clearError();
  } catch (e) {
    markRefreshed(false);
    showError(e);
  } finally {
    holding(name, false);
  }
}

document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => showView(item.dataset.view, { focus: true }));
});

/* ══════════════ Theme and density ══════════════
   Both are viewer preferences, persisted locally and applied to :root.
   Storage can throw in a private window, so every access is guarded and
   the interface renders correctly when it fails. */
function readPref(key, fallback) {
  try { return window.localStorage.getItem(key) || fallback; }
  catch (e) { return fallback; }
}
function writePref(key, value) {
  try { window.localStorage.setItem(key, value); } catch (e) { /* not fatal */ }
}

/* Three states, not two. An explicit choice stamps data-theme and wins in
   both directions; with no stored choice nothing is stamped, so the dark
   palette on :root is the default and a viewer whose system asks for light
   gets the light block. */
function applyTheme(theme) {
  const root = document.documentElement;
  if (theme === 'system') { root.removeAttribute('data-theme'); }
  else { root.setAttribute('data-theme', theme); }
  const dark = theme === 'dark'
    || (theme === 'system' && !window.matchMedia('(prefers-color-scheme: light)').matches);
  const toggle = document.getElementById('theme-toggle');
  toggle.setAttribute('aria-pressed', String(!dark));
  toggle.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
  setText('theme-label', dark ? 'Dark' : 'Light');
  /* Charts hold their own colours, so a theme change has to repaint them
     from the new token values rather than waiting for the next fetch. The
     first call happens before boot, when there is nothing to repaint. */
  retheme();
  applyChartDefaults();
  if (booted) { runLoader(currentView); }
}

function applyDensity(density) {
  document.documentElement.setAttribute('data-density', density);
  document.querySelectorAll('.seg-btn[data-density]').forEach(btn =>
    btn.setAttribute('aria-pressed', String(btn.dataset.density === density)));
}

document.getElementById('theme-toggle').addEventListener('click', () => {
  const light = window.matchMedia('(prefers-color-scheme: light)').matches;
  const current = document.documentElement.getAttribute('data-theme')
    || (light ? 'light' : 'dark');
  const next = current === 'light' ? 'dark' : 'light';
  writePref('netwatch.theme', next);
  applyTheme(next);
});

document.querySelectorAll('.seg-btn[data-density]').forEach(btn => {
  btn.addEventListener('click', () => {
    writePref('netwatch.density', btn.dataset.density);
    applyDensity(btn.dataset.density);
  });
});

/* ══════════════ Queue controls ══════════════ */

function refreshQueue() {
  queue.limit = PAGE;
  loadAlerts().catch(showError);
}

document.querySelectorAll('#severity-filters .seg-btn[data-sev]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#severity-filters .seg-btn[data-sev]')
      .forEach(b => b.setAttribute('aria-pressed', String(b === btn)));
    alertFilters.severity = btn.dataset.sev;
    refreshQueue();
  });
});

document.getElementById('alert-state').addEventListener('change', event => {
  alertFilters.acknowledged = event.target.value;
  refreshQueue();
});

document.getElementById('alert-detector').addEventListener('change', event => {
  alertFilters.threat_type = event.target.value;
  refreshQueue();
});

document.getElementById('time-window').addEventListener('change', () => {
  seenViews.clear();
  queue.first = true;
  refreshQueue();
  if (currentView !== 'alerts') runLoader(currentView);
});

/* Debounced, no submit button: a monitoring console should not make an
   analyst press a button to see the effect of what they typed. */
let ipFilterTimer = null;
document.getElementById('alert-ip-filter').addEventListener('input', event => {
  window.clearTimeout(ipFilterTimer);
  const value = event.target.value.trim();
  ipFilterTimer = window.setTimeout(() => {
    alertFilters.src_ip = value;
    refreshQueue();
  }, 250);
});

document.getElementById('filters-toggle').addEventListener('click', event => {
  const row = document.getElementById('alert-filters');
  const open = row.classList.toggle('open');
  event.currentTarget.setAttribute('aria-expanded', String(open));
  event.currentTarget.textContent = open ? 'Hide filters' : 'Filters';
});

document.getElementById('alert-clear').addEventListener('click', clearAlertFilters);

function clearAlertFilters() {
  alertFilters = { severity: '', src_ip: '', threat_type: '', acknowledged: '' };
  document.getElementById('alert-ip-filter').value = '';
  document.getElementById('alert-state').value = '';
  document.getElementById('alert-detector').value = '';
  document.querySelectorAll('#severity-filters .seg-btn[data-sev]')
    .forEach(b => b.setAttribute('aria-pressed', String(b.dataset.sev === '')));
  refreshQueue();
}

document.getElementById('alerts-pending').addEventListener('click', () => {
  refreshQueue();
  document.getElementById('alerts-scroll').scrollTop = 0;
});

document.getElementById('alerts-more').addEventListener('click', () => {
  queue.limit = Math.min(500, queue.limit + PAGE);
  loadAlerts().catch(showError);
});

document.querySelectorAll('#alerts-table .th-sort').forEach(button => {
  button.addEventListener('click', () => {
    const key = button.dataset.sort;
    queue.sort = key === queue.sort.key
      ? { key, dir: queue.sort.dir === 'desc' ? 'asc' : 'desc' }
      : { key, dir: 'desc' };
    /* Sorting is an explicit action, so it is allowed to move rows. */
    loadAlerts().catch(showError);
  });
});

/* The whole row is the target, not one cell in it. */
document.getElementById('alerts-tbody').addEventListener('click', event => {
  if (event.target.closest('[data-action]')) return;
  const tr = event.target.closest('tr[data-alert-id]');
  if (!tr) return;
  selectRow(tr.dataset.alertId);
  openAlert(Number(tr.dataset.alertId));
});

function selectRow(id) {
  queue.selected = id == null ? null : String(id);
  markSelected();
  const tr = document.querySelector(
    '#alerts-tbody tr[data-alert-id="' + queue.selected + '"]');
  if (tr) { tr.focus({ preventScroll: true }); tr.scrollIntoView({ block: 'nearest' }); }
}

function moveSelection(step) {
  const rows = Array.from(document.querySelectorAll('#alerts-tbody tr[data-alert-id]'));
  if (!rows.length) return;
  const at = rows.findIndex(tr => tr.dataset.alertId === queue.selected);
  const next = at < 0 ? 0 : Math.max(0, Math.min(rows.length - 1, at + step));
  selectRow(rows[next].dataset.alertId);
}

const TYPING = new Set(['INPUT', 'SELECT', 'TEXTAREA']);

document.addEventListener('keydown', event => {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
    event.preventDefault();
    focusSearch();
    return;
  }
  if (event.metaKey || event.ctrlKey || event.altKey) return;
  const typing = TYPING.has(document.activeElement.tagName);

  if (event.key === 'Escape') {
    if (typing) { document.activeElement.blur(); return; }
    closeDrawer();
    return;
  }
  if (typing) return;

  /* Search is reachable from anywhere; row navigation is not, because there
     are no rows to move through outside the queue. */
  if (event.key === '/') {
    event.preventDefault();
    focusSearch();
    return;
  }
  /* The drawer owns the keyboard while it is open. Without this the queue's
     Enter shortcut preventDefault()s the Return key on a focused pivot link
     inside the drawer and reopens the alert instead of following it. */
  if (drawer.classList.contains('open')) return;
  if (currentView !== 'alerts') return;

  if (event.key === 'ArrowDown' || event.key === 'j') {
    event.preventDefault(); moveSelection(1);
  } else if (event.key === 'ArrowUp' || event.key === 'k') {
    event.preventDefault(); moveSelection(-1);
  } else if (event.key === 'Enter' && queue.selected) {
    event.preventDefault(); openAlert(Number(queue.selected));
  } else if (event.key === 'a' && queue.selected) {
    const btn = document.querySelector(
      '#alerts-tbody tr[data-alert-id="' + queue.selected + '"] .ack-btn[data-action]');
    if (btn) { event.preventDefault(); ackAlert(Number(queue.selected), btn); }
  }
});

async function fillProtocolFilter() {
  const select = document.getElementById('pkt-proto-filter');
  if (select.options.length > 1) return;
  try {
    const catalog = await api('/api/protocols');
    catalog.forEach(c => {
      const option = document.createElement('option');
      option.value = c.protocol;
      option.textContent = c.protocol;
      select.appendChild(option);
    });
  } catch (e) { /* the filter stays at "Any" */ }
}

document.getElementById('pkt-proto-filter').addEventListener('change', event => {
  pktFilters.protocol = event.target.value;
  resetStream();
  loadPackets().catch(showError);
});

let pktIpTimer = null;
document.getElementById('pkt-ip-filter').addEventListener('input', event => {
  window.clearTimeout(pktIpTimer);
  const value = event.target.value.trim();
  pktIpTimer = window.setTimeout(() => {
    pktFilters.src_ip = value;
    resetStream();
    loadPackets().catch(showError);
  }, 250);
});

document.getElementById('pkt-mal-btn').addEventListener('click', event => {
  pktFilters.malicious_only = !pktFilters.malicious_only;
  event.currentTarget.classList.toggle('active', pktFilters.malicious_only);
  event.currentTarget.setAttribute('aria-pressed', String(pktFilters.malicious_only));
  resetStream();
  loadPackets().catch(showError);
});

document.getElementById('pkt-pause').addEventListener('click', event => {
  stream.paused = !stream.paused;
  const button = event.currentTarget;
  button.setAttribute('aria-pressed', String(stream.paused));
  button.classList.toggle('active', stream.paused);
  button.textContent = stream.paused ? 'Resume' : 'Pause';
  if (!stream.paused) releaseHeld();
  else renderPackets();
});

document.getElementById('pkt-jump').addEventListener('click', releaseHeld);

/* Newest frames land at the top, so "following" means the view is at the
   top. Reading back through history holds the stream rather than yanking
   the rows out from under the cursor. */
document.getElementById('pkt-scroll').addEventListener('scroll', event => {
  const atTop = event.currentTarget.scrollTop <= 8;
  if (atTop === stream.follow) return;
  stream.follow = atTop;
  if (atTop && !stream.paused) releaseHeld();
  else renderPackets();
});

/* The whole frame is the target, but a real link inside it wins: the row
   handler would otherwise fire alongside the anchor's own navigation. */
document.getElementById('pkt-tbody').addEventListener('click', event => {
  if (event.target.closest('a')) return;
  const tr = event.target.closest('tr[data-ip]');
  if (tr && tr.dataset.ip) openHost(tr.dataset.ip);
});


/* ══════════════ Chart table twins ══════════════
   Every chart ships the same numbers as a real table. Tooltips enhance a
   chart; they never gate a value, and a canvas is invisible to a screen
   reader. Built from the chart's own data, so the table cannot drift from
   what is plotted. */

function chartsInPanel(panel) {
  return Array.from(panel.querySelectorAll('canvas[id^="chart-"]'))
    .map(c => Object.keys(charts).find(k => charts[k] && charts[k].canvas === c))
    .filter(Boolean);
}

function twinTable(key) {
  const chart = charts[key];
  if (!chart) return '';
  const labels = chart.data.labels || [];
  const sets = chart.data.datasets || [];
  const heads = ['', ...sets.map(d => d.label || 'value')];
  return `<table class="data-tbl twin">
    <caption class="visually-hidden">${esc(key)} data</caption>
    <thead><tr>${heads.map(h =>
      `<th scope="col">${esc(h)}</th>`).join('')}</tr></thead>
    <tbody>${labels.map((label, i) => `<tr>
      <td>${esc(label)}</td>
      ${sets.map(d => `<td class="num">${esc(fmtInt(d.data[i]))}</td>`).join('')}
    </tr>`).join('')}</tbody>
  </table>`;
}

function toggleTwin(panel, on) {
  const body = panel.querySelector('.panel-body');
  const host = panel.querySelector('.twin-host');
  body.hidden = on;
  host.hidden = !on;
  host.innerHTML = on ? chartsInPanel(panel).map(twinTable).join('') : '';
  panel.querySelector('.twin-toggle').setAttribute('aria-pressed', String(on));
  panel.querySelector('.twin-toggle').textContent = on ? 'Chart' : 'Table';
}

function installTwins() {
  document.querySelectorAll('.panel').forEach(panel => {
    if (!panel.querySelector('canvas[id^="chart-"]')) return;
    if (panel.querySelector('.twin-toggle')) return;
    const header = panel.querySelector('.panel-header');
    if (!header) return;
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'twin-toggle';
    button.textContent = 'Table';
    button.setAttribute('aria-pressed', 'false');
    button.setAttribute('aria-label', 'Show this chart as a table');
    header.appendChild(button);
    const host = document.createElement('div');
    host.className = 'twin-host';
    host.hidden = true;
    panel.appendChild(host);
    button.addEventListener('click', () =>
      toggleTwin(panel, button.getAttribute('aria-pressed') !== 'true'));
  });
}

/* ══════════════ Global investigation search ══════════════
   One field for every entity the API can resolve. Two kinds of result, and
   the panel labels which is which:

     * Looked up directly — the address, alert id or technique id was sent to
       its endpoint and this is the API's answer. A 404 is reported as "not
       observed", which is a finding, not an empty result.
     * Catalog match — matched against a complete catalog the console has
       already fetched (/api/mitre/techniques, /api/threats/types,
       /api/protocols each return everything, so this is not a sample).

   Nothing is ever rendered that did not come from the API. Hostnames are
   refused outright because no hostname exists anywhere in the schema. */

const RE_IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const RE_IPV6 = /^[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}$/i;
const RE_TECHNIQUE = /^T\d{4}(\.\d{3})?$/i;
const RE_DIGITS = /^\d+$/;
const RE_HOSTNAME = /^(?=.*[a-z])[a-z0-9-]+(\.[a-z0-9-]+)+$/i;
const SEARCH_GROUP_MAX = 6;

const catalogs = { techniques: null, detectors: null, protocols: null };

async function ensureCatalogs() {
  if (!catalogs.techniques) {
    const [techniques, detectors, protocols] = await Promise.all([
      api('/api/mitre/techniques'),
      api('/api/threats/types'),
      api('/api/protocols'),
    ]);
    catalogs.techniques = techniques;
    catalogs.detectors = detectors;
    catalogs.protocols = protocols;
  }
  return catalogs;
}

function isIpv4(value) {
  const m = RE_IPV4.exec(value);
  return Boolean(m) && m.slice(1).every(o => Number(o) <= 255);
}
const isAddress = v => isIpv4(v) || (v.includes(':') && RE_IPV6.test(v));

const searchInput = document.getElementById('q');
const searchPanel = document.getElementById('search-results');
let searchSeq = 0;
let searchTimer = null;
let searchCursor = -1;

function focusSearch() {
  searchInput.focus();
  searchInput.select();
}

function hideSearch() {
  searchPanel.hidden = true;
  searchPanel.innerHTML = '';
  searchInput.setAttribute('aria-expanded', 'false');
  searchCursor = -1;
}

/* Direct lookups run against the endpoints that own each entity, so a hit is
   the API's own record and a miss is an explicit statement of absence. */
async function directResults(query) {
  const sections = [];
  const notes = [];
  const jobs = [];

  if (RE_DIGITS.test(query)) {
    jobs.push(api('/api/alerts/' + encodeURIComponent(query)).then(a => {
      sections.push({ rank: 0, group: 'Alert', scope: 'Looked up directly', items: [{
        kind: 'alert', value: String(a.id),
        primary: '#' + a.id + '  ' + a.threat_type,
        secondary: (a.src_ip || '—') + ' → ' + (a.dst_ip || '—'),
        trailing: a.severity,
      }] });
    }).catch(() => {
      notes.push('No alert with id <strong>' + esc(query) + '</strong> exists.');
    }));
  }

  if (isAddress(query)) {
    jobs.push(api('/api/hosts/' + encodeURIComponent(query)).then(h => {
      sections.push({ rank: 1, group: 'Host', scope: 'Looked up directly', items: [
        { kind: 'host', value: h.ip,
          primary: h.ip,
          secondary: (h.is_internal ? 'internal' : 'external') + ' · '
            + fmtInt(h.packets_sent) + ' sent · ' + fmtInt(h.packets_recv) + ' received',
          trailing: h.alert_count ? fmtInt(h.alert_count) + ' alerts' : 'no alerts' },
        { kind: 'host-alerts', value: h.ip,
          primary: 'Alerts from ' + h.ip,
          secondary: 'Filter the queue to this source',
          trailing: 'queue' },
      ] });
    }).catch(() => {
      notes.push('<strong>' + esc(query) + '</strong> has not been observed by '
        + 'this sensor. Addresses only appear once a frame carries them.');
    }));
  }

  await Promise.all(jobs);
  return { sections: sections, notes: notes };
}

/* Catalog matches. All three catalogs are returned whole by their endpoints,
   so these results are complete rather than a slice of loaded data. */
function catalogResults(query) {
  const lower = query.toLowerCase();
  const sections = [];
  const hit = value => String(value || '').toLowerCase().includes(lower);

  const exact = t => t.technique_id.toLowerCase() === lower;
  const techniques = (catalogs.techniques || [])
    .filter(t => hit(t.technique_id) || hit(t.name) || hit(t.tactic))
    .sort((a, b) => (exact(b) ? 1 : 0) - (exact(a) ? 1 : 0));
  if (techniques.length) {
    sections.push({ rank: 3, group: 'ATT&CK technique',
      scope: 'Catalog match · all ' + catalogs.techniques.length + ' mapped techniques',
      items: techniques.slice(0, SEARCH_GROUP_MAX).map(t => ({
        kind: 'technique', value: t.technique_id,
        primary: t.technique_id + '  ' + t.name,
        secondary: t.tactic,
        trailing: t.alert_count ? fmtInt(t.alert_count) + ' alerts' : 'none seen',
      })),
      more: Math.max(0, techniques.length - SEARCH_GROUP_MAX) });
  }

  const detectors = (catalogs.detectors || []).filter(
    d => hit(d.threat_type) || hit(d.name) || hit(d.description));
  if (detectors.length) {
    sections.push({ rank: 4, group: 'Detector',
      scope: 'Catalog match · all ' + catalogs.detectors.length + ' detectors',
      items: detectors.slice(0, SEARCH_GROUP_MAX).map(d => ({
        kind: 'detector', value: d.threat_type,
        primary: d.threat_type,
        secondary: d.name,
        trailing: d.alert_count ? fmtInt(d.alert_count) + ' alerts' : 'none seen',
      })),
      more: Math.max(0, detectors.length - SEARCH_GROUP_MAX) });
  }

  const protocols = (catalogs.protocols || []).filter(x => hit(x.protocol));
  if (protocols.length) {
    sections.push({ rank: 5, group: 'Protocol',
      scope: 'Catalog match · all ' + catalogs.protocols.length + ' supported protocols',
      items: protocols.slice(0, SEARCH_GROUP_MAX).map(x => ({
        kind: 'protocol', value: x.protocol,
        primary: x.protocol,
        secondary: x.risk.toLowerCase() + ' risk · '
          + (x.encrypted ? 'encrypted' : 'cleartext'),
        trailing: x.packets_parsed ? fmtInt(x.packets_parsed) + ' parsed' : 'none parsed',
      })),
      more: Math.max(0, protocols.length - SEARCH_GROUP_MAX) });
  }

  return sections;
}

async function runSearch(raw) {
  const query = raw.trim();
  const seq = ++searchSeq;
  if (!query) { hideSearch(); return; }

  try { await ensureCatalogs(); } catch (e) { /* direct lookups still work */ }
  if (seq !== searchSeq) return;

  const direct = await directResults(query);
  if (seq !== searchSeq) return;

  const sections = direct.sections.concat(catalogResults(query))
    .sort((x, y) => x.rank - y.rank);
  const notes = direct.notes.slice();

  if (RE_TECHNIQUE.test(query)
      && !sections.some(section => section.group === 'ATT&CK technique')) {
    notes.push('<strong>' + esc(query.toUpperCase()) + '</strong> is not one of '
      + 'the ' + ((catalogs.techniques || []).length) + ' techniques NetWatch '
      + 'maps. Only techniques a detector can raise are catalogued.');
  }

  /* There is no hostname anywhere in the schema, so a hostname cannot
     silently return nothing — say why. */
  if (RE_HOSTNAME.test(query) && !isAddress(query)) {
    notes.push('NetWatch stores addresses, not hostnames: there is no DNS or '
      + 'PTR enrichment in this schema, so <strong>' + esc(query)
      + '</strong> cannot be resolved. Search the address instead.');
  }
  renderSearch(sections, notes, query);
}

function renderSearch(sections, notes, query) {
  let html = sections.map(section => `
    <div class="search-group" role="group" aria-label="${esc(section.group)}">
      <div class="search-group-head">
        <span>${esc(section.group)}</span>
        <span class="search-scope">${esc(section.scope)}</span>
      </div>
      ${section.items.map(item => `
        <button type="button" class="search-opt" role="option" aria-selected="false"
                data-kind="${esc(item.kind)}" data-value="${esc(item.value)}">
          <span class="primary">${esc(item.primary)}</span>
          <span class="secondary">${esc(item.secondary || '')}</span>
          ${item.trailing ? `<span class="trailing">${esc(item.trailing)}</span>` : ''}
        </button>`).join('')}
      ${section.more ? `<div class="search-note">${section.more} more match
        &ldquo;${esc(query)}&rdquo;. Narrow the term to see them.</div>` : ''}
    </div>`).join('');

  if (notes.length) {
    html += `<div class="search-group">${notes.map(
      text => `<div class="search-note">${text}</div>`).join('')}</div>`;
  }
  if (!html) {
    html = `<div class="search-note">Nothing in the API matches
      <strong>${esc(query)}</strong>. Searchable: address, alert id,
      ATT&amp;CK technique id or name, detector, protocol.</div>`;
  }
  searchPanel.innerHTML = html;
  searchPanel.hidden = false;
  searchInput.setAttribute('aria-expanded', 'true');
  searchCursor = -1;
}

function searchOptions() {
  return Array.from(searchPanel.querySelectorAll('.search-opt'));
}

function moveSearchCursor(step) {
  const options = searchOptions();
  if (!options.length) return;
  searchCursor = (searchCursor + step + options.length) % options.length;
  options.forEach((el, i) => {
    const on = i === searchCursor;
    el.classList.toggle('active', on);
    el.setAttribute('aria-selected', String(on));
    if (on) el.scrollIntoView({ block: 'nearest' });
  });
}

/* A result either opens the drawer for that entity or applies the filter that
   scopes a module to it. Both are pivots; neither invents data. */
function chooseSearchResult(kind, value) {
  hideSearch();
  searchInput.blur();
  if (kind === 'alert') { openAlert(Number(value)); return; }
  if (kind === 'host') { openHost(value); return; }
  if (kind === 'technique') { openTechnique(value); return; }
  if (kind === 'host-alerts') {
    document.getElementById('alert-ip-filter').value = value;
    alertFilters.src_ip = value;
    showView('alerts', { focus: true });
    announce('Queue filtered to source ' + value);
    return;
  }
  if (kind === 'detector') {
    document.getElementById('alert-detector').value = value;
    alertFilters.threat_type = value;
    showView('alerts', { focus: true });
    announce('Queue filtered to detector ' + value);
    return;
  }
  if (kind === 'protocol') {
    document.getElementById('pkt-proto-filter').value = value;
    pktFilters.protocol = value;
    resetStream();
    showView('packets', { focus: true });
    announce('Packet log filtered to ' + value);
  }
}

searchPanel.addEventListener('click', event => {
  const option = event.target.closest('.search-opt');
  if (option) chooseSearchResult(option.dataset.kind, option.dataset.value);
});

searchInput.addEventListener('input', event => {
  window.clearTimeout(searchTimer);
  const value = event.target.value;
  searchTimer = window.setTimeout(() => runSearch(value), 200);
});

searchInput.addEventListener('keydown', event => {
  if (event.key === 'ArrowDown') { event.preventDefault(); moveSearchCursor(1); }
  else if (event.key === 'ArrowUp') { event.preventDefault(); moveSearchCursor(-1); }
  else if (event.key === 'Escape') { hideSearch(); searchInput.blur(); }
  else if (event.key === 'Enter') {
    event.preventDefault();
    const option = searchOptions()[searchCursor] || searchOptions()[0];
    if (option) chooseSearchResult(option.dataset.kind, option.dataset.value);
  }
});

searchInput.addEventListener('focus', () => {
  if (searchInput.value.trim()) runSearch(searchInput.value);
});

document.addEventListener('click', event => {
  if (!event.target.closest('.search-wrap')) hideSearch();
});

/* ══════════════ Shell state ══════════════
   One poll feeds the status rail, the live indicator and the engine facts,
   so the posture figures are the same numbers on every view. */
function loadShell() {
  shellOnce = fetchShell();
  return shellOnce;
}

async function fetchShell() {
  let stats = null;
  try {
    const [overview, health, perf] = await Promise.all([
      api('/api/stats/overview'),
      api('/api/health'),
      api('/api/performance', { limit: 1 }),
    ]);
    stats = overview;

    setValue('rail-open', fmtInt(overview.unacknowledged));
    setText('rail-open-sub', fmtInt(overview.alerts_24h) + ' raised in 24 h');
    setValue('rail-crit', fmtInt(overview.critical_open));
    setText('rail-crit-sub', overview.critical_open ? 'needs triage' : 'none open');
    document.getElementById('rail-crit').classList
      .toggle('crit', overview.critical_open > 0);
    setValue('rail-ppm', fmtInt(overview.packets_per_min));
    setValue('rail-tech', fmtInt(overview.techniques_observed));
    setText('rail-tech-sub', 'of ' + health.engine.techniques + ' catalogued');

    const latest = (perf.history && perf.history[0]) || null;
    setValue('rail-p95', latest ? latest.query_p95_ms.toFixed(1) : '—');

    setText('nav-alert-badge', fmtInt(overview.unacknowledged));
    setText('side-detectors', health.engine.detectors);
    setText('side-protocols', health.engine.protocols_supported);
    setText('side-techniques', health.engine.techniques);
    setText('side-tables', health.table_count);

    setEngineStatus(health.simulation_running ? 'live' : 'idle');
    document.body.classList.toggle('demo', Boolean(health.demo));
    isDemo = Boolean(health.demo);
  } catch (e) {
    setEngineStatus('offline');
  }
  return stats;
}

/* /api/health.simulation_running says whether the frames being analysed came
   from the built-in generator. That is a fact about the data on screen, so it
   is stated plainly instead of being left for the reader to assume. */
function setEngineStatus(state) {
  engineState = state;
  const dot = document.getElementById('engine-dot');
  const label = {
    live: 'Simulated traffic',
    idle: 'Sensor idle',
    offline: 'API unreachable',
  };
  const detail = {
    live: 'Frames are generated by the built-in simulator and analysed by the '
      + 'real detection pipeline',
    idle: 'No capture is running, so no new frames are being analysed',
    offline: 'The dashboard cannot reach /api/health',
  };
  setText('engine-status', label[state] || label.offline);
  const pill = document.getElementById('sensor-pill');
  if (pill) pill.title = detail[state] || detail.offline;
  dot.classList.toggle('red', state === 'offline');
  dot.classList.toggle('muted', state === 'idle');
}

/* The header says when the numbers on screen were last fetched, so a frozen
   console is visibly frozen rather than quietly wrong. */
function markRefreshed(ok) {
  setText('refresh-time', ok
    ? new Date().toLocaleTimeString('en-GB')
    : 'stale');
  const el = document.getElementById('refresh-state');
  if (el) el.classList.toggle('stale', !ok);
}

// Refresh whichever module is on screen; the others reload on navigation.
setInterval(() => {
  if (currentView === 'alerts') queue.merge = true;
  runLoader(currentView);
}, REFRESH_MS);
setInterval(() => { loadShell(); }, SHELL_REFRESH_MS);

applyTheme(readPref('netwatch.theme', 'system'));
applyDensity(readPref('netwatch.density', 'comfortable'));
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  if (!document.documentElement.getAttribute('data-theme')) {
    applyTheme('system');
  }
});

booted = true;
installTwins();
fillProtocolFilter();
loadShell();
/* A link into a specific alert, host, technique or view wins over the
   default queue; otherwise the console opens where a shift starts. */
if (!route(window.location.hash)) { showView('alerts'); }
