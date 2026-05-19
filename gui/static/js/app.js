/* ═══════════════════════════════════════════════════════════════════════════
   ZEROBREACH V23 — KRAKEN CONSOLE FRONTEND JS
   Transport: native EventSource (SSE) + fetch — no Socket.IO dependency
   ═══════════════════════════════════════════════════════════════════════════ */

'use strict';

// ── State ────────────────────────────────────────────────────────────────────
const STATE = {
  sse: null,
  currentView: 'launchpad',
  scanMode: 'FULL',
  scanHours: 0,
  scanning: false,
  scanComplete: false,
  findings: [],
  threatCounts: {},
  selectedFindings: new Set(),
  mspBuffer: '',
  mspMode: false,
  logFilter: 'ALL',
  autoScroll: true,
  logLines: [],
  totalThreats: 0,
  elapsedSec: 0,
  currentPhase: 0,
  totalPhases: 107,
};

// ── DOM Helpers ───────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const $$ = sel => document.querySelectorAll(sel);

// ── Boot Sequence ─────────────────────────────────────────────────────────────
const BOOT_MESSAGES = [
  'LOADING THREAT INTELLIGENCE DATABASE...',
  'INITIALIZING IOC ENGINE...',
  'CALIBRATING FORENSIC MODULES...',
  'ESTABLISHING SECURE BRIDGE...',
  'ARMING PHASE SCANNER...',
  'SYSTEM READY.',
];

function runBoot() {
  const bar = $('boot-bar');
  const status = $('boot-status');
  let progress = 0;
  let msgIdx = 0;

  const interval = setInterval(() => {
    progress += Math.random() * 18 + 5;
    if (progress > 100) progress = 100;
    bar.style.width = progress + '%';

    if (msgIdx < BOOT_MESSAGES.length) {
      status.textContent = BOOT_MESSAGES[Math.floor((progress / 100) * BOOT_MESSAGES.length)] || BOOT_MESSAGES[msgIdx];
      msgIdx++;
    }

    if (progress >= 100) {
      clearInterval(interval);
      setTimeout(finishBoot, 400);
    }
  }, 120);
}

function finishBoot() {
  const overlay = $('boot-overlay');
  overlay.style.transition = 'opacity 0.6s ease';
  overlay.style.opacity = '0';
  setTimeout(() => {
    overlay.remove();
    $('app').classList.remove('hidden');
    if (window.gsap) gsap.from('#app', { opacity: 0, duration: 0.4 });
    initApp();
  }, 600);
}

// ── App Init ──────────────────────────────────────────────────────────────────
function initApp() {
  initSSE();
  initClock();
  initNav();
  initLaunchPad();
  initScanMonitor();
  initFindingsView();
  initMspListener();
  loadSysInfo();
  initParticles();
  startVitalsPoller();
}

// ── Server-Sent Events ────────────────────────────────────────────────────────
function initSSE() {
  STATE.sse = new EventSource('/api/events');

  STATE.sse.onopen = () => setConnected(true);

  STATE.sse.onerror = () => {
    setConnected(false);
    // EventSource auto-reconnects; no manual retry needed
  };

  STATE.sse.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      dispatchEvent(data);
    } catch (err) {
      // ignore parse errors on keepalive comments
    }
  };
}

function dispatchEvent(data) {
  switch (data.type) {
    case 'sync':
      handleSync(data);
      break;
    case 'log_line':
      appendLogLine(data);
      break;
    case 'finding':
      STATE.findings.push(data);
      STATE.totalThreats++;
      updateThreatChip(data.threat_type);
      addIntelItem(data);
      updateBadge();
      break;
    case 'scan_state':
      STATE.currentPhase    = data.phase;
      STATE.totalPhases     = data.phase_total;
      STATE.elapsedSec      = data.elapsed;
      STATE.threatCounts    = data.threat_counts || {};
      updateMonitorUI(data);
      updateTallyBars(data.threat_counts);
      updateStatusBar();
      break;
    case 'scan_complete':
      STATE.scanning     = false;
      STATE.scanComplete = true;
      if (data.threat_counts) STATE.threatCounts = data.threat_counts;
      onScanComplete(data);
      break;
  }
}

function handleSync(data) {
  // Called once on SSE connect to restore state after page reload mid-scan
  STATE.currentPhase = data.phase || 0;
  STATE.totalPhases  = data.phase_total || 107;
  STATE.elapsedSec   = data.elapsed || 0;
  STATE.threatCounts = data.threat_counts || {};
  if (data.running) {
    STATE.scanning = true;
    $('btn-abort').disabled = false;
    $('sb-status').textContent = '● SCANNING';
    $('sb-status').style.color = 'var(--threat-high)';
  }
  if (data.scan_complete && !data.running) {
    STATE.scanComplete = true;
    $('nav-remediation').classList.add('unlocked');
    $('nav-remediation').querySelector('.nav-lock-icon').textContent = '🔓';
  }
  updateTallyBars(data.threat_counts);
  updateStatusBar();
}

function setConnected(connected) {
  const dot   = $('connDot');
  const label = $('connLabel');
  dot.classList.toggle('online', connected);
  label.textContent = connected ? 'ONLINE' : 'OFFLINE';
}

// ── Clock ─────────────────────────────────────────────────────────────────────
function initClock() {
  const el = $('live-clock');
  function tick() {
    const now = new Date();
    el.textContent = now.toLocaleTimeString('en-US', { hour12: false });
  }
  tick();
  setInterval(tick, 1000);
}

// ── Navigation ────────────────────────────────────────────────────────────────
function initNav() {
  $$('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
      const view = item.dataset.view;
      if (item.classList.contains('nav-locked') && !item.classList.contains('unlocked')) return;
      switchView(view);
    });
  });
}

function switchView(viewId) {
  $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === viewId));
  $$('.view').forEach(v => v.classList.toggle('active', v.id === `view-${viewId}`));
  STATE.currentView = viewId;

  if (viewId === 'report')      buildReport();
  if (viewId === 'findings')    renderFindingsTree();
  if (viewId === 'remediation') renderRemediationView();
}

// ── Launch Pad ────────────────────────────────────────────────────────────────
function initLaunchPad() {
  $$('.mode-tile').forEach(tile => {
    tile.addEventListener('click', () => {
      $$('.mode-tile').forEach(t => t.classList.remove('active'));
      tile.classList.add('active');
      STATE.scanMode = tile.dataset.mode;
    });
  });

  $$('.time-tile:not(.custom-tile)').forEach(tile => {
    tile.addEventListener('click', () => {
      $$('.time-tile').forEach(t => t.classList.remove('active'));
      tile.classList.add('active');
      STATE.scanHours = parseInt(tile.dataset.hours);
    });
  });

  $('custom-hours').addEventListener('focus', () => {
    $$('.time-tile').forEach(t => t.classList.remove('active'));
    document.querySelector('.custom-tile').classList.add('active');
  });
  $('custom-hours').addEventListener('input', () => {
    STATE.scanHours = parseInt($('custom-hours').value) || 0;
  });

  $('btn-initiate').addEventListener('click', startScan);

  document.querySelectorAll('.theme-swatch').forEach(sw => {
    sw.addEventListener('click', () => {
      document.querySelectorAll('.theme-swatch').forEach(s => s.classList.remove('active'));
      sw.classList.add('active');
      document.body.className = sw.dataset.theme !== 'cyan' ? `theme-${sw.dataset.theme}` : '';
    });
  });
}

function startScan() {
  if (STATE.scanning) return;

  const flash = $('scan-flash');
  flash.style.opacity = '0.15';
  setTimeout(() => flash.style.opacity = '0', 300);

  STATE.scanning     = true;
  STATE.scanComplete = false;
  STATE.findings     = [];
  STATE.totalThreats = 0;
  STATE.logLines     = [];
  STATE.currentPhase = 0;

  $('log-output').innerHTML = '';
  Object.keys(STATE.threatCounts).forEach(k => {
    STATE.threatCounts[k] = 0;
    const el = $(`cnt-${k}`);
    if (el) el.textContent = '0';
    const chip = $(`chip-${k}`);
    if (chip) chip.classList.remove('active');
  });
  $('intel-feed').innerHTML = '';

  const config = {
    mode:        STATE.scanMode,
    hours:       STATE.scanHours,
    html_report: $('opt-html').checked,
    paranoid:    $('opt-paranoid').checked,
    stealth:     $('opt-stealth').checked,
    ioc_file:    $('ioc-path').value.trim(),
    msp_mode:    STATE.mspMode,
  };

  $('si-mode').textContent   = STATE.scanMode;
  $('pill-mode').style.display = 'flex';
  $('btn-abort').disabled    = false;

  switchView('scanmonitor');

  fetch('/api/scan/start', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(config),
  }).catch(e => appendLogLine({ text: `[ERROR] Could not start scan: ${e}`, severity: 'CRITICAL', phase: 0 }));

  $('sb-status').textContent = '● SCANNING';
  $('sb-status').style.color = 'var(--threat-high)';
}

// ── Scan Monitor ──────────────────────────────────────────────────────────────
function initScanMonitor() {
  $('btn-abort').addEventListener('click', () => {
    fetch('/api/scan/abort', { method: 'POST' });
    STATE.scanning = false;
    $('btn-abort').disabled = true;
    $('sb-status').textContent = '● ABORTED';
    $('sb-status').style.color = 'var(--threat-critical)';
  });

  $('autoscroll').addEventListener('change', e => { STATE.autoScroll = e.target.checked; });

  $$('.log-filter').forEach(f => {
    f.addEventListener('click', () => {
      $$('.log-filter').forEach(x => x.classList.remove('active'));
      f.classList.add('active');
      STATE.logFilter = f.dataset.filter;
      rerenderLog();
    });
  });
}

function appendLogLine(data) {
  STATE.logLines.push(data);

  const visible = STATE.logFilter === 'ALL' || data.severity === STATE.logFilter;
  if (!visible) return;

  const el   = $('log-output');
  const line = document.createElement('div');
  line.className      = `log-line sev-${data.severity}`;
  line.dataset.sev    = data.severity;

  const timeStr = new Date().toLocaleTimeString('en-US', { hour12: false });
  line.innerHTML = `<span class="log-ts">${timeStr}</span><span class="log-text">${escapeHtml(data.text)}</span>`;
  el.appendChild(line);

  if (STATE.autoScroll) el.scrollTop = el.scrollHeight;
}

function rerenderLog() {
  $('log-output').innerHTML = '';
  STATE.logLines.forEach(d => appendLogLine(d));
}

function updateMonitorUI(data) {
  $('cur-phase').textContent   = data.phase;
  $('total-phase').textContent = data.phase_total;

  if (data.phase_name) {
    const nameEl = $('phase-name-display');
    if (nameEl.textContent !== data.phase_name) {
      if (window.gsap) {
        gsap.to(nameEl, { opacity: 0, x: -10, duration: 0.15, onComplete: () => {
          nameEl.textContent = data.phase_name;
          gsap.to(nameEl, { opacity: 1, x: 0, duration: 0.15 });
        }});
      } else {
        nameEl.textContent = data.phase_name;
      }
    }
  }
  if (data.section) $('section-display').textContent = data.section;

  const phasePct = data.phase_total > 0 ? Math.round((data.phase / data.phase_total) * 100) : 0;
  $('prog-overall').style.width  = phasePct + '%';
  $('prog-overall-pct').textContent = phasePct + '%';

  $('elapsed-display').textContent = formatTime(data.elapsed);
  $('sb-elapsed').textContent      = formatTime(data.elapsed);

  const total = Object.values(data.threat_counts || {}).reduce((a, b) => a + b, 0);
  $('total-threats-display').textContent = total;
  $('sb-threats').textContent = `🔴 ${total} Threats`;
}

function updateThreatChip(threatType) {
  if (!threatType) return;
  const cntEl  = $(`cnt-${threatType}`);
  const chipEl = $(`chip-${threatType}`);
  if (cntEl) {
    const newVal = (parseInt(cntEl.textContent) || 0) + 1;
    cntEl.textContent = newVal;
    cntEl.classList.remove('bump');
    void cntEl.offsetWidth;
    cntEl.classList.add('bump');
  }
  if (chipEl) chipEl.classList.add('active');
}

function updateTallyBars(counts) {
  if (!counts) return;
  const max = Math.max(...Object.values(counts), 1);
  Object.entries(counts).forEach(([k, v]) => {
    const bar = $(`tbar-${k}`);
    const num = $(`tnum-${k}`);
    if (bar) {
      bar.style.width = Math.round((v / max) * 100) + '%';
      bar.classList.toggle('active', v > 0);
    }
    if (num) num.textContent = v;
  });
}

function addIntelItem(finding) {
  const feed = $('intel-feed');
  const dot  = { CRITICAL: '🔴', HIGH: '🟠', POSSIBLE: '🟡' }[finding.severity] || '⚪';
  const item = document.createElement('div');
  item.className = 'intel-item';
  item.innerHTML = `<span class="intel-ts">${finding.timestamp || ''}</span><span class="intel-dot">${dot}</span><span class="intel-msg">${escapeHtml((finding.line || '').substring(0, 60))}</span>`;
  feed.insertBefore(item, feed.firstChild);
  while (feed.children.length > 30) feed.removeChild(feed.lastChild);
}

function updateStatusBar() {
  const pct = STATE.totalPhases > 0 ? (STATE.currentPhase / STATE.totalPhases) * 100 : 0;
  $('sb-progress').style.width  = pct + '%';
  $('sb-phase').textContent     = `Phase ${STATE.currentPhase}/${STATE.totalPhases}`;
}

function updateBadge() {
  const badge = $('findings-badge');
  const total = STATE.findings.length;
  badge.textContent   = total;
  badge.style.display = total > 0 ? 'inline' : 'none';
  $('nav-findings').classList.add('unlocked');
}

// ── Scan Complete ─────────────────────────────────────────────────────────────
function onScanComplete(data) {
  $('btn-abort').disabled    = true;
  $('sb-status').textContent = '● COMPLETE';
  $('sb-status').style.color = 'var(--threat-clean)';

  const navRem = $('nav-remediation');
  navRem.classList.add('unlocked');
  navRem.querySelector('.nav-lock-icon').textContent = '🔓';

  const total = Object.values(data.threat_counts || {}).reduce((a, b) => a + b, 0);
  $('modal-summary').innerHTML = `
    <div class="complete-stat"><span class="complete-stat-num">${data.findings_count}</span><span class="complete-stat-label">TOTAL FINDINGS</span></div>
    <div class="complete-stat"><span class="complete-stat-num" style="color:var(--threat-high)">${total}</span><span class="complete-stat-label">THREAT DETECTIONS</span></div>
    <div class="complete-stat"><span class="complete-stat-num" style="color:var(--threat-clean)">${formatTime(data.elapsed)}</span><span class="complete-stat-label">SCAN DURATION</span></div>
    <div style="margin-top:8px;font-size:10px;color:var(--text-dim)">Results saved: ${data.results_path || 'N/A'}</div>
  `;
  $('modal-complete').classList.remove('hidden');

  $('modal-btn-findings').onclick = () => { $('modal-complete').classList.add('hidden'); switchView('findings'); };
  $('modal-btn-report').onclick   = () => { $('modal-complete').classList.add('hidden'); switchView('report'); };
  $('modal-btn-close').onclick    = () => $('modal-complete').classList.add('hidden');
}

// ── Findings Tree ─────────────────────────────────────────────────────────────
function initFindingsView() {
  $('btn-select-all').addEventListener('click', () => {
    $$('#findings-tree input[type=checkbox]').forEach(cb => cb.checked = true);
    STATE.findings.forEach(f => STATE.selectedFindings.add(f.id));
    updateRemediationBtn();
  });

  $('btn-clear-all').addEventListener('click', () => {
    $$('#findings-tree input[type=checkbox]').forEach(cb => cb.checked = false);
    STATE.selectedFindings.clear();
    updateRemediationBtn();
  });

  $('btn-expand-all').addEventListener('click', () => {
    $$('.tree-group-header').forEach(h => h.classList.remove('collapsed'));
    $$('.tree-items').forEach(i => i.style.display = '');
  });

  $('btn-collapse-all').addEventListener('click', () => {
    $$('.tree-group-header').forEach(h => h.classList.add('collapsed'));
    $$('.tree-items').forEach(i => i.style.display = 'none');
  });

  $('btn-goto-remediation').addEventListener('click', () => switchView('remediation'));

  $('btn-export-findings').addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(STATE.findings, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = `zerobreach_findings_${Date.now()}.json`;
    a.click();
  });
}

function renderFindingsTree() {
  const container = $('findings-tree');
  container.innerHTML = '';

  const groups   = {};
  const counts   = { CRITICAL: 0, HIGH: 0, POSSIBLE: 0, CLEAN: 0 };

  STATE.findings.forEach(f => {
    const g = f.threat_type || 'Other';
    if (!groups[g]) groups[g] = [];
    groups[g].push(f);
    if (counts[f.severity] !== undefined) counts[f.severity]++;
  });

  Object.entries(counts).forEach(([k, v]) => {
    const el = $(`count-${k.toLowerCase()}`);
    if (el) el.textContent = v;
  });

  if (Object.keys(groups).length === 0) {
    container.innerHTML = '<div style="padding:20px;color:var(--text-dim);font-size:11px;text-align:center">NO FINDINGS — RUN A SCAN FIRST</div>';
    return;
  }

  Object.entries(groups).forEach(([groupName, items]) => {
    const groupEl = document.createElement('div');
    groupEl.className = 'tree-group';

    const maxSev = items.some(i => i.severity === 'CRITICAL') ? 'CRITICAL' :
                   items.some(i => i.severity === 'HIGH')     ? 'HIGH'     :
                   items.some(i => i.severity === 'POSSIBLE') ? 'POSSIBLE' : 'CLEAN';

    const sevDot = { CRITICAL: '🔴', HIGH: '🟠', POSSIBLE: '🟡', CLEAN: '🟢' }[maxSev] || '⚪';

    groupEl.innerHTML = `
      <div class="tree-group-header">
        <span class="tree-toggle">▼</span>
        <span>${sevDot} ${groupName.toUpperCase()}</span>
        <span class="tree-group-count">${items.length}</span>
      </div>
      <div class="tree-items"></div>
    `;

    const header  = groupEl.querySelector('.tree-group-header');
    const itemsEl = groupEl.querySelector('.tree-items');

    header.addEventListener('click', () => {
      header.classList.toggle('collapsed');
      itemsEl.style.display = itemsEl.style.display === 'none' ? '' : 'none';
    });

    items.forEach(finding => {
      const item      = document.createElement('div');
      item.className  = 'tree-item';
      const shortText = (finding.line || '').substring(0, 120);
      const autoCheck = finding.severity === 'CRITICAL' || finding.severity === 'HIGH';
      item.innerHTML = `
        <input type="checkbox" data-id="${finding.id}" ${autoCheck ? 'checked' : ''}>
        <span class="item-sev ${finding.severity}"></span>
        <span class="item-text">${escapeHtml(shortText)}</span>
        <span class="item-phase">PH${finding.phase}</span>
      `;

      if (autoCheck) STATE.selectedFindings.add(finding.id);

      const cb = item.querySelector('input');
      cb.addEventListener('change', () => {
        if (!cb.checked && finding.severity === 'CRITICAL') {
          showWarnModal(
            `This finding is CRITICAL:\n\n"${shortText}"\n\nDeselecting will skip remediation.`,
            () => { STATE.selectedFindings.delete(finding.id); updateRemediationBtn(); },
            () => { cb.checked = true; }
          );
        } else {
          cb.checked ? STATE.selectedFindings.add(finding.id) : STATE.selectedFindings.delete(finding.id);
          updateRemediationBtn();
        }
      });

      itemsEl.appendChild(item);
    });

    container.appendChild(groupEl);
  });

  updateRemediationBtn();
}

function updateRemediationBtn() {
  $('btn-goto-remediation').disabled = STATE.selectedFindings.size === 0;
}

// ── Remediation ───────────────────────────────────────────────────────────────
function renderRemediationView() {
  const selected = STATE.findings.filter(f => STATE.selectedFindings.has(f.id));
  renderFindingsTreeMini(selected);

  const queue = $('action-queue');
  queue.innerHTML = '';

  selected.forEach(f => {
    const action = inferAction(f);
    const item   = document.createElement('div');
    item.className    = 'queue-item';
    item.dataset.id   = f.id;
    item.innerHTML = `
      <span class="queue-action">${action.label}</span>
      <span class="queue-target">${escapeHtml((f.line || '').substring(0, 80))}</span>
      <span class="queue-status">⏳</span>
    `;
    queue.appendChild(item);
  });

  $('queue-count').textContent = `${selected.length} actions pending`;
  $('btn-execute').disabled    = selected.length === 0;
  $('btn-execute').onclick     = () => executeRemediation(selected);
}

function renderFindingsTreeMini(findings) {
  const container  = $('remediation-tree');
  container.innerHTML = '';
  findings.forEach(f => {
    const item = document.createElement('div');
    item.className = 'tree-item';
    const dot  = { CRITICAL: '🔴', HIGH: '🟠', POSSIBLE: '🟡' }[f.severity] || '⚪';
    item.innerHTML = `<span class="item-sev ${f.severity}"></span><span class="item-text">${dot} ${escapeHtml((f.line || '').substring(0, 100))}</span>`;
    container.appendChild(item);
  });
}

function inferAction(finding) {
  const text = (finding.line || '').toLowerCase();
  if (text.includes('process') || text.includes('pid'))                          return { label: 'KILL PROCESS',    type: 'kill' };
  if (text.includes('registry') || text.includes('hkcu') || text.includes('hklm')) return { label: 'DELETE REG KEY', type: 'reg' };
  if (text.includes('.exe') || text.includes('.dll') || text.includes('file'))   return { label: 'QUARANTINE FILE', type: 'file' };
  if (text.includes('service'))                                                   return { label: 'DISABLE SERVICE', type: 'service' };
  if (text.includes('scheduled task'))                                            return { label: 'REMOVE TASK',     type: 'task' };
  return { label: 'FLAG / AUDIT', type: 'info' };
}

function executeRemediation(findings) {
  const items = $$('#action-queue .queue-item');
  let idx = 0;

  function processNext() {
    if (idx >= items.length) {
      $('btn-execute').textContent = '✓ REMEDIATION COMPLETE';
      $('sb-status').textContent   = '● REMEDIATED';
      $('sb-status').style.color   = 'var(--threat-clean)';
      return;
    }
    const item   = items[idx];
    const status = item.querySelector('.queue-status');
    status.textContent = '⏳';
    setTimeout(() => {
      status.textContent = '✓';
      item.style.opacity = '0.5';
      idx++;
      processNext();
    }, 300 + Math.random() * 400);
  }

  processNext();
}

// ── Report View ───────────────────────────────────────────────────────────────
function buildReport() {
  const counts    = STATE.threatCounts;
  const total     = Object.values(counts).reduce((a, b) => a + b, 0);
  const riskScore = Math.min(100, Math.round((total / Math.max(STATE.findings.length, 1)) * 60 + total * 2));

  drawRiskDial(riskScore);
  $('risk-score-label').textContent = riskScore;
  drawRadarChart(counts);

  const cardsEl = $('report-cards');
  cardsEl.innerHTML = '';
  STATE.findings.filter(f => f.severity === 'CRITICAL').slice(0, 6).forEach(f => {
    const card = document.createElement('div');
    card.className = 'report-card critical';
    card.innerHTML = `<div class="card-sev" style="color:var(--threat-critical)">🔴 CRITICAL — ${f.threat_type || 'Unknown'}</div><div class="card-text">${escapeHtml((f.line || '').substring(0, 100))}</div>`;
    cardsEl.appendChild(card);
  });
  if (!STATE.findings.some(f => f.severity === 'CRITICAL')) {
    cardsEl.innerHTML = '<div style="color:var(--threat-clean);font-size:11px;padding:12px">✓ NO CRITICAL FINDINGS</div>';
  }
}

function drawRiskDial(score) {
  const canvas = $('riskDial');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const cx = 100, cy = 110, r = 80;
  ctx.clearRect(0, 0, 200, 200);

  ctx.beginPath();
  ctx.arc(cx, cy, r, Math.PI, 2 * Math.PI);
  ctx.strokeStyle = 'rgba(255,255,255,0.06)';
  ctx.lineWidth   = 12;
  ctx.stroke();

  const color    = score > 70 ? '#FF0033' : score > 40 ? '#FF6600' : '#00D4FF';
  const endAngle = Math.PI + (score / 100) * Math.PI;
  ctx.beginPath();
  ctx.arc(cx, cy, r, Math.PI, endAngle);
  ctx.strokeStyle = color;
  ctx.lineWidth   = 12;
  ctx.lineCap     = 'round';
  ctx.shadowColor = color;
  ctx.shadowBlur  = 16;
  ctx.stroke();
  ctx.shadowBlur  = 0;
}

function drawRadarChart(counts) {
  const canvas = $('threatRadar');
  if (!canvas || !window.Chart) return;
  if (canvas._chart) canvas._chart.destroy();

  canvas._chart = new Chart(canvas, {
    type: 'radar',
    data: {
      labels:   Object.keys(counts),
      datasets: [{
        data:                Object.values(counts),
        backgroundColor:     'rgba(0,212,255,0.1)',
        borderColor:         'rgba(0,212,255,0.8)',
        pointBackgroundColor: 'var(--accent)',
        pointRadius:         3,
        borderWidth:         1.5,
      }]
    },
    options: {
      responsive: false,
      plugins: { legend: { display: false } },
      scales: {
        r: {
          grid:        { color: 'rgba(255,255,255,0.05)' },
          pointLabels: { color: 'rgba(200,232,248,0.6)', font: { size: 9, family: 'JetBrains Mono' } },
          ticks:       { display: false },
          angleLines:  { color: 'rgba(255,255,255,0.05)' },
        }
      }
    }
  });
}

// ── MSP Mode ──────────────────────────────────────────────────────────────────
function initMspListener() {
  const TRIGGERS = ['msp', 'gannon', 'staples'];
  document.addEventListener('keydown', (e) => {
    if (STATE.scanning) return;
    if (e.key.length === 1) {
      STATE.mspBuffer += e.key.toLowerCase();
      if (STATE.mspBuffer.length > 10) STATE.mspBuffer = STATE.mspBuffer.slice(-10);
      $('msp-input-display').textContent = STATE.mspBuffer + '_';
      if (!STATE.mspMode && TRIGGERS.find(w => STATE.mspBuffer.includes(w))) {
        activateMspMode();
      }
    }
  });
}

function activateMspMode() {
  STATE.mspMode = true;
  document.body.classList.add('theme-orange');
  $('msp-badge').classList.remove('hidden');

  const flash = $('scan-flash');
  flash.style.background = '#FF6B00';
  flash.style.opacity    = '0.12';
  setTimeout(() => { flash.style.opacity = '0'; flash.style.background = 'var(--accent)'; }, 400);

  addLogLine('[MSP MODE ACTIVATED] // GANNON ORANGE PROTOCOL ENGAGED', 'HUNT');
}

// ── Warning Modal ─────────────────────────────────────────────────────────────
function showWarnModal(message, onConfirm, onCancel) {
  $('modal-warn-text').textContent = message;
  $('modal-warn').classList.remove('hidden');
  $('modal-warn-confirm').onclick = () => { $('modal-warn').classList.add('hidden'); if (onConfirm) onConfirm(); };
  $('modal-warn-cancel').onclick  = () => { $('modal-warn').classList.add('hidden'); if (onCancel)  onCancel();  };
}

// ── System Info & Vitals ──────────────────────────────────────────────────────
function loadSysInfo() {
  fetch('/api/sysinfo').then(r => r.json()).then(d => {
    if (d.error) return;
    $('si-host').textContent = d.hostname || '—';
    $('si-user').textContent = d.username || '—';
    $('si-os').textContent   = d.os || '—';
    if (d.defender !== undefined) {
      $('vstat-defender').style.color = d.defender ? 'var(--threat-clean)' : 'var(--threat-critical)';
    }
  }).catch(() => {});
}

function startVitalsPoller() {
  function poll() {
    fetch('/api/sysinfo').then(r => r.json()).then(d => {
      if (d.error) return;
      const cpuPct = d.cpu    || 0;
      const ramPct = d.ram_used || 0;
      $('vbar-cpu').style.width  = cpuPct + '%';
      $('vpct-cpu').textContent  = Math.round(cpuPct) + '%';
      $('vbar-ram').style.width  = ramPct + '%';
      $('vpct-ram').textContent  = Math.round(ramPct) + '%';
      $('vbar-cpu').style.background = cpuPct > 80 ? 'var(--threat-critical)' : 'var(--accent)';
    }).catch(() => {});
  }
  poll();
  setInterval(poll, 5000);
}

// ── Particle Background ────────────────────────────────────────────────────────
function initParticles() {
  const canvas = document.createElement('canvas');
  canvas.id    = 'particle-canvas';
  document.body.insertBefore(canvas, document.body.firstChild);

  const ctx = canvas.getContext('2d');
  let particles = [];

  function resize() { canvas.width = window.innerWidth; canvas.height = window.innerHeight; }
  resize();
  window.addEventListener('resize', resize);

  for (let i = 0; i < 60; i++) {
    particles.push({
      x: Math.random() * canvas.width, y: Math.random() * canvas.height,
      r: Math.random() * 1.2 + 0.2,
      vx: (Math.random() - 0.5) * 0.3, vy: (Math.random() - 0.5) * 0.3,
      alpha: Math.random() * 0.5 + 0.1,
    });
  }

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    const accent = STATE.mspMode ? '255,107,0' : '0,212,255';
    particles.forEach(p => {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = canvas.width;  if (p.x > canvas.width)  p.x = 0;
      if (p.y < 0) p.y = canvas.height; if (p.y > canvas.height) p.y = 0;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${accent},${p.alpha})`;
      ctx.fill();
    });
    requestAnimationFrame(draw);
  }
  draw();
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function formatTime(seconds) {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
}

function addLogLine(text, severity = 'INFO') {
  appendLogLine({ text, severity, phase: STATE.currentPhase });
}

function exportReport(format) {
  if (format === 'json') {
    const blob = new Blob([JSON.stringify({ findings: STATE.findings, threatCounts: STATE.threatCounts }, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `zerobreach_report_${Date.now()}.json`;
    a.click();
  }
}

// ── Boot ──────────────────────────────────────────────────────────────────────
window.addEventListener('load', () => setTimeout(runBoot, 100));
