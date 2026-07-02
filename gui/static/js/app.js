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
  findingsAutoSelected: false,  // SAFETY: severity-based auto-select runs ONCE per report load;
                                // later re-renders seed checkboxes from selectedFindings so an
                                // operator's deselection can never silently re-arm (see renderFindingsTree).
  ioc: null,            // { hashes, ips, domains, regex, files, _path }
  iocTab: 'hashes',
  iocLoaded: false,
  engineReport: '',     // filename of the engine's rich report (drives real remediation)
  remediating: false,
  mspBuffer: '',
  mspMode: false,
  logFilter: 'ALL',
  autoScroll: true,
  logLines: [],
  totalThreats: 0,
  elapsedSec: 0,
  currentPhase: 0,
  totalPhases: 115,
  scanStartMs: 0,   // local clock origin (re-synced from server elapsed)
  lastEventMs: 0,   // last time any SSE event arrived (drives the "still working" heartbeat)
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
    try {
      initApp();
      window.__ZB_BOOTED = true;                       // tell the inline watchdog we made it
      try { sessionStorage.removeItem('zb_boot_retry'); } catch (e) {}
    } catch (err) {
      // initApp blew up (a sibling script lost the launch race, etc.). Rather than
      // leave a blank/grey console, self-heal with one immediate reload — capped via
      // the same sessionStorage key the inline watchdog uses so we never loop.
      console.error('[ZeroBreach] init failed:', err);
      let n = 0;
      try { n = parseInt(sessionStorage.getItem('zb_boot_retry') || '0', 10); } catch (e) {}
      if (n < 2) {
        try { sessionStorage.setItem('zb_boot_retry', String(n + 1)); } catch (e) {}
        location.reload();
      }
    }
  }, 600);
}

// ── App Init ──────────────────────────────────────────────────────────────────
function initApp() {
  ZBFX.init();
  ZBThemes.restore();
  // Initialize the per-view FX layer for the default (launchpad) view so the very
  // first paint already has its signature decoration. switchView() only runs on
  // navigation, and the launchpad is shown statically via class="view active".
  ensureViewFxLayer();
  ensureCineFxLayers();
  applyCineFx();
  document.body.dataset.view = 'launchpad';
  document.body.classList.toggle('fx-off', ZBFX.getIntensity() === 'off');
  initSSE();
  initClock();
  initNav();
  initLaunchPad();
  initScanMonitor();
  initFindingsView();
  initIocView();
  initMspListener();
  loadSysInfo();
  startVitalsPoller();
  initSettingsUI();
  initCmdPalette();
  initAudioUnlock();
  restoreGodBadge();
  ZBSound.play('boot');
}

// First user gesture unlocks the AudioContext (browser autoplay policy)
function initAudioUnlock() {
  const unlock = () => { ZBSound.unlock(); document.removeEventListener('pointerdown', unlock); document.removeEventListener('keydown', unlock); };
  document.addEventListener('pointerdown', unlock);
  document.addEventListener('keydown', unlock);
}

function restoreGodBadge() {
  if (ZBThemes.isGod() && !$('god-badge')) {
    const b = document.createElement('div');
    b.id = 'god-badge';
    b.textContent = '🐙 ABYSSAL';
    $('header-right').insertBefore(b, $('header-right').firstChild);
  }
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
      enqueueEvent(JSON.parse(e.data));
    } catch (err) {
      // ignore parse errors on keepalive comments
    }
  };
}

// ── Event pump ─────────────────────────────────────────────────────────────────
// SSE can deliver tens of thousands of events in a burst (a noisy phase). Dispatching
// each one synchronously inside onmessage saturates the main thread, which starves the
// requestAnimationFrame loop that drives the matrix rain / FX — the canvas freezes and
// the page eventually goes unresponsive. Instead we buffer events and drain a bounded
// number per animation frame, so the browser always gets to paint and run the FX.
const EV_QUEUE = [];
let evPumpScheduled = false;
const EV_MAX_PER_FRAME = 300;

function enqueueEvent(data) {
  EV_QUEUE.push(data);
  if (!evPumpScheduled) { evPumpScheduled = true; requestAnimationFrame(pumpEvents); }
}

function pumpEvents() {
  evPumpScheduled = false;
  const n = Math.min(EV_QUEUE.length, EV_MAX_PER_FRAME);
  for (let i = 0; i < n; i++) dispatchEvent(EV_QUEUE.shift());
  if (EV_QUEUE.length) { evPumpScheduled = true; requestAnimationFrame(pumpEvents); }
}

function dispatchEvent(data) {
  STATE.lastEventMs = Date.now();   // heartbeat: engine is producing output
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
      playFindingSound(data.severity);
      break;
    case 'scan_state':
      if (data.phase !== STATE.currentPhase) playThrottled('step', 400);
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
    case 'remediation_complete':
      onRemediationComplete(data);
      break;
  }
}

function handleSync(data) {
  // Called once on SSE connect to restore state after page reload mid-scan
  STATE.currentPhase = data.phase || 0;
  STATE.totalPhases  = data.phase_total || 115;
  STATE.elapsedSec   = data.elapsed || 0;
  STATE.threatCounts = data.threat_counts || {};
  if (data.running) {
    STATE.scanning = true;
    STATE.scanStartMs = Date.now() - (data.elapsed || 0) * 1000;
    STATE.lastEventMs = Date.now();
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

// throttled scan-event sounds so a noisy log doesn't become a noise machine
const SND_LAST = {};
function playThrottled(name, ms) {
  const now = Date.now();
  if (now - (SND_LAST[name] || 0) < ms) return;
  SND_LAST[name] = now;
  ZBSound.play(name);
}
function playFindingSound(sev) {
  if (sev === 'CRITICAL') playThrottled('alert', 2000);
  else playThrottled('tick', 300);
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
    updateHeartbeat();
  }
  tick();
  setInterval(tick, 1000);
}

// Advances the elapsed clock locally every second and shows whether the engine is
// actively emitting or just busy on a long phase — so the UI never *looks* frozen even
// when the engine goes silent for minutes (e.g. a heavy WMI/registry sweep).
function updateHeartbeat() {
  const dot = $('hb-dot'), txt = $('hb-text');
  if (!dot || !txt) return;

  if (!STATE.scanning) {
    dot.className = '';
    txt.textContent = STATE.scanComplete ? 'SCAN COMPLETE' : 'IDLE';
    return;
  }

  // Local elapsed keeps moving regardless of server traffic.
  const localElapsed = Math.max(0, Math.round((Date.now() - STATE.scanStartMs) / 1000));
  $('elapsed-display').textContent = formatTime(localElapsed);
  $('sb-elapsed').textContent      = formatTime(localElapsed);

  const silent = Math.round((Date.now() - STATE.lastEventMs) / 1000);
  if (silent < 4) {
    dot.className = 'hb-active';
    txt.style.color = '';
    txt.textContent = 'ENGINE ACTIVE';
  } else {
    dot.className = 'hb-busy';
    txt.style.color = 'var(--threat-high, #ffae42)';
    txt.textContent = `WORKING — ${silent}s since last update (heavy phase, not frozen)`;
  }
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
  // Per-view signature overlay: a single pointer-events-none layer whose look is
  // driven entirely by CSS keyed on body[data-view] (see fx.css "PER-VIEW TREATMENTS").
  ensureViewFxLayer();
  document.body.classList.toggle('fx-off', ZBFX.getIntensity() === 'off');
  document.body.dataset.view = viewId;
  ZBSound.play('tab');

  // scramble-decrypt the view title on entry
  const title = document.querySelector(`#view-${viewId} .view-title`);
  if (title) {
    if (!title.dataset.text) title.dataset.text = title.textContent;
    ZBFX.decrypt(title, title.dataset.text, 500);
  }

  if (viewId === 'report')      buildReport();
  if (viewId === 'findings')    renderFindingsTree();
  if (viewId === 'remediation') renderRemediationView();
  if (viewId === 'ioc')         renderIocTable();
}

// Build the per-view FX layer once. Two spans give CSS up to four decorative
// pseudo-elements (::before/::after on each) for richer per-view signatures.
function ensureViewFxLayer() {
  if (document.getElementById('view-fx')) return;
  const wrap = document.createElement('div');
  wrap.id = 'view-fx';
  wrap.setAttribute('aria-hidden', 'true');
  wrap.innerHTML = '<span class="vfx-a"></span><span class="vfx-b"></span>';
  document.body.appendChild(wrap);
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

  $$('.mode-tile, .time-tile').forEach(t => {
    t.addEventListener('click', () => ZBSound.play('click'));
    t.addEventListener('mouseenter', () => ZBSound.play('hover'));
  });
}

// ── Settings: theme grid, FX intensity, audio ────────────────────────────────
function initSettingsUI() {
  buildThemeGrid();
  buildFxTiers();
  buildCineFxToggles();
  initAudioControls();
  document.addEventListener('zb-god-unlocked', buildThemeGrid);
}

function buildThemeGrid() {
  const grid = $('theme-grid');
  if (!grid) return;
  grid.innerHTML = '';
  const cur = ZBThemes.current().id;
  ZBThemes.visible().forEach(t => {
    const card = document.createElement('div');
    card.className = 'theme-card' + (t.id === cur ? ' active' : '') + (t.secret ? ' secret' : '');
    card.style.setProperty('--c', t.vars['--accent']);
    card.innerHTML = `<div class="theme-card-name">${t.name}</div><div class="theme-card-tag">${t.tagline}</div>`;
    card.addEventListener('click', () => {
      ZBThemes.apply(t.id);
      ZBSound.play('confirm');
      $$('#theme-grid .theme-card').forEach(c => c.classList.remove('active'));
      card.classList.add('active');
    });
    card.addEventListener('mouseenter', () => ZBSound.play('hover'));
    grid.appendChild(card);
  });
}

function buildFxTiers() {
  const row = $('fx-tier-row');
  if (!row) return;
  row.innerHTML = '';
  Object.entries(ZBFX.INTENSITY).forEach(([id, tier]) => {
    const el = document.createElement('div');
    el.className = 'fx-tier' + (ZBFX.getIntensity() === id ? ' active' : '');
    el.textContent = tier.label;
    el.title = tier.desc;
    el.addEventListener('click', () => {
      ZBFX.setIntensity(id);
      document.body.classList.toggle('fx-off', id === 'off');
      ZBSound.play('click');
      $$('#fx-tier-row .fx-tier').forEach(t => t.classList.remove('active'));
      el.classList.add('active');
    });
    row.appendChild(el);
  });
}

// ── Cinematic FX toggles (independent, opt-in, theme-aware) ───────────────────
// Each effect layers OVER the theme system via a body.zbfx-<id> class; persisted
// as localStorage zb_cfx_<id>. Overlay-type effects (layer: 'bg'|'fg') render
// into #cine-fx-bg / #cine-fx-fg (built once by ensureCineFxLayers). Transform /
// filter effects (no layer) are driven straight off the body class in CSS. See
// fx.css "CINEMATIC FX TOGGLES". All default OFF — a clean console out of the box.
const CINE_FX = [
  { id: 'aurora',      label: 'Aurora Nebula',        layer: 'bg', el: 'ce-aurora',    desc: 'Drifting nebula glow behind the console' },
  { id: 'hologrid',    label: 'Holo Grid Floor',      layer: 'bg', el: 'ce-hologrid',  desc: 'Animated neon perspective grid along the bottom' },
  { id: 'scangrid',    label: 'Tactical Grid',        layer: 'bg', el: 'ce-scangrid',  desc: 'Full-screen pulsing tactical grid' },
  { id: 'spotlight',   label: 'Cursor Spotlight',     layer: 'fg', el: 'ce-spotlight', desc: 'Accent glow that tracks your cursor' },
  { id: 'vignette',    label: 'Cinematic Vignette',   layer: 'fg', el: 'ce-vignette',  desc: 'Dark cinematic edge falloff' },
  { id: 'grain',       label: 'Film Grain',           layer: 'fg', el: 'ce-grain',     desc: 'Animated 35mm film-grain noise' },
  { id: 'crt',         label: 'CRT Tube',             layer: 'fg', el: 'ce-crt',       desc: 'Heavy scanlines + tube curvature + flicker' },
  { id: 'scansweep',   label: 'Scan Sweep Bar',       desc: 'The sweeping bar on the Scan Monitor (off by default)' },
  { id: 'neonpulse',   label: 'Neon Border Pulse',    desc: 'Breathing accent glow on the panel borders' },
  { id: 'aberration',  label: 'Chromatic Aberration', desc: 'Constant RGB colour-split across the UI' },
  { id: 'glitch',      label: 'Glitch Bursts',        desc: 'Brief data-corruption slices every few seconds (GPU)' },
];

function cfxKey(id) { return 'zb_cfx_' + id; }
function cfxEnabled(id) { return localStorage.getItem(cfxKey(id)) === '1'; }

// Build the two persistent overlay containers (behind + above #app) once.
function ensureCineFxLayers() {
  if (document.getElementById('cine-fx-bg')) return;
  const bg = document.createElement('div'); bg.id = 'cine-fx-bg'; bg.setAttribute('aria-hidden', 'true');
  const fg = document.createElement('div'); fg.id = 'cine-fx-fg'; fg.setAttribute('aria-hidden', 'true');
  CINE_FX.forEach(fx => {
    if (!fx.layer) return;
    const d = document.createElement('div');
    d.className = fx.el;
    (fx.layer === 'bg' ? bg : fg).appendChild(d);
  });
  document.body.insertBefore(bg, document.body.firstChild); // behind #app (z-index:0)
  document.body.appendChild(fg);                            // above #app (z-index:9990)
  // Cursor spotlight: feed mouse position into CSS vars (cheap — no layout).
  window.addEventListener('pointermove', (e) => {
    if (!cfxEnabled('spotlight')) return;
    document.body.style.setProperty('--mx', e.clientX + 'px');
    document.body.style.setProperty('--my', e.clientY + 'px');
  }, { passive: true });
}

// Apply all saved toggles to <body> (called on boot).
function applyCineFx() {
  CINE_FX.forEach(fx => document.body.classList.toggle('zbfx-' + fx.id, cfxEnabled(fx.id)));
}

// Render the Settings → CINEMATIC FX checkbox grid.
function buildCineFxToggles() {
  const wrap = $('cine-fx-list');
  if (!wrap) return;
  wrap.innerHTML = '';
  CINE_FX.forEach(fx => {
    const label = document.createElement('label');
    label.className = 'opt-toggle cfx-toggle';
    label.title = fx.desc;
    label.innerHTML = `<input type="checkbox" data-cfx="${fx.id}"${cfxEnabled(fx.id) ? ' checked' : ''}> <span class="toggle-box"></span> ${fx.label}`;
    const cb = label.querySelector('input');
    cb.addEventListener('change', () => {
      localStorage.setItem(cfxKey(fx.id), cb.checked ? '1' : '0');
      document.body.classList.toggle('zbfx-' + fx.id, cb.checked);
      ZBSound.play(cb.checked ? 'confirm' : 'click');
    });
    wrap.appendChild(label);
  });
}

function initAudioControls() {
  const cb  = $('opt-sound');
  const vol = $('snd-vol');
  const lbl = $('snd-vol-label');
  if (!cb) return;
  cb.checked = !ZBSound.isMuted();
  vol.value  = Math.round(ZBSound.getVolume() * 100);
  lbl.textContent = vol.value + '%';
  cb.addEventListener('change', () => { ZBSound.setMuted(!cb.checked); if (cb.checked) ZBSound.play('on'); });
  vol.addEventListener('input', () => { ZBSound.setVolume(vol.value / 100); lbl.textContent = vol.value + '%'; ZBSound.play('tick'); });
}

// ── Command Palette (Ctrl+K) ─────────────────────────────────────────────────
function initCmdPalette() {
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); toggleCmdPalette(); }
    if (e.key === 'Escape' && $('cmd-palette')) closeCmdPalette();
  });
}

function cmdActions() {
  const acts = [
    { icon: '⚡', label: 'GO: LAUNCH PAD',     hint: 'view', fn: () => switchView('launchpad') },
    { icon: '🔍', label: 'GO: SCAN MONITOR',   hint: 'view', fn: () => switchView('scanmonitor') },
    { icon: '🌲', label: 'GO: FINDINGS',       hint: 'view', fn: () => switchView('findings') },
    { icon: '📊', label: 'GO: REPORT',         hint: 'view', fn: () => switchView('report') },
    { icon: '📁', label: 'GO: IOC MANAGER',    hint: 'view', fn: () => switchView('ioc') },
    { icon: '⚙', label: 'GO: SETTINGS',        hint: 'view', fn: () => switchView('settings') },
    { icon: '🚀', label: 'INITIATE SCAN',      hint: 'action', fn: () => startScan() },
    { icon: '■',  label: 'ABORT SCAN',         hint: 'action', fn: () => $('btn-abort').click() },
    { icon: '📋', label: 'EXPORT FINDINGS JSON', hint: 'action', fn: () => $('btn-export-findings').click() },
    { icon: '🔇', label: ZBSound.isMuted() ? 'UNMUTE SOUND' : 'MUTE SOUND', hint: 'audio', fn: () => { ZBSound.setMuted(!ZBSound.isMuted()); initAudioControls(); } },
  ];
  ZBThemes.visible().forEach(t => acts.push({ icon: '🎨', label: 'THEME: ' + t.name, hint: 'theme', fn: () => { ZBThemes.apply(t.id); buildThemeGrid(); } }));
  if (ZBThemes.isGod()) acts.push({ icon: '🐙', label: 'RELEASE THE KRAKEN (REPLAY)', hint: 'ritual', fn: () => ZBKraken.release() });
  return acts;
}

function toggleCmdPalette() {
  if ($('cmd-palette')) { closeCmdPalette(); return; }
  ZBSound.play('open');
  const wrap = document.createElement('div');
  wrap.id = 'cmd-palette';
  wrap.innerHTML = '<div id="cmd-box"><input id="cmd-input" placeholder="TYPE A COMMAND…" autocomplete="off"><div id="cmd-list"></div></div>';
  document.body.appendChild(wrap);
  wrap.addEventListener('pointerdown', (e) => { if (e.target === wrap) closeCmdPalette(); });

  const input = $('cmd-input'), list = $('cmd-list');
  let filtered = [], sel = 0;

  function render() {
    const q = input.value.trim().toUpperCase();
    filtered = cmdActions().filter(a => !q || a.label.toUpperCase().includes(q));
    sel = Math.min(sel, Math.max(0, filtered.length - 1));
    list.innerHTML = '';
    filtered.forEach((a, i) => {
      const el = document.createElement('div');
      el.className = 'cmd-item' + (i === sel ? ' sel' : '');
      el.innerHTML = `<span class="cmd-icon">${a.icon}</span><span>${a.label}</span><span class="cmd-hint">${a.hint}</span>`;
      el.addEventListener('click', () => { run(a); });
      list.appendChild(el);
    });
  }
  function run(a) { closeCmdPalette(); ZBSound.play('confirm'); a.fn(); }

  input.addEventListener('input', () => { sel = 0; render(); });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { sel = Math.min(sel + 1, filtered.length - 1); render(); e.preventDefault(); }
    if (e.key === 'ArrowUp')   { sel = Math.max(sel - 1, 0); render(); e.preventDefault(); }
    if (e.key === 'Enter' && filtered[sel]) run(filtered[sel]);
  });
  render();
  input.focus();
}

function closeCmdPalette() {
  const p = $('cmd-palette');
  if (p) { p.remove(); ZBSound.play('close'); }
}

function startScan() {
  if (STATE.scanning) return;
  ZBSound.play('deploy');

  const flash = $('scan-flash');
  flash.style.opacity = '0.15';
  setTimeout(() => flash.style.opacity = '0', 300);

  STATE.scanning     = true;
  STATE.scanComplete = false;
  STATE.findings     = [];
  STATE.totalThreats = 0;
  STATE.logLines     = [];
  STATE.currentPhase = 0;
  STATE.scanStartMs  = Date.now();
  STATE.lastEventMs  = Date.now();

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
  })
    .then(r => {
      if (!r.ok) return r.json().then(j => { throw new Error(j.error || r.status); });
    })
    .catch(e => {
      STATE.scanning = false;
      $('btn-abort').disabled = true;
      $('sb-status').textContent = '● ERROR';
      $('sb-status').style.color = 'var(--threat-critical)';
      appendLogLine({ text: `[ERROR] Could not start scan: ${e}`, severity: 'CRITICAL', phase: 0 });
    });

  $('sb-status').textContent = '● SCANNING';
  $('sb-status').style.color = 'var(--threat-high)';
}

// ── Scan Monitor ──────────────────────────────────────────────────────────────
function initScanMonitor() {
  $('btn-abort').addEventListener('click', () => {
    ZBSound.play('error');
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

const LOG_BUFFER_CAP = 2000;   // retained log records (caps memory + rerenderLog cost)
const LOG_DOM_CAP    = 800;    // live <div> nodes in #log-output (caps layout/paint cost)

function appendLogLine(data) {
  STATE.logLines.push(data);
  if (STATE.logLines.length > LOG_BUFFER_CAP) STATE.logLines.shift();

  const visible = STATE.logFilter === 'ALL' || data.severity === STATE.logFilter;
  if (!visible) return;

  const el   = $('log-output');
  const line = document.createElement('div');
  line.className      = `log-line sev-${data.severity}`;
  line.dataset.sev    = data.severity;

  const timeStr = new Date().toLocaleTimeString('en-US', { hour12: false });
  line.innerHTML = `<span class="log-ts">${timeStr}</span><span class="log-text">${escapeHtml(data.text)}</span>`;
  el.appendChild(line);
  // Trim oldest nodes so a long/noisy scan can't grow the DOM without bound.
  while (el.childElementCount > LOG_DOM_CAP) el.removeChild(el.firstChild);

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

  // Re-anchor the local clock to the server's authoritative elapsed (prevents drift).
  if (typeof data.elapsed === 'number') STATE.scanStartMs = Date.now() - data.elapsed * 1000;
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
  ZBSound.play('complete');
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
  ZBSound.play('open');
  // animate the headline numbers
  const nums = $('modal-summary').querySelectorAll('.complete-stat-num');
  if (nums[0]) ZBFX.countUp(nums[0], data.findings_count || 0, 900);
  if (nums[1]) ZBFX.countUp(nums[1], total, 900);

  $('modal-btn-findings').onclick = () => { $('modal-complete').classList.add('hidden'); switchView('findings'); };
  $('modal-btn-report').onclick   = () => { $('modal-complete').classList.add('hidden'); switchView('report'); };
  $('modal-btn-close').onclick    = () => $('modal-complete').classList.add('hidden');

  // Swap in the engine's rich findings (carry real FixAction + MITRE) so remediation
  // can actually act. Falls back silently to the live SSE findings if unavailable.
  if (data.engine_report) loadEngineFindings(data.engine_report);
}

// Replace the live SSE findings with the engine's authoritative report findings.
function loadEngineFindings(name) {
  fetch('/api/report?name=' + encodeURIComponent(name))
    .then(r => r.json())
    .then(list => {
      if (!Array.isArray(list)) return;
      // Keep the findings view focused on notable severities (matches the live view),
      // but each now carries fix_action/fix_param for real remediation.
      const notable = list.filter(f => ['CRITICAL', 'HIGH', 'POSSIBLE'].includes(f.severity));
      if (notable.length === 0) return;          // nothing actionable — keep SSE findings
      STATE.engineReport = name;
      STATE.findings = notable;
      STATE.selectedFindings.clear();
      STATE.findingsAutoSelected = false;   // fresh report → allow the one-time severity auto-select
      updateBadge();
      // Correct the completion modal: the live SSE count is ~0 in GUI mode (engine emits clean
      // output); the engine report is the real total. notable = actionable, list = all severities.
      updateCompleteModalCounts(list.length, notable.length);
      if (STATE.currentView === 'findings')   renderFindingsTree();
      if (STATE.currentView === 'report')     buildReport();
      if (STATE.currentView === 'remediation') renderRemediationView();
    })
    .catch(() => {});
}

// Update the "scan complete" modal headline numbers once the engine report has loaded.
function updateCompleteModalCounts(total, notable) {
  const modal = $('modal-complete');
  if (!modal || modal.classList.contains('hidden')) return;
  const nums = $('modal-summary').querySelectorAll('.complete-stat-num');
  if (nums[0]) ZBFX.countUp(nums[0], total, 700);
  if (nums[1]) ZBFX.countUp(nums[1], notable, 700);
}

function onRemediationComplete(data) {
  STATE.remediating = false;
  $$('#action-queue .queue-item .queue-status').forEach(s => { s.textContent = '✓'; });
  $$('#action-queue .queue-item').forEach(it => it.style.opacity = '0.6');
  const blocked = data.blocked || 0;
  const btn = $('btn-execute');
  if (btn) { btn.disabled = true; btn.textContent = `✓ APPLIED ${data.applied} · FAILED ${data.failed} · SKIPPED ${data.skipped}${blocked ? ' · 🛡 ' + blocked : ''}`; }
  $('sb-status').textContent = '● REMEDIATED';
  $('sb-status').style.color = 'var(--threat-clean)';
  let msg = `Remediation complete — ${data.applied} applied, ${data.failed} failed, ${data.skipped} skipped`;
  if (blocked) msg += `; 🛡 ${blocked} BLOCKED (protected system resources)`;
  showToast(msg);
  ZBSound.play('complete');
}

// ── Findings Tree ─────────────────────────────────────────────────────────────
function initFindingsView() {
  $('btn-select-all').addEventListener('click', () => {
    // SAFETY: "select all" never selects protected (disabled) or trusted-vendor findings.
    // (Trusted RMM tooling stays individually tickable, but bulk-select skips it.)
    const allowed = STATE.findings.filter(f => !f.protected && !f.vendor_trusted);
    STATE.selectedFindings = new Set(allowed.map(f => f.id));          // native id type (str|num)
    const allowedStr = new Set(allowed.map(f => String(f.id)));         // dataset.id is always a string
    $$('#findings-tree input[type=checkbox]').forEach(cb => { cb.checked = allowedStr.has(cb.dataset.id); });
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

  // SAFETY (B1): only the FIRST render after a report loads may auto-select by severity.
  // Every later render (e.g. switching back into the Findings view) must reflect the
  // operator's actual selection, or a deliberately-deselected destructive finding would
  // silently re-check and could fire on PURGE.
  const firstPass = !STATE.findingsAutoSelected;

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
      // SAFETY: protected (system-critical) findings can NEVER be selected/auto-selected.
      // Vendor-trusted (RMM partner tooling) is NOT auto-selected, but stays manually selectable.
      const autoEligible = (finding.severity === 'CRITICAL' || finding.severity === 'HIGH') && !finding.protected && !finding.vendor_trusted;
      // First render: auto-select eligible items. Re-renders: mirror the operator's live selection.
      const autoCheck = firstPass ? autoEligible : STATE.selectedFindings.has(finding.id);
      if (finding.protected) item.classList.add('protected');
      if (finding.vendor_trusted) item.classList.add('vendor-trusted');
      item.innerHTML = `
        <input type="checkbox" data-id="${finding.id}" ${autoCheck ? 'checked' : ''} ${finding.protected ? 'disabled' : ''}>
        <span class="item-sev ${finding.severity}"></span>
        <span class="item-text">${escapeHtml(shortText)}</span>
        ${protectedBadge(finding)}
        ${vendorBadge(finding)}
        ${mitreBadge(finding)}
        <span class="item-phase">PH${finding.phase}</span>
      `;

      if (firstPass && autoEligible) STATE.selectedFindings.add(finding.id);

      // MITRE badge opens the technique page without toggling the checkbox row.
      const mb = item.querySelector('.item-mitre');
      if (mb) mb.addEventListener('click', e => e.stopPropagation());

      const cb = item.querySelector('input');
      if (finding.protected) {
        // Hard stop in the UI: cannot be ticked at all (the server also refuses it).
        STATE.selectedFindings.delete(finding.id);
        itemsEl.appendChild(item);
        return;
      }
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

  STATE.findingsAutoSelected = true;   // one-time auto-select consumed; re-renders now mirror selection
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
  if (!STATE.remediating) {
    $('btn-execute').innerHTML = '<span class="initiate-icon">⚡</span><span class="initiate-text">EXECUTE REMEDIATION</span>';
  }
  $('btn-execute').disabled    = selected.length === 0 || STATE.remediating;
  $('btn-execute').onclick     = () => showDangerConfirm(
    'PURGE',
    `You are about to execute ${selected.length} remediation action(s) — kills, quarantines, and registry deletions are irreversible without the rollback snapshot.`,
    () => executeRemediation(selected)
  );
}

// ── Danger confirm: destructive actions require typing the confirm word ──────
function showDangerConfirm(word, message, onConfirm) {
  ZBSound.play('danger');
  const wrap = document.createElement('div');
  wrap.className = 'modal';
  wrap.id = 'modal-danger';
  wrap.innerHTML = `
    <div class="modal-box danger">
      <div class="modal-title">⚠ DESTRUCTIVE OPERATION</div>
      <div style="font-size:11px;color:var(--text);line-height:1.6">${escapeHtml(message)}</div>
      <div id="danger-word">${word}</div>
      <input id="danger-input" autocomplete="off" placeholder="TYPE THE WORD ABOVE">
      <div class="modal-actions">
        <button class="cyber-btn danger" id="danger-go" disabled>EXECUTE</button>
        <button class="cyber-btn" id="danger-cancel">CANCEL</button>
      </div>
    </div>`;
  document.body.appendChild(wrap);
  const input = wrap.querySelector('#danger-input');
  const go    = wrap.querySelector('#danger-go');
  input.addEventListener('input', () => {
    const ok = input.value.trim().toUpperCase() === word;
    go.disabled = !ok;
    if (ok) ZBSound.play('lock');
  });
  input.addEventListener('keydown', e => { if (e.key === 'Enter' && !go.disabled) go.click(); e.stopPropagation(); });
  go.onclick = () => { wrap.remove(); ZBSound.play('confirm'); onConfirm(); };
  wrap.querySelector('#danger-cancel').onclick = () => { wrap.remove(); ZBSound.play('close'); };
  input.focus();
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

// MITRE ATT&CK badge — links to the technique page; tagged server-side per finding.
function mitreBadge(finding) {
  const m = finding.mitre;
  if (!m || !m.id) return '';
  const title = escapeHtml(`${m.id} — ${m.name || ''}${m.tactic ? ' · ' + m.tactic : ''}`);
  const href  = m.url ? escapeHtml(m.url) : `https://attack.mitre.org/techniques/${m.id.replace('.', '/')}/`;
  return `<a class="item-mitre" href="${href}" target="_blank" rel="noopener" title="${title}">${escapeHtml(m.id)}</a>`;
}

// SAFETY badge — system-critical resource the tool will never remediate (cert store,
// Windows/system files, user dotfiles, SafeBoot/core registry, critical processes).
function protectedBadge(finding) {
  if (!finding.protected) return '';
  const title = escapeHtml(`PROTECTED — will not be remediated: ${finding.protected_reason || 'system-critical resource'}`);
  return `<span class="item-protected" title="${title}">🛡 PROTECTED</span>`;
}

// Trusted-vendor badge — legit RMM partner tooling (Datto/CentraStage/Kaseya). Not auto-selected,
// but still manually selectable so the operator can act if they judge it suspicious.
function vendorBadge(finding) {
  if (!finding.vendor_trusted) return '';
  const title = escapeHtml(`TRUSTED VENDOR — not auto-selected: ${finding.vendor_reason || 'RMM partner tooling'}`);
  return `<span class="item-vendor" title="${title}">✔ TRUSTED</span>`;
}

const FIX_ACTION_LABELS = {
  KillProcess:  'KILL PROCESS',
  DeleteFile:   'DELETE FILE',
  DeleteReg:    'DELETE REG VALUE',
  DeleteRegKey: 'DELETE REG KEY',
  Quarantine:   'QUARANTINE FILE',
  RunCmd:       'RUN FIX COMMAND',
  Info:         'FLAG / REVIEW',
  None:         'FLAG / REVIEW',
};

function inferAction(finding) {
  // Prefer the engine's authoritative FixAction when present (rich report findings).
  if (finding.fix_action) {
    return { label: FIX_ACTION_LABELS[finding.fix_action] || finding.fix_action.toUpperCase(), type: finding.fix_action };
  }
  // Heuristic fallback for live SSE findings (no engine report loaded).
  const text = (finding.line || '').toLowerCase();
  if (text.includes('process') || text.includes('pid'))                          return { label: 'KILL PROCESS',    type: 'kill' };
  if (text.includes('registry') || text.includes('hkcu') || text.includes('hklm')) return { label: 'DELETE REG KEY', type: 'reg' };
  if (text.includes('.exe') || text.includes('.dll') || text.includes('file'))   return { label: 'QUARANTINE FILE', type: 'file' };
  if (text.includes('service'))                                                   return { label: 'DISABLE SERVICE', type: 'service' };
  if (text.includes('scheduled task'))                                            return { label: 'REMOVE TASK',     type: 'task' };
  return { label: 'FLAG / AUDIT', type: 'info' };
}

function executeRemediation(findings) {
  // Real remediation requires the engine's rich report (carries FixAction/FixParam).
  if (!STATE.engineReport) {
    showToast('No engine report available — cannot remediate. Re-run the scan.');
    ZBSound.play('alert');
    return;
  }
  // SAFETY (belt-and-suspenders): never send protected findings — the server also refuses them.
  const ids = findings.filter(f => !f.protected).map(f => f.id);
  if (ids.length === 0) {
    showToast('Nothing to remediate — all selected items are protected system resources.');
    ZBSound.play('alert');
    return;
  }
  const btn = $('btn-execute');
  btn.disabled = true;
  btn.textContent = '⏳ REMEDIATING...';
  STATE.remediating = true;
  $$('#action-queue .queue-item .queue-status').forEach(s => { s.textContent = '⏳'; });

  fetch('/api/remediate', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ report: STATE.engineReport, ids }),
  })
    .then(r => r.json().then(j => { if (!r.ok || j.error) throw new Error(j.error || r.status); return j; }))
    .then(() => {
      // Live [FIX] lines stream into the scan-monitor log; completion arrives via SSE.
      showToast('Remediation started — watch the live log');
      $('sb-status').textContent = '● REMEDIATING';
      $('sb-status').style.color = 'var(--threat-high)';
    })
    .catch(e => {
      STATE.remediating = false;
      btn.disabled = false;
      btn.textContent = '⚠ EXECUTE REMEDIATION';
      showToast('Remediation failed to start: ' + e.message);
      ZBSound.play('alert');
    });
}

// ── IOC Manager ───────────────────────────────────────────────────────────────
const IOC_CATS = ['hashes', 'ips', 'domains', 'regex', 'files'];
const IOC_TAB_TO_CAT = { hashes: 'hashes', ips: 'ips', domains: 'domains', regex: 'regex', files: 'files' };

function emptyIoc() { return { hashes: [], ips: [], domains: [], regex: [], files: [], _path: '' }; }

function initIocView() {
  // Tabs
  $$('#view-ioc .ioc-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      $$('#view-ioc .ioc-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      STATE.iocTab = tab.dataset.tab;
      renderIocTable();
      ZBSound.play('tab');
    });
  });

  $('btn-ioc-add').addEventListener('click', addIocValue);
  $('ioc-add-val').addEventListener('keydown', e => { if (e.key === 'Enter') { addIocValue(); e.stopPropagation(); } });
  $('btn-ioc-import').addEventListener('click', () => $('ioc-file-input').click());
  $('ioc-file-input').addEventListener('change', importIocFile);
  $('btn-ioc-save').addEventListener('click', saveIoc);
}

function loadIoc() {
  return fetch('/api/ioc')
    .then(r => r.json())
    .then(data => {
      STATE.ioc = Object.assign(emptyIoc(), data);
      IOC_CATS.forEach(c => { if (!Array.isArray(STATE.ioc[c])) STATE.ioc[c] = STATE.ioc[c] ? [STATE.ioc[c]] : []; });
      STATE.iocLoaded = true;
    })
    .catch(() => { STATE.ioc = emptyIoc(); STATE.iocLoaded = true; });
}

function renderIocTable() {
  if (!STATE.iocLoaded) { loadIoc().then(renderIocTable); return; }
  const tbody = $('ioc-tbody');
  if (!tbody) return;
  const cat = IOC_TAB_TO_CAT[STATE.iocTab] || 'hashes';
  const list = STATE.ioc[cat] || [];
  tbody.innerHTML = '';
  if (list.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--text-dim);padding:14px">NO ${cat.toUpperCase()} — ADD ONE BELOW OR IMPORT A FILE</td></tr>`;
  } else {
    list.forEach((val, i) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${cat.slice(0, -1).toUpperCase()}</td><td class="ioc-val">${escapeHtml(String(val))}</td><td>${STATE.ioc._custom ? 'CUSTOM' : 'DEFAULT'}</td><td><button class="cyber-btn-sm ioc-del" data-i="${i}">✕</button></td>`;
      tr.querySelector('.ioc-del').addEventListener('click', () => { STATE.ioc[cat].splice(i, 1); renderIocTable(); ZBSound.play('click'); });
      tbody.appendChild(tr);
    });
  }
  const total = IOC_CATS.reduce((n, c) => n + (STATE.ioc[c] ? STATE.ioc[c].length : 0), 0);
  const st = $('ioc-status');
  if (st) st.textContent = `${total} indicators across ${IOC_CATS.length} categories` + (STATE.ioc._path ? ` · active file: ${STATE.ioc._path}` : ' · not yet saved');
}

function addIocValue() {
  const input = $('ioc-add-val');
  const val = input.value.trim();
  if (!val) return;
  const cat = IOC_TAB_TO_CAT[STATE.iocTab] || 'hashes';
  if (!STATE.ioc) STATE.ioc = emptyIoc();
  if (!STATE.ioc[cat].includes(val)) STATE.ioc[cat].push(val);
  input.value = '';
  renderIocTable();
  ZBSound.play('confirm');
}

// Accepts either our JSON shape or the engine's prefixed/bare text format.
function importIocFile(e) {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    const text = String(reader.result || '');
    if (!STATE.ioc) STATE.ioc = emptyIoc();
    let added = 0;
    const tryJson = () => { try { return JSON.parse(text); } catch { return null; } };
    const j = tryJson();
    if (j && typeof j === 'object') {
      IOC_CATS.forEach(c => {
        (Array.isArray(j[c]) ? j[c] : []).forEach(v => { v = String(v).trim(); if (v && !STATE.ioc[c].includes(v)) { STATE.ioc[c].push(v); added++; } });
      });
    } else {
      text.split(/\r?\n/).forEach(raw => {
        const line = raw.trim();
        if (!line || line.startsWith('#')) return;
        const m = line.match(/^(hash|md5|sha1|sha256|domain|host|ip|cidr|regex|pattern|file)\s*:\s*(.+)$/i);
        let cat, val;
        if (m) {
          val = m[2].trim();
          const k = m[1].toLowerCase();
          cat = (k === 'hash' || k === 'md5' || k === 'sha1' || k === 'sha256') ? 'hashes'
              : (k === 'domain' || k === 'host') ? 'domains'
              : (k === 'ip' || k === 'cidr') ? 'ips'
              : (k === 'regex' || k === 'pattern') ? 'regex' : 'files';
        } else {
          val = line;
          if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(line)) cat = 'hashes';
          else if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(line)) cat = 'ips';
          else if (/^[a-z0-9.\-]+\.[a-z]{2,}$/i.test(line)) cat = 'domains';
          else cat = 'regex';
        }
        if (val && !STATE.ioc[cat].includes(val)) { STATE.ioc[cat].push(val); added++; }
      });
    }
    renderIocTable();
    showToast(`Imported ${added} indicator(s) from ${file.name}`);
    ZBSound.play('deploy');
  };
  reader.readAsText(file);
  e.target.value = '';
}

function saveIoc() {
  if (!STATE.ioc) STATE.ioc = emptyIoc();
  const payload = {};
  IOC_CATS.forEach(c => payload[c] = STATE.ioc[c] || []);
  $('btn-ioc-save').disabled = true;
  fetch('/api/ioc', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
    .then(r => r.json())
    .then(res => {
      if (res.error) throw new Error(res.error);
      STATE.ioc._path = res.path;
      STATE.ioc._custom = true;
      if ($('ioc-path')) $('ioc-path').value = res.path;   // scans now pass this via -IocFile
      renderIocTable();
      showToast(`Saved ${res.count} IOCs → scans will use this file`);
      ZBSound.play('complete');
    })
    .catch(e => { showToast(`IOC save failed: ${e.message}`); ZBSound.play('alert'); })
    .finally(() => { $('btn-ioc-save').disabled = false; });
}

// ── Report View ───────────────────────────────────────────────────────────────
function buildReport() {
  const counts    = STATE.threatCounts;
  const total     = Object.values(counts).reduce((a, b) => a + b, 0);
  const riskScore = Math.min(100, Math.round((total / Math.max(STATE.findings.length, 1)) * 60 + total * 2));

  drawRiskDial(riskScore);
  ZBFX.countUp($('risk-score-label'), riskScore, 1100);
  drawRadarChart(counts);

  const cardsEl = $('report-cards');
  cardsEl.innerHTML = '';
  STATE.findings.filter(f => f.severity === 'CRITICAL').slice(0, 6).forEach(f => {
    const card = document.createElement('div');
    card.className = 'report-card critical';
    card.innerHTML = `<div class="card-sev" style="color:var(--threat-critical)">🔴 CRITICAL — ${f.threat_type || 'Unknown'} ${mitreBadge(f)}</div><div class="card-text">${escapeHtml((f.line || '').substring(0, 100))}</div>`;
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

// ── Secret code listener (MSP mode + the Kraken ritual) ──────────────────────
function initMspListener() {
  const TRIGGERS = ['msp', 'gannon', 'staples'];
  document.addEventListener('keydown', (e) => {
    if (STATE.scanning) return;
    // Don't sniff keystrokes typed into form fields or while a modal/command palette is open —
    // otherwise typing an IOC like "kraken.io" or the word "msp" into an input fires the
    // cinematic / flips the whole UI into MSP mode mid-task.
    const t = e.target;
    if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)) return;
    if (document.querySelector('.modal:not(.hidden), #cmd-palette')) return;
    if (e.key && e.key.length === 1) {
      STATE.mspBuffer += e.key.toLowerCase();
      if (STATE.mspBuffer.length > 10) STATE.mspBuffer = STATE.mspBuffer.slice(-10);
      $('msp-input-display').textContent = STATE.mspBuffer + '_';
      if (STATE.mspBuffer.includes('kraken') && !ZBKraken.isRunning()) {
        STATE.mspBuffer = '';
        ZBKraken.release();
        return;
      }
      if (!STATE.mspMode && TRIGGERS.find(w => STATE.mspBuffer.includes(w))) {
        activateMspMode();
      }
    }
  });
}

function activateMspMode() {
  STATE.mspMode = true;
  ZBThemes.apply('gannon-orange');
  buildThemeGrid();
  ZBSound.play('confirm');
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

// (legacy particle background removed — superseded by the ZBFX layer in fx.js)

// ── Helpers ───────────────────────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Transient bottom-right notification.
function showToast(msg) {
  let host = $('zb-toast-host');
  if (!host) {
    host = document.createElement('div');
    host.id = 'zb-toast-host';
    document.body.appendChild(host);
  }
  const t = document.createElement('div');
  t.className = 'zb-toast';
  t.textContent = msg;
  host.appendChild(t);
  requestAnimationFrame(() => t.classList.add('show'));
  setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 350); }, 3200);
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
  } else if (format === 'html' || format === 'csv') {
    // Server renders from current scan state (includes MITRE tags) and streams a download.
    ZBSound.play('click');
    const a = document.createElement('a');
    a.href = `/api/export/${format}`;
    a.download = '';
    document.body.appendChild(a);
    a.click();
    a.remove();
  }
}

// ── Boot ──────────────────────────────────────────────────────────────────────
window.addEventListener('load', () => setTimeout(runBoot, 100));
