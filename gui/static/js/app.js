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
  logQuery: '',          // free-text filter over the log view (paired with the severity chips)
  // Findings triage filter model (UX pass): the severity pills are real toggles, the
  // search box matches free text across the finding, and groupBy re-buckets the tree.
  findingsSevFilter: new Set(['CRITICAL', 'HIGH', 'POSSIBLE', 'CLEAN', 'INFO']),
  findingsQuery: '',
  findingsGroupBy: 'threat_type',
  autoScroll: true,
  logLines: [],
  totalThreats: 0,
  elapsedSec: 0,
  currentPhase: 0,
  totalPhases: 115,
  scanStartMs: 0,   // local clock origin (re-synced from server elapsed)
  lastEventMs: 0,   // last time any SSE event arrived (drives the "still working" heartbeat)
  sseWasDown: false,     // so a reconnect is announced once, not on every retry tick
  lastRemediation: null, // persisted PURGE outcome, rendered on the Report view
  bgTitleTimer: 0,       // flashes document.title when a scan finishes in a background tab
  origTitle: '',         // captured once, so repeated flashes cannot restore the flash text
};

// ── CSRF token ────────────────────────────────────────────────────────────────
// The server rejects any same-origin browser POST that does not echo this token
// (see Test-RequestAllowed in ZeroBreach-Server.ps1). It is readable only from this
// origin, so a malicious page in another tab cannot learn it and cannot drive
// /api/remediate behind the operator's back. Fetched once at boot; postJSON() below
// is the single choke point that attaches it, so no POST site can forget it.
let CSRF_TOKEN = '';

function loadCsrfToken() {
  return fetch('/api/csrf')
    .then(r => r.json())
    .then(j => { CSRF_TOKEN = j.token || ''; })
    .catch(() => { CSRF_TOKEN = ''; });
}

// Every state-changing request goes through here.
function postJSON(url, payload) {
  const headers = { 'Content-Type': 'application/json', 'X-ZB-Token': CSRF_TOKEN };
  const opts = { method: 'POST', headers };
  if (payload !== undefined) opts.body = JSON.stringify(payload);
  return fetch(url, opts).then(r => {
    // A 403 here almost always means the page was loaded before the server restarted
    // and is holding a stale token — re-fetch once and retry rather than failing silently.
    if (r.status === 403) {
      return loadCsrfToken().then(() => {
        headers['X-ZB-Token'] = CSRF_TOKEN;
        return fetch(url, opts);
      });
    }
    return r;
  });
}

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
  // Fire-and-forget: the token is only needed by POSTs, all of which happen after a
  // user interaction, and postJSON() re-fetches + retries once on a 403 anyway.
  loadCsrfToken();
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
  initProfiles();
  initScanMonitor();
  initFindingsView();
  initIocView();
  initMspListener();
  loadSysInfo();
  startVitalsPoller();
  initSettingsUI();
  initReportTools();
  initCmdPalette();
  initKeyboardActivation();
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

  STATE.sse.onopen = () => {
    setConnected(true);
    // Only announce a RE-connect, not the initial one.
    if (STATE.sseWasDown) {
      STATE.sseWasDown = false;
      showToast('Live connection restored');
      appendLogLine({ text: '[INFO] Live event stream reconnected.', severity: 'INFO', phase: 0 });
    }
  };

  STATE.sse.onerror = () => {
    setConnected(false);
    // EventSource auto-reconnects on its own, but silently — during a 25-minute DEEP scan a
    // dropped stream looked exactly like "the scan went quiet", so say it out loud once.
    if (!STATE.sseWasDown) {
      STATE.sseWasDown = true;
      showToast('Live connection lost — retrying (the scan itself keeps running)');
      appendLogLine({
        text: '[WARN] Live event stream dropped — reconnecting. The scan continues on the server; findings will catch up.',
        severity: 'POSSIBLE', phase: 0,
      });
    }
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
let evQueueHead = 0;

function enqueueEvent(data) {
  EV_QUEUE.push(data);
  if (!evPumpScheduled) { evPumpScheduled = true; requestAnimationFrame(pumpEvents); }
}

function pumpEvents() {
  evPumpScheduled = false;
  // Read through the queue with a moving head index instead of Array.shift(): shift()
  // re-indexes the whole array on every call, so draining a big burst was O(n^2) — the
  // exact cost this batching exists to avoid. The consumed prefix is dropped in one
  // splice once it gets large, which keeps memory flat without paying per event.
  const n = Math.min(EV_QUEUE.length - evQueueHead, EV_MAX_PER_FRAME);
  for (let i = 0; i < n; i++) {
    // Advance the head BEFORE dispatching, and swallow a throwing handler. The old
    // shift()-based pump removed the event before dispatch, so a bad event cost exactly one
    // event. With a head index, an exception escaping here left evQueueHead unchanged and
    // evPumpScheduled false — the next SSE event rescheduled the pump, which replayed the
    // identical prefix and hit the same bad event again, forever: duplicated log lines,
    // inflated threat counts, and findings duplicated into the tree and the PURGE queue.
    const ev = EV_QUEUE[evQueueHead + i];
    try {
      handleServerEvent(ev);
    } catch (err) {
      console.error('[ZeroBreach] event handler failed; skipping event', err, ev);
    }
  }
  evQueueHead += n;
  if (evQueueHead > 4096 || evQueueHead === EV_QUEUE.length) {
    EV_QUEUE.splice(0, evQueueHead);
    evQueueHead = 0;
  }
  if (EV_QUEUE.length > evQueueHead) { evPumpScheduled = true; requestAnimationFrame(pumpEvents); }
}

// NOT named dispatchEvent: a top-level function declaration by that name shadows the
// inherited window.dispatchEvent (EventTarget.prototype.dispatchEvent) for this whole
// script, so any library or future code calling window.dispatchEvent(new CustomEvent(...))
// would have silently invoked this SSE handler instead.
function handleServerEvent(data) {
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
      notifyBackground(`Scan complete — ${data.findings_count || 0} findings`);
      break;
    case 'remediation_complete':
      STATE.lastRemediation = {
        applied: data.applied, failed: data.failed, skipped: data.skipped, blocked: data.blocked,
        snapshot: data.snapshot || '',   // rollback .reg path, surfaced on the Report view
        when: new Date().toLocaleString(),
      };
      onRemediationComplete(data);
      notifyBackground(`Remediation complete — ${data.applied || 0} applied, ${data.blocked || 0} blocked`);
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
// TRIAGE deployment mode (EVIDENCE_ENGINE_PLAN P9). Injected here rather than added to
// index.html so the tile picks up the existing click/sound/profile wiring below with no
// duplicated markup, and so it stays next to the comment explaining what the mode is.
// Runs the QUICK 30-phase core PLUS every phase from 81-115 — the evidence, correlation
// and Defender-tamper phases FULL (ceiling 80) gates out of an alert-ticket triage.
function ensureTriageModeTile() {
  const host = document.getElementById('mode-tiles');
  if (!host || host.querySelector('[data-mode="TRIAGE"]')) return;
  const tile = document.createElement('div');
  tile.className = 'mode-tile';
  tile.dataset.mode = 'TRIAGE';
  tile.innerHTML =
    '<div class="mode-tile-icon">🎯</div>' +
    '<div class="mode-tile-name">TRIAGE</div>' +
    '<div class="mode-tile-phases">CORE + 81-115</div>' +
    '<div class="mode-tile-desc">Alert ticket triage · evidence + Defender tamper</div>';
  const full = host.querySelector('[data-mode="FULL"]');
  if (full) host.insertBefore(tile, full); else host.appendChild(tile);
}

function initLaunchPad() {
  ensureTriageModeTile();
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

// ── Scan Profiles (named config presets — /api/profiles) ─────────────────────
let SCAN_PROFILES = [];

// Single source of truth for checkbox-id ↔ profile-key pairs; used by both
// applyProfile and saveProfile so the two field lists can never drift.
const PROFILE_TOGGLES = [
  ['opt-html', 'html_report'], ['opt-snapshot', 'snapshot'], ['opt-baseline', 'baseline'],
  ['opt-paranoid', 'paranoid'], ['opt-csv', 'csv'], ['opt-stealth', 'stealth'],
];

function initProfiles() {
  $('profile-select').addEventListener('change', () => {
    const p = SCAN_PROFILES.find(x => x.name === $('profile-select').value);
    if (p) applyProfile(p);
  });
  $('btn-profile-save').addEventListener('click', saveProfile);
  $('btn-profile-del').addEventListener('click', deleteProfile);
  loadProfiles();
}

function loadProfiles(selectName) {
  fetch('/api/profiles')
    .then(r => r.json())
    .then(j => { SCAN_PROFILES = j.profiles || []; renderProfileOptions(selectName); })
    .catch(() => {});
}

function renderProfileOptions(selectName) {
  const sel = $('profile-select');
  sel.innerHTML = '<option value="">— LOAD PROFILE —</option>';
  SCAN_PROFILES.forEach(p => {
    const o = document.createElement('option');
    o.value = p.name;
    const h = parseInt(p.hours) || 0;
    const scope = h === 0 ? 'ALL TIME' : (h % 24 === 0 ? (h / 24) + 'D' : h + 'H');
    o.textContent = `${p.builtin ? '◆ ' : ''}${p.name} — ${p.mode} / ${scope}`;
    sel.appendChild(o);
  });
  sel.value = selectName || '';
}

function applyProfile(p) {
  ZBSound.play('confirm');
  STATE.scanMode = p.mode;
  $$('.mode-tile').forEach(t => t.classList.toggle('active', t.dataset.mode === p.mode));

  const h = parseInt(p.hours) || 0;
  STATE.scanHours = h;
  $$('.time-tile').forEach(t => t.classList.remove('active'));
  const tile = document.querySelector(`.time-tile[data-hours="${h}"]`);
  if (tile) { tile.classList.add('active'); $('custom-hours').value = ''; }
  else { document.querySelector('.custom-tile').classList.add('active'); $('custom-hours').value = h; }

  PROFILE_TOGGLES.forEach(([id, k]) => {
    const el = $(id);
    if (el && k in p) el.checked = !!p[k];
  });
  if ('ioc_file' in p) $('ioc-path').value = p.ioc_file || '';
  $('profile-name').value = p.builtin ? '' : p.name;
}

function saveProfile() {
  const name = $('profile-name').value.trim();
  if (!name) { ZBSound.play('error'); $('profile-name').focus(); return; }
  const profile = {
    name,
    mode:     STATE.scanMode,
    hours:    STATE.scanHours,
    ioc_file: $('ioc-path').value.trim(),
  };
  PROFILE_TOGGLES.forEach(([id, k]) => { profile[k] = $(id).checked; });
  postJSON('/api/profiles', { action: 'save', profile })
    .then(r => r.json().then(j => ({ ok: r.ok, j })))
    .then(({ ok, j }) => {
      if (!ok) throw new Error(j.error || 'save failed');
      ZBSound.play('confirm');
      showToast(`Profile "${name}" saved`);
      SCAN_PROFILES = j.profiles || [];
      renderProfileOptions(name);
    })
    .catch(e => { showToast(`Profile save failed: ${e.message}`); ZBSound.play('error'); });
}

function deleteProfile() {
  const name = $('profile-select').value;
  const p = SCAN_PROFILES.find(x => x.name === name);
  if (!p) { ZBSound.play('error'); return; }
  if (p.builtin) { showToast('Built-in profiles cannot be deleted'); ZBSound.play('error'); return; }
  postJSON('/api/profiles', { action: 'delete', name })
    .then(r => r.json().then(j => ({ ok: r.ok, j })))
    .then(({ ok, j }) => {
      if (!ok) throw new Error(j.error || 'delete failed');
      ZBSound.play('close');
      showToast(`Profile "${name}" deleted`);
      SCAN_PROFILES = j.profiles || [];
      renderProfileOptions();
      $('profile-name').value = '';
    })
    .catch(e => { showToast(`Profile delete failed: ${e.message}`); ZBSound.play('error'); });
}

// ── Settings: theme grid, FX intensity, audio ────────────────────────────────
// Anything that is a <div>/<span> with a click handler must also answer Enter/Space,
// or it simply does not exist for a keyboard user. One delegated listener covers the
// nav items, IOC tabs, log filters and theme cards without touching their own handlers.
function initKeyboardActivation() {
  document.addEventListener('keydown', e => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const el = e.target;
    if (!el || !el.matches) return;
    if (el.matches('.nav-item, .ioc-tab, .log-filter, .theme-card')) {
      e.preventDefault();
      el.click();
    }
  });
  // Make the remaining click-only controls reachable in the first place.
  // .threat-chip is intentionally excluded: it is a pure counter with no click handler, so
  // announcing it as a button just adds dead tab stops for a screen-reader user.
  $$('.log-filter, .theme-card').forEach(el => {
    if (!el.hasAttribute('tabindex')) el.setAttribute('tabindex', '0');
    if (!el.hasAttribute('role')) el.setAttribute('role', 'button');
  });
}

// Desktop notifications are opt-in from Settings, never prompted on page load —
// browsers penalise unprompted permission requests and users rightly distrust them.
function initNotifyOptIn() {
  const cb = $('opt-notify');
  if (!cb || !window.Notification) return;
  cb.checked = Notification.permission === 'granted';
  cb.addEventListener('change', () => {
    if (!cb.checked) return;                       // cannot revoke from JS; browser settings only
    if (Notification.permission === 'granted') return;
    Notification.requestPermission().then(perm => {
      cb.checked = perm === 'granted';
      showToast(perm === 'granted'
        ? 'Desktop notifications enabled'
        : 'Notification permission denied — the tab title will still flash');
    });
  });
}

function initSettingsUI() {
  initNotifyOptIn();
  buildThemeGrid();
  buildFxTiers();
  buildCineFxToggles();
  initAudioControls();
  initScheduleUI();
  document.addEventListener('zb-god-unlocked', buildThemeGrid);
}

// The SCHEDULE + SMTP section used to render with no listeners and no route behind it.
function initScheduleUI() {
  const btn = $('btn-schedule-apply');
  const st  = $('schedule-status');
  if (!btn) return;

  // Repopulate from the last-applied settings.
  fetch('/api/schedule').then(r => r.json()).then(d => {
    if (!d || d.error) return;
    if ($('set-schedule'))    $('set-schedule').value    = d.schedule    || '';
    if ($('set-smtp-server')) $('set-smtp-server').value = d.smtp_server || '';
    if ($('set-smtp-from'))   $('set-smtp-from').value   = d.smtp_from   || '';
    if ($('set-smtp-to'))     $('set-smtp-to').value     = d.smtp_to     || '';
  }).catch(() => {});

  btn.addEventListener('click', () => {
    const payload = {
      schedule:    $('set-schedule').value,
      smtp_server: $('set-smtp-server').value.trim(),
      smtp_from:   $('set-smtp-from').value.trim(),
      smtp_to:     $('set-smtp-to').value.trim(),
    };
    // Partial SMTP is a silent no-op in the engine — say so rather than pretend it worked.
    const filled = [payload.smtp_server, payload.smtp_from, payload.smtp_to].filter(Boolean).length;
    if (filled > 0 && filled < 3) {
      st.textContent = 'Fill in ALL THREE SMTP fields (server, from, to) or leave all three empty.';
      st.style.color = 'var(--threat-high)';
      ZBSound.play('error');
      return;
    }
    btn.disabled = true;
    st.textContent = 'Applying...';
    st.style.color = 'var(--text-mid)';
    postJSON('/api/schedule', payload)
      .then(r => r.json().then(j => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) throw new Error(j.error || 'failed');
        st.textContent = j.status || 'applied';
        st.style.color = 'var(--threat-clean)';
        ZBSound.play('confirm');
        showToast(j.status || 'Schedule applied');
      })
      .catch(e => {
        st.textContent = `Failed: ${e.message}`;
        st.style.color = 'var(--threat-critical)';
        ZBSound.play('error');
      })
      .finally(() => { btn.disabled = false; });
  });
}

function buildThemeGrid() {
  const grid = $('theme-grid');
  if (!grid) return;
  grid.innerHTML = '';
  // NB: cards are re-created here on the KRAKEN unlock and on MSP activation, so the
  // role/tabindex are set per-card below rather than once in initKeyboardActivation.
  const cur = ZBThemes.current().id;
  ZBThemes.visible().forEach(t => {
    const card = document.createElement('div');
    card.className = 'theme-card' + (t.id === cur ? ' active' : '') + (t.secret ? ' secret' : '');
    card.setAttribute('role', 'button');
    card.setAttribute('tabindex', '0');
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

  // snapshot / baseline / csv round-trip through scan profiles but used never to be
  // sent here, so those three checkboxes did nothing whatever the operator picked.
  const config = {
    mode:        STATE.scanMode,
    hours:       STATE.scanHours,
    html_report: $('opt-html').checked,
    paranoid:    $('opt-paranoid').checked,
    stealth:     $('opt-stealth').checked,
    snapshot:    $('opt-snapshot').checked,
    baseline:    $('opt-baseline').checked,
    csv:         $('opt-csv').checked,
    ioc_file:    $('ioc-path').value.trim(),
    msp_mode:    STATE.mspMode,
  };

  $('si-mode').textContent   = STATE.scanMode;
  $('pill-mode').style.display = 'flex';
  $('btn-abort').disabled    = false;

  switchView('scanmonitor');

  postJSON('/api/scan/start', config)
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
    postJSON('/api/scan/abort');
    STATE.scanning = false;
    $('btn-abort').disabled = true;
    $('sb-status').textContent = '● ABORTED';
    $('sb-status').style.color = 'var(--threat-critical)';
  });

  $('autoscroll').addEventListener('change', e => { STATE.autoScroll = e.target.checked; });

  const logSearch = $('log-search');
  if (logSearch) {
    logSearch.addEventListener('input', () => {
      STATE.logQuery = logSearch.value.trim().toLowerCase();
      rerenderLog();
    });
  }

  $$('.log-filter').forEach(f => {
    f.addEventListener('click', () => {
      $$('.log-filter').forEach(x => x.classList.remove('active'));
      f.classList.add('active');
      STATE.logFilter = f.dataset.filter;
      rerenderLog();
    });
  });
}

// Severity chip AND text query must both pass for a line to show.
function logLineVisible(data) {
  if (STATE.logFilter !== 'ALL' && data.severity !== STATE.logFilter) return false;
  if (STATE.logQuery && !String(data.text || '').toLowerCase().includes(STATE.logQuery)) return false;
  return true;
}

const LOG_BUFFER_CAP = 2000;   // retained log records (caps memory + rerenderLog cost)
const LOG_DOM_CAP    = 800;    // live <div> nodes in #log-output (caps layout/paint cost)

// Render one line into the log element. Pure DOM — it must NOT touch STATE.logLines,
// so that re-rendering on a filter change cannot mutate the buffer (see rerenderLog).
function renderLogNode(data, el) {
  const line = document.createElement('div');
  line.className   = `log-line sev-${data.severity}`;
  line.dataset.sev = data.severity;
  // Stamp the arrival time once, on first append, and reuse it on every re-render —
  // formatting `new Date()` here restamped the whole backlog to "now" each time the
  // filter changed, so the log claimed every line arrived at the same instant.
  if (!data._ts) data._ts = new Date().toLocaleTimeString('en-US', { hour12: false });
  line.innerHTML = `<span class="log-ts">${data._ts}</span><span class="log-text">${escapeHtml(data.text)}</span>`;
  el.appendChild(line);
  // Trim oldest nodes so a long/noisy scan can't grow the DOM without bound.
  while (el.childElementCount > LOG_DOM_CAP) el.removeChild(el.firstChild);
}

function appendLogLine(data) {
  STATE.logLines.push(data);
  if (STATE.logLines.length > LOG_BUFFER_CAP) STATE.logLines.shift();

  if (!logLineVisible(data)) return;

  const el = $('log-output');
  renderLogNode(data, el);
  if (STATE.autoScroll) el.scrollTop = el.scrollHeight;
}

function rerenderLog() {
  const el = $('log-output');
  el.innerHTML = '';
  // Render only. This used to call appendLogLine, which ALSO pushes into
  // STATE.logLines — so every filter/search change duplicated the entire buffer
  // (and, once past LOG_BUFFER_CAP, silently discarded the oldest real lines).
  const visible = STATE.logLines.filter(logLineVisible);
  visible.slice(-LOG_DOM_CAP).forEach(d => renderLogNode(d, el));
  if (STATE.autoScroll) el.scrollTop = el.scrollHeight;
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
// One definition of "this is a hardening action", used by both the findings loader and the
// SELECT HARDENING button. Keyed on the engine's Group, which is exact, with a threat_type
// fallback for the older group names.
function isHardeningFinding(f) {
  const g = String(f.group || '');
  if (/^(Proactive|Operator|System) Hardening$/i.test(g)) return true;
  return /hardening opportunity|macro\/attachment exposure|script (host exposure|lure association)|defender posture|remote access exposure/i
    .test(String(f.threat_type || ''));
}

function loadEngineFindings(name) {
  fetch('/api/report?name=' + encodeURIComponent(name))
    .then(r => r.json())
    .then(list => {
      if (!Array.isArray(list)) return;
      // Keep the findings view focused on notable severities (matches the live view),
      // but each now carries fix_action/fix_param for real remediation.
      // Notable severities, PLUS the INFO-level hardening actions. Most of the hardening set
      // (WSH disable, the six ASR rules, the HARDEN6_* posture items, the script-lure
      // associations) is deliberately INFO so it can never be auto-selected — but filtering it
      // out here meant SELECT HARDENING had almost nothing to select and the ASR set, the actual
      // point of the feature, was unreachable from the GUI entirely. INFO findings are still
      // never auto-selected: autoEligible only ever matches CRITICAL/HIGH.
      const notable = list.filter(f =>
        ['CRITICAL', 'HIGH', 'POSSIBLE'].includes(f.severity) ||
        (f.severity === 'INFO' && isHardeningFinding(f)));
      if (notable.length === 0) return;          // nothing actionable — keep SSE findings
      STATE.engineReport = name;
      STATE.findings = notable;
      STATE.selectedFindings.clear();
      STATE.findingsAutoSelected = false;   // fresh report → allow the one-time severity auto-select
      // Reset the view filters too. The auto-select only walks the VISIBLE findings and then
      // burns the one-shot flag, so a filter left over from the previous scan (a deselected
      // CRITICAL pill, or text still in the search box) would silently leave the new scan's
      // CRITICALs unselected with no way to re-run the auto-select.
      STATE.findingsSevFilter = new Set(['CRITICAL', 'HIGH', 'POSSIBLE', 'CLEAN', 'INFO']);
      STATE.findingsQuery = '';
      if ($('findings-search')) $('findings-search').value = '';
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
    // Scoped to what is CURRENTLY VISIBLE, and additive. Operating on the whole result set
    // while the tree showed a filtered subset meant "select all" could queue ~200 findings —
    // including destructive CRITICALs — when the operator was looking at 3 POSSIBLEs. SELECT
    // GROUP was already scoped to its group; these two now agree about what "all" means.
    // P10: same rule for a LIKELY-FALSE-POSITIVE verdict — bulk-select skips it.
    const allowed = visibleFindings().filter(f => !f.protected && !f.vendor_trusted && !isLikelyFalsePositive(f));
    allowed.forEach(f => STATE.selectedFindings.add(f.id));            // native id type (str|num)
    const allowedStr = new Set(allowed.map(f => String(f.id)));         // dataset.id is always a string
    $$('#findings-tree input[type=checkbox]').forEach(cb => { if (allowedStr.has(cb.dataset.id)) cb.checked = true; });
    if (allowed.length < STATE.findings.length) {
      showToast(`Selected ${allowed.length} visible finding(s) — ${STATE.findings.length - allowed.length} are hidden by the current filter`);
    }
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

  // Severity pills as filters. They were static counters with no handlers despite looking
  // clickable — the log view's .log-filter chips already proved the pattern.
  [['pill-critical', 'CRITICAL'], ['pill-high', 'HIGH'], ['pill-possible', 'POSSIBLE'],
   ['pill-clean', 'CLEAN'], ['pill-info', 'INFO']]
    .forEach(([id, sev]) => {
      const el = $(id);
      if (!el) return;
      el.addEventListener('click', () => {
        if (STATE.findingsSevFilter.has(sev)) STATE.findingsSevFilter.delete(sev);
        else STATE.findingsSevFilter.add(sev);
        // Never let the operator filter everything away with no way back.
        if (STATE.findingsSevFilter.size === 0) {
          ['CRITICAL', 'HIGH', 'POSSIBLE', 'CLEAN', 'INFO'].forEach(x => STATE.findingsSevFilter.add(x));
        }
        ZBSound.play('tick');
        renderFindingsTree();
      });
    });

  const searchEl = $('findings-search');
  if (searchEl) {
    searchEl.addEventListener('input', () => {
      STATE.findingsQuery = searchEl.value.trim().toLowerCase();
      renderFindingsTree();
    });
  }
  const groupEl = $('findings-groupby');
  if (groupEl) {
    groupEl.addEventListener('change', () => {
      STATE.findingsGroupBy = groupEl.value;
      renderFindingsTree();
    });
  }

  // Bulk-select the operator-only hardening set. These findings are Info/POSSIBLE by
  // design so nothing auto-ticks them; this is the deliberate opt-in. Deliberately does
  // NOT execute anything — the operator still reviews the queue and types PURGE.
  const hardenBtn = $('btn-select-hardening');
  if (hardenBtn) {
    hardenBtn.addEventListener('click', () => {
      // !vendor_trusted like every other bulk selector: Test-VendorTrusted is a SOFT signal
      // that must never be bulk-selected (it stays individually tickable). Omitting it here
      // let one click bypass the vendor guard for exactly this button.
      const picks = STATE.findings.filter(f => isHardeningFinding(f) && !f.protected && !f.vendor_trusted && !isLikelyFalsePositive(f));
      if (!picks.length) {
        showToast('No hardening actions in this scan — posture already good');
        ZBSound.play('error');
        return;
      }
      picks.forEach(f => STATE.selectedFindings.add(f.id));
      const pickStr = new Set(picks.map(f => String(f.id)));
      $$('#findings-tree input[type=checkbox]').forEach(cb => {
        if (pickStr.has(cb.dataset.id)) cb.checked = true;
      });
      ZBSound.play('confirm');
      showToast(`${picks.length} hardening action(s) selected — review the queue, then EXECUTE`);
      updateRemediationBtn();
    });
  }

  const clientBtn = $('btn-export-client');
  if (clientBtn) clientBtn.addEventListener('click', () => exportReport('client'));

  $('btn-goto-remediation').addEventListener('click', () => switchView('remediation'));

  $('btn-export-findings').addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(STATE.findings, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = `zerobreach_findings_${Date.now()}.json`;
    a.click();
  });
}

// Single source of truth for "what is currently on screen" — used by the renderer and by
// SELECT ALL so the button can never disagree with the view.
function visibleFindings() {
  const q = STATE.findingsQuery;
  return STATE.findings.filter(f => {
    if (!STATE.findingsSevFilter.has(f.severity)) return false;
    if (!q) return true;
    // P10 fields join the haystack so an operator can filter by verdict, evidence source,
    // hash or signer. Undefined entries are already dropped by the filter/join below.
    const hay = [f.line, f.threat_type, f.mitre_id, f.mitre && f.mitre.name,
                 f.mitre && f.mitre.tactic, f.phase, f.severity,
                 f.verdict, f.confidence, f.evidence_source, f.threat_name,
                 f.sha256, f.signer, f.host_url, f.process_name]
      .filter(Boolean).join(' ').toLowerCase();
    return hay.includes(q);
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

  // Counts always reflect the WHOLE result set, not the filtered view — the pills double as
  // the filter control, so a count that shrank when you clicked it would be circular.
  const counts = { CRITICAL: 0, HIGH: 0, POSSIBLE: 0, CLEAN: 0, INFO: 0 };
  STATE.findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
  Object.entries(counts).forEach(([k, v]) => {
    const el = $(`count-${k.toLowerCase()}`);
    if (el) el.textContent = v;
    const pill = $(`pill-${k.toLowerCase()}`);
    if (pill) {
      const on = STATE.findingsSevFilter.has(k);
      pill.classList.toggle('active', on);
      pill.classList.toggle('filtered-out', !on);
      pill.setAttribute('aria-pressed', on ? 'true' : 'false');
    }
  });

  // Apply severity filter + free-text search. Search covers everything the technician can
  // see on the row plus the MITRE id, so pasting a path or a T-number just works.
  const visible = visibleFindings();

  const filterStatus = $('findings-filter-status');
  if (filterStatus) {
    const hidden = STATE.findings.length - visible.length;
    const visibleIds = new Set(visible.map(f => f.id));
    const hiddenSelected = [...STATE.selectedFindings].filter(id => !visibleIds.has(id)).length;
    filterStatus.textContent = hidden > 0
      ? `Showing ${visible.length} of ${STATE.findings.length} findings (${hidden} hidden by filter/search`
        + (hiddenSelected ? `, ${hiddenSelected} of them SELECTED and still queued)` : ')')
      : `Showing all ${STATE.findings.length} findings`;
  }

  if (STATE.findings.length === 0) {
    // Distinguish "clean box" from "you have not scanned yet" — these used to look identical.
    container.innerHTML = STATE.scanComplete
      ? '<div class="findings-empty findings-empty-clean" role="status">✅ <b>NO THREATS FOUND</b><br><span>The scan completed and every phase came back clean.</span></div>'
      : '<div class="findings-empty" role="status">NO FINDINGS YET — RUN A SCAN FIRST</div>';
    return;
  }
  if (visible.length === 0) {
    container.innerHTML = '<div class="findings-empty" role="status">NO FINDINGS MATCH THE CURRENT FILTER/SEARCH<br><span>Adjust the severity pills or clear the search box.</span></div>';
    updateRemediationBtn();   // this early return used to leave the button state stale
    return;
  }

  // Bucket by the operator's chosen dimension.
  const groupKey = f => {
    switch (STATE.findingsGroupBy) {
      case 'severity': return f.severity || 'UNKNOWN';
      case 'tactic':   return (f.mitre && f.mitre.tactic) || 'Unmapped';
      case 'phase':    return `Phase ${f.phase}`;
      default:         return f.threat_type || 'Other';
    }
  };
  const groups = {};
  visible.forEach(f => {
    const g = groupKey(f);
    if (!groups[g]) groups[g] = [];
    groups[g].push(f);
  });

  // Most-severe groups first so the technician triages top-down.
  const sevRank = { CRITICAL: 0, HIGH: 1, POSSIBLE: 2, CLEAN: 3 };
  const groupMaxSev = items =>
    items.some(i => i.severity === 'CRITICAL') ? 'CRITICAL' :
    items.some(i => i.severity === 'HIGH')     ? 'HIGH'     :
    items.some(i => i.severity === 'POSSIBLE') ? 'POSSIBLE' : 'CLEAN';
  const ordered = Object.entries(groups).sort((a, b) => {
    const d = sevRank[groupMaxSev(a[1])] - sevRank[groupMaxSev(b[1])];
    return d !== 0 ? d : b[1].length - a[1].length;
  });

  ordered.forEach(([groupName, items]) => {
    const groupEl = document.createElement('div');
    groupEl.className = 'tree-group';

    const maxSev = groupMaxSev(items);
    const sevDot = { CRITICAL: '🔴', HIGH: '🟠', POSSIBLE: '🟡', CLEAN: '🟢' }[maxSev] || '⚪';

    groupEl.innerHTML = `
      <div class="tree-group-header" role="button" tabindex="0" aria-expanded="true">
        <span class="tree-toggle" aria-hidden="true">▼</span>
        <span class="tree-group-name">${sevDot} ${escapeHtml(String(groupName).toUpperCase())}</span>
        <span class="tree-group-count">${items.length}</span>
        <button type="button" class="tree-group-selall cyber-btn-sm" title="Select every actionable finding in this group">SELECT GROUP</button>
      </div>
      <div class="tree-items"></div>
    `;

    const header  = groupEl.querySelector('.tree-group-header');
    const itemsEl = groupEl.querySelector('.tree-items');

    const toggleGroup = () => {
      const collapsed = header.classList.toggle('collapsed');
      itemsEl.style.display = collapsed ? 'none' : '';
      header.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
    };
    header.addEventListener('click', e => {
      if (e.target.closest('.tree-group-selall')) return;   // the button has its own job
      toggleGroup();
    });
    header.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleGroup(); }
    });

    // Per-group select-all. Same safety rule as the global SELECT ALL: never picks up a
    // protected finding (the server refuses those anyway) or trusted RMM vendor tooling.
    groupEl.querySelector('.tree-group-selall').addEventListener('click', e => {
      e.stopPropagation();
      const allowed = items.filter(f => !f.protected && !f.vendor_trusted && !isLikelyFalsePositive(f));
      allowed.forEach(f => STATE.selectedFindings.add(f.id));
      const allowedStr = new Set(allowed.map(f => String(f.id)));
      itemsEl.querySelectorAll('input[type=checkbox]').forEach(cb => {
        if (allowedStr.has(cb.dataset.id)) cb.checked = true;
      });
      ZBSound.play('confirm');
      updateRemediationBtn();
    });

    items.forEach(finding => {
      const item      = document.createElement('div');
      item.className  = 'tree-item';
      const shortText = (finding.line || '').substring(0, 120);
      // SAFETY: protected (system-critical) findings can NEVER be selected/auto-selected.
      // Vendor-trusted (RMM partner tooling) is NOT auto-selected, but stays manually selectable.
      // P10: a LIKELY-FALSE-POSITIVE verdict demotes exactly like vendor-trusted does —
      // shown, still manually tickable, never auto-selected. Demotion only; a verdict can
      // never make a finding auto-eligible that was not already.
      const autoEligible = (finding.severity === 'CRITICAL' || finding.severity === 'HIGH') &&
                           !finding.protected && !finding.vendor_trusted && !isLikelyFalsePositive(finding);
      // First render: auto-select eligible items. Re-renders: mirror the operator's live selection.
      const autoCheck = firstPass ? autoEligible : STATE.selectedFindings.has(finding.id);
      if (finding.protected) item.classList.add('protected');
      if (finding.vendor_trusted) item.classList.add('vendor-trusted');
      item.innerHTML = `
        <input type="checkbox" data-id="${escapeHtml(String(finding.id))}" ${autoCheck ? 'checked' : ''} ${finding.protected ? 'disabled' : ''}>
        <span class="item-sev ${escapeHtml(String(finding.severity || ''))}"></span>
        <span class="item-text">${escapeHtml(shortText)}</span>
        ${protectedBadge(finding)}
        ${vendorBadge(finding)}
        ${verdictBadge(finding)}
        ${evidenceBadge(finding)}
        ${mitreBadge(finding)}
        <span class="item-phase">PH${escapeHtml(String(finding.phase))}</span>
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
      <button type="button" class="queue-remove" title="Remove this action from the queue"
              aria-label="Remove this action from the queue">✕</button>
      <span class="queue-status">⏳</span>
    `;
    item.querySelector('.queue-remove').addEventListener('click', () => {
      if (STATE.remediating) return;              // never mutate the queue mid-run
      STATE.selectedFindings.delete(f.id);
      // Keep the findings tree's checkboxes honest with the queue.
      const cb = document.querySelector(`#findings-tree input[data-id="${CSS.escape(String(f.id))}"]`);
      if (cb) cb.checked = false;
      ZBSound.play('close');
      updateRemediationBtn();
      renderRemediationView();                    // re-render queue + mini tree + count
    });
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
    () => executeRemediation(selected),
    selected                       // previewed inside the modal (see showDangerConfirm)
  );
}

// A DEEP/PARANOID scan runs 25-30 minutes; the technician will be in another tab. Flash the
// document title (always) and raise a system notification (only if already granted — we never
// prompt on page load, which browsers rightly punish; Settings offers the opt-in).
function notifyBackground(text) {
  if (!document.hidden) return;
  // Stop any in-flight flash BEFORE reading the title, and remember the true original once —
  // otherwise a second notification (scan_complete then remediation_complete) captured the
  // flashing text as "original" and restored that permanently.
  clearInterval(STATE.bgTitleTimer);
  if (!STATE.origTitle) STATE.origTitle = document.title.replace(/^\(!\)\s*/, '');
  const original = STATE.origTitle;
  document.title = original;
  let on = false;
  STATE.bgTitleTimer = setInterval(() => {
    on = !on;
    document.title = on ? `(!) ${text}` : original;
  }, 1200);
  const restore = () => {
    if (document.hidden) return;
    clearInterval(STATE.bgTitleTimer);
    document.title = original;
    document.removeEventListener('visibilitychange', restore);
  };
  document.addEventListener('visibilitychange', restore);

  try {
    if (window.Notification && Notification.permission === 'granted') {
      new Notification('ZeroBreach', { body: text });
    }
  } catch (e) { /* notifications unavailable — the title flash still fired */ }
}

// ── Danger confirm: destructive actions require typing the confirm word ──────
function showDangerConfirm(word, message, onConfirm, previewItems) {
  ZBSound.play('danger');

  // The modal covers #action-queue — the very list the operator just reviewed — so a bare
  // count string asked them to confirm from memory. Show the actual targets, grouped by fix
  // action, with the irreversible ones first.
  const items = Array.isArray(previewItems) ? previewItems : [];
  let previewHtml = '';
  if (items.length) {
    const byAction = {};
    items.forEach(f => {
      // fix_action (snake_case) is what Get-EngineReportFindings actually emits; the
      // PascalCase key never exists on this path.
      const a = f.fix_action || f.FixAction || 'Unknown';
      (byAction[a] = byAction[a] || []).push(f);
    });
    // Most-destructive first: what an operator most needs to see before typing the word.
    const rank = { DeleteFile: 0, DeleteReg: 1, DeleteRegKey: 2, KillProcess: 3, RunCmd: 4, Quarantine: 5 };
    const label = {
      DeleteFile:  'DELETE FILE (irreversible)',
      DeleteReg:   'DELETE REGISTRY VALUE (rollback snapshot only)',
      DeleteRegKey:'DELETE REGISTRY KEY (rollback snapshot only)',
      KillProcess: 'KILL PROCESS',
      RunCmd:      'RUN COMMAND',
      Quarantine:  'QUARANTINE (reversible — moved to the vault)',
    };
    const sections = Object.entries(byAction)
      .sort((a, b) => (rank[a[0]] ?? 9) - (rank[b[0]] ?? 9))
      .map(([action, fs]) => {
        const rows = fs.map(f => {
          // fix_param is THE string that will execute — for the RunCmd group especially, the
          // operator must see the command, not its description. The PascalCase/`target` keys
          // are absent from the engine-report shape, so the preview always fell back to `line`.
          const target = f.fix_param || f.target || f.line || '';
          return `<li title="${escapeHtml(String(target))}">${escapeHtml(String(target).substring(0, 110))}</li>`;
        }).join('');
        return `<div class="danger-preview-group">
                  <div class="danger-preview-action">${escapeHtml(label[action] || action)} <span>x${fs.length}</span></div>
                  <ul class="danger-preview-list">${rows}</ul>
                </div>`;
      }).join('');
    previewHtml = `<div class="danger-preview" tabindex="0" aria-label="Actions that will be executed">${sections}</div>`;
  }

  // For a large batch the word alone is too easy to type on autopilot — require the count too.
  const bigBatch  = items.length >= 10;
  const needWord  = bigBatch ? `${word} ${items.length}` : word;
  const hint      = bigBatch
    ? `Large batch — type <b>${escapeHtml(needWord)}</b> (the word AND the count) to confirm.`
    : `Type <b>${escapeHtml(needWord)}</b> to confirm.`;

  const wrap = document.createElement('div');
  wrap.className = 'modal';
  wrap.id = 'modal-danger';
  wrap.setAttribute('role', 'dialog');
  wrap.setAttribute('aria-modal', 'true');
  wrap.setAttribute('aria-labelledby', 'danger-title');
  wrap.innerHTML = `
    <div class="modal-box danger">
      <div class="modal-title" id="danger-title">⚠ DESTRUCTIVE OPERATION</div>
      <div style="font-size:11px;color:var(--text);line-height:1.6">${escapeHtml(message)}</div>
      ${previewHtml}
      <div id="danger-word">${escapeHtml(needWord)}</div>
      <div class="danger-hint">${hint}</div>
      <input id="danger-input" autocomplete="off" placeholder="TYPE THE WORD ABOVE" aria-label="Confirmation phrase">
      <div class="modal-actions">
        <button class="cyber-btn danger" id="danger-go" disabled>EXECUTE</button>
        <button class="cyber-btn" id="danger-cancel">CANCEL</button>
      </div>
    </div>`;
  document.body.appendChild(wrap);
  const input = wrap.querySelector('#danger-input');
  const go    = wrap.querySelector('#danger-go');
  const close = () => {
    wrap.remove();
    document.removeEventListener('keydown', onEsc, true);
    if (lastFocus && lastFocus.focus) lastFocus.focus();   // return focus where it came from
  };
  const lastFocus = document.activeElement;
  const onEsc = e => { if (e.key === 'Escape') { e.stopPropagation(); ZBSound.play('close'); close(); } };
  document.addEventListener('keydown', onEsc, true);

  input.addEventListener('input', () => {
    const ok = input.value.trim().toUpperCase() === needWord.toUpperCase();
    go.disabled = !ok;
    if (ok) ZBSound.play('lock');
  });
  input.addEventListener('keydown', e => { if (e.key === 'Enter' && !go.disabled) go.click(); e.stopPropagation(); });

  // Focus trap: Tab must not escape the two highest-stakes dialogs in the app.
  wrap.addEventListener('keydown', e => {
    if (e.key !== 'Tab') return;
    const f = wrap.querySelectorAll('input, button, [tabindex="0"]');
    if (!f.length) return;
    const first = f[0], last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  });

  go.onclick = () => { close(); ZBSound.play('confirm'); onConfirm(); };
  wrap.querySelector('#danger-cancel').onclick = () => { ZBSound.play('close'); close(); };
  input.focus();
}

function renderFindingsTreeMini(findings) {
  const container  = $('remediation-tree');
  container.innerHTML = '';
  findings.forEach(f => {
    const item = document.createElement('div');
    item.className = 'tree-item';
    const dot  = { CRITICAL: '🔴', HIGH: '🟠', POSSIBLE: '🟡' }[f.severity] || '⚪';
    item.innerHTML = `<span class="item-sev ${escapeHtml(String(f.severity || ''))}"></span><span class="item-text">${dot} ${escapeHtml((f.line || '').substring(0, 100))}</span>`;
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

// ── P10 structured evidence / verdict (EVIDENCE_ENGINE_PLAN §2 + §4) ──────────
// Everything below is ADDITIVE and absence-tolerant: a finding carrying none of the
// new fields renders exactly as it did before this change (every helper returns '').
// No CSS file is touched — the badges carry inline, theme-var-tinted styling.

// The one field with behaviour attached. It can only ever DEMOTE: a finding the engine's
// verdict layer graded LIKELY-FALSE-POSITIVE is never auto-selected and never picked up
// by a bulk selector, exactly like a trusted-vendor finding — but it stays individually
// tickable, so the operator keeps the final call. Nothing here can promote a finding into
// the auto-select set (rule #1).
function isLikelyFalsePositive(finding) {
  return String(finding.verdict || '').toUpperCase() === 'LIKELY-FALSE-POSITIVE';
}

const VERDICT_TINT = {
  'CONFIRMED':             'var(--threat-critical, #ff5050)',
  'LIKELY':                'var(--threat-high, #ffa000)',
  'UNPROVEN':              'var(--text-dim, #8a8a8a)',
  'LIKELY-FALSE-POSITIVE': 'var(--threat-clean, #40c060)',
};

function verdictBadge(finding) {
  const v = String(finding.verdict || '').toUpperCase();
  if (!v) return '';
  const tint  = VERDICT_TINT[v] || 'var(--text-dim, #8a8a8a)';
  const bits  = [`VERDICT: ${v}`];
  if (finding.confidence)    bits.push(`confidence: ${finding.confidence}`);
  if (finding.corroboration) bits.push(`corroborated by: ${finding.corroboration}`);
  // §4: "UNPROVEN" must be distinguishable from "CLEAN" — the caveat is what makes it so.
  if (finding.caveat)        bits.push(`NOT CHECKED: ${finding.caveat}`);
  const short = v === 'LIKELY-FALSE-POSITIVE' ? 'LIKELY FP' : v;
  return `<span class="item-verdict" title="${escapeHtml(bits.join(' · '))}"` +
         ` style="font-size:9px;letter-spacing:.5px;padding:1px 5px;border-radius:2px;` +
         `border:1px solid ${tint};color:${tint};white-space:nowrap">${escapeHtml(short)}</span>`;
}

// Compact provenance badge: WHICH artifact or log produced this finding (§4 timeline
// `source`), with the corroborating identity fields in the tooltip.
function evidenceBadge(finding) {
  const src = String(finding.evidence_source || '');
  const detail = [];
  if (src)                        detail.push(`source: ${src}`);
  if (finding.event_time)         detail.push(`when: ${finding.event_time}`);
  if (finding.threat_name)        detail.push(`label: ${finding.threat_name}`);
  if (finding.sha256)             detail.push(`sha256: ${finding.sha256}`);
  if (finding.signer)             detail.push(`signer: ${finding.signer}`);
  if (finding.signature_status)   detail.push(`signature: ${finding.signature_status}`);
  if (finding.file_write_time)    detail.push(`written: ${finding.file_write_time}`);
  if (finding.file_age_hours !== undefined && finding.file_age_hours !== null && finding.file_age_hours !== '') {
    detail.push(`age: ${finding.file_age_hours}h`);
  }
  if (finding.file_size !== undefined && finding.file_size !== null && finding.file_size !== '') {
    detail.push(`size: ${finding.file_size} bytes`);
  }
  if (finding.zone_id)            detail.push(`MoTW zone: ${finding.zone_id}`);
  if (finding.host_url)           detail.push(`downloaded from: ${finding.host_url}`);
  if (finding.referrer_url)       detail.push(`referrer: ${finding.referrer_url}`);
  if (finding.process_name)       detail.push(`process: ${finding.process_name}`);
  if (finding.parent_process)     detail.push(`parent: ${finding.parent_process}`);
  if (!detail.length) return '';
  const label = src ? src.substring(0, 28) : 'EVIDENCE';
  return `<span class="item-evidence" title="${escapeHtml(detail.join('\n'))}"` +
         ` style="font-size:9px;letter-spacing:.5px;padding:1px 5px;border-radius:2px;` +
         `border:1px dashed var(--accent-2, #5aa9e6);color:var(--accent-2, #5aa9e6);` +
         `white-space:nowrap">⌕ ${escapeHtml(label)}</span>`;
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

  postJSON('/api/remediate', { report: STATE.engineReport, ids })
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
  postJSON('/api/ioc', payload)
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
  drawMitreTactics();
  renderExecSummary();
  loadReportHistory();
  renderRemediationSummary();

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


// Scan-level MITRE ATT&CK tactic rollup. Per-finding badges answer "what is this?"; this
// answers "what is happening to this machine?" — which tactics the incident actually spans.
function drawMitreTactics() {
  const canvas = $('mitreTactics');
  const emptyEl = $('mitre-rollup-empty');
  if (!canvas) return;

  const tally = {};
  STATE.findings.forEach(f => {
    const t = f.mitre && f.mitre.tactic;
    if (!t) return;
    // A technique can map to several tactics; count the finding under each.
    String(t).split(/\s*,\s*/).filter(Boolean).forEach(one => { tally[one] = (tally[one] || 0) + 1; });
  });
  const entries = Object.entries(tally).sort((a, b) => b[1] - a[1]);

  if (canvas._chart) { canvas._chart.destroy(); canvas._chart = null; }
  if (!entries.length) {
    canvas.style.display = 'none';
    if (emptyEl) emptyEl.textContent = STATE.findings.length
      ? 'No findings in this scan carry a MITRE tactic mapping.'
      : 'Run a scan to populate the ATT&CK rollup.';
    return;
  }
  canvas.style.display = '';
  if (emptyEl) emptyEl.textContent = '';

  const cs     = getComputedStyle(document.body);
  const accent = cs.getPropertyValue('--accent').trim() || '#00D4FF';
  const text   = cs.getPropertyValue('--text-mid').trim() || '#9aa';

  if (!window.Chart) {
    // Text fallback so the data is never simply missing.
    canvas.style.display = 'none';
    if (emptyEl) emptyEl.textContent = entries.map(([k, v]) => `${k}: ${v}`).join('  ·  ');
    return;
  }
  canvas._chart = new Chart(canvas, {
    type: 'bar',
    data: {
      labels: entries.map(e => e[0]),
      datasets: [{ label: 'Findings', data: entries.map(e => e[1]), backgroundColor: accent, borderWidth: 0 }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      animation: prefersReducedMotion() ? false : undefined,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: text, precision: 0 }, grid: { color: 'rgba(255,255,255,.06)' } },
        y: { ticks: { color: text }, grid: { display: false } },
      },
    },
  });
}

function prefersReducedMotion() {
  try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) { return false; }
}

// A PURGE run's outcome used to survive only as a 3-second toast. Keep it on the Report view
// so it can go into the client writeup.
function renderRemediationSummary() {
  const wrap = $('remediation-summary-wrap');
  const el   = $('remediation-summary');
  if (!wrap || !el) return;
  const r = STATE.lastRemediation;
  if (!r) { wrap.style.display = 'none'; return; }
  wrap.style.display = '';
  el.innerHTML = `
    <div class="remsum-grid">
      <div class="remsum-cell ok"><span>${r.applied || 0}</span>APPLIED</div>
      <div class="remsum-cell warn"><span>${r.failed || 0}</span>FAILED</div>
      <div class="remsum-cell"><span>${r.skipped || 0}</span>SKIPPED</div>
      <div class="remsum-cell block"><span>${r.blocked || 0}</span>BLOCKED (PROTECTED)</div>
    </div>
    <div class="remsum-when">Executed ${escapeHtml(r.when || '')}${r.snapshot ? ` · rollback snapshot: ${escapeHtml(r.snapshot)}` : ''}</div>`;
}

// ── WS5: executive summary + scan history/trend + baseline compare ────────────

// The verdict line an MSP writeup opens with. Rendered from the same STATE.findings the
// dial/radar use, so it can never disagree with them.
function renderExecSummary() {
  const el = $('exec-summary');
  if (!el) return;
  const sev = { CRITICAL: 0, HIGH: 0, POSSIBLE: 0, INFO: 0 };
  STATE.findings.forEach(f => { if (sev[f.severity] !== undefined) sev[f.severity]++; });
  const tac = {};
  STATE.findings.forEach(f => {
    const t = f.mitre && f.mitre.tactic;
    if (!t) return;
    String(t).split(/\s*,\s*/).filter(Boolean).forEach(one => { tac[one] = (tac[one] || 0) + 1; });
  });
  const topTac = Object.entries(tac).sort((a, b) => b[1] - a[1]).slice(0, 5);
  let verdict, vcolor;
  if (sev.CRITICAL > 0)      { verdict = `ACTIVE-THREAT INDICATORS PRESENT — ${sev.CRITICAL} critical finding${sev.CRITICAL > 1 ? 's' : ''} require immediate triage.`; vcolor = 'var(--threat-critical)'; }
  else if (sev.HIGH > 0)     { verdict = `ELEVATED RISK — ${sev.HIGH} high-severity finding${sev.HIGH > 1 ? 's' : ''} require review before this host is trusted.`; vcolor = 'var(--threat-high)'; }
  else if (sev.POSSIBLE > 0) { verdict = 'LOW SIGNAL — possible/informational findings only; review at convenience.'; vcolor = 'var(--threat-possible)'; }
  else                       { verdict = 'No actionable findings — system appears clean.'; vcolor = 'var(--threat-clean)'; }
  const rem = STATE.lastRemediation;
  el.innerHTML = `
    <div class="exec-verdict" style="color:${vcolor}">${verdict}</div>
    <div class="exec-counts">
      <span><b style="color:var(--threat-critical)">${sev.CRITICAL}</b> CRITICAL</span>
      <span><b style="color:var(--threat-high)">${sev.HIGH}</b> HIGH</span>
      <span><b style="color:var(--threat-possible)">${sev.POSSIBLE}</b> POSSIBLE</span>
      <span><b style="color:var(--text-dim)">${sev.INFO}</b> INFO</span>
    </div>
    ${topTac.length ? `<div class="exec-tactics">Top ATT&amp;CK tactics: ${topTac.map(([k, v]) => `${escapeHtml(k)} (${v})`).join(' · ')}</div>` : ''}
    ${rem ? `<div class="exec-tactics">Remediation: ${rem.applied || 0} applied · ${rem.failed || 0} failed · ${rem.blocked || 0} blocked</div>` : ''}`;
}

// Scan history from GET /api/reports (newest first). Drives the trend chart + the
// compare pickers. GETs carry no CSRF token by design — the gate covers non-GET only.
let REPORT_HISTORY = [];

function loadReportHistory() {
  fetch('/api/reports')
    .then(r => r.json())
    .then(j => {
      REPORT_HISTORY = (j && j.reports) || [];
      drawTrendChart();
      populateComparePickers();
    })
    .catch(() => {});
}

function drawTrendChart() {
  const canvas = $('trendChart');
  const emptyEl = $('trend-empty');
  if (!canvas) return;
  const runs = REPORT_HISTORY.slice(0, 20).reverse();   // oldest → newest, last 20
  if (canvas._chart) { canvas._chart.destroy(); canvas._chart = null; }
  if (runs.length < 2) {
    canvas.style.display = 'none';
    if (emptyEl) emptyEl.textContent = runs.length ? 'Only one saved baseline — run another scan to start the trend.' : 'No saved baselines yet.';
    return;
  }
  canvas.style.display = '';
  if (emptyEl) emptyEl.textContent = '';
  if (!window.Chart) {
    // Text fallback so the data is never simply missing.
    canvas.style.display = 'none';
    if (emptyEl) emptyEl.textContent = runs.map(r => `${r.mtime}: risk ${r.risk_score} (${r.critical}C/${r.high}H)`).join('  ·  ');
    return;
  }
  const cs = getComputedStyle(document.body);
  const accent = cs.getPropertyValue('--accent').trim() || '#00D4FF';
  const text = cs.getPropertyValue('--text-mid').trim() || '#9aa';
  const crit = cs.getPropertyValue('--threat-critical').trim() || '#ff3838';
  const high = cs.getPropertyValue('--threat-high').trim() || '#ff9500';
  canvas._chart = new Chart(canvas, {
    type: 'line',
    data: {
      labels: runs.map(r => `${(r.mtime || '').slice(5, 16)} ${r.mode || ''}`),
      datasets: [
        { label: 'Risk score', data: runs.map(r => r.risk_score), borderColor: accent, backgroundColor: 'transparent', tension: 0.25 },
        { label: 'Critical',   data: runs.map(r => r.critical),   borderColor: crit,   backgroundColor: 'transparent', tension: 0.25 },
        { label: 'High',       data: runs.map(r => r.high),       borderColor: high,   backgroundColor: 'transparent', tension: 0.25 },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: prefersReducedMotion() ? false : undefined,
      plugins: { legend: { labels: { color: text, boxWidth: 12 } } },
      scales: {
        x: { ticks: { color: text, maxRotation: 45 }, grid: { color: 'rgba(255,255,255,.06)' } },
        y: { ticks: { color: text, precision: 0 }, grid: { color: 'rgba(255,255,255,.06)' }, beginAtZero: true },
      },
    },
  });
}

function populateComparePickers() {
  const a = $('cmp-a'), b = $('cmp-b');
  if (!a || !b) return;
  const opts = REPORT_HISTORY.map(r =>
    `<option value="${escapeHtml(r.name)}">${escapeHtml(r.mtime)} — ${escapeHtml(r.mode || '?')} (${r.critical}C/${r.high}H)</option>`).join('');
  const prevA = a.value, prevB = b.value;
  a.innerHTML = opts; b.innerHTML = opts;
  // Default: previous run → newest run (REPORT_HISTORY is newest-first). Keep the
  // operator's own picks across refreshes when those files still exist.
  if (prevA && REPORT_HISTORY.some(r => r.name === prevA)) a.value = prevA;
  else if (REPORT_HISTORY.length > 1) a.value = REPORT_HISTORY[1].name;
  if (prevB && REPORT_HISTORY.some(r => r.name === prevB)) b.value = prevB;
  else if (REPORT_HISTORY.length) b.value = REPORT_HISTORY[0].name;
}

function initReportTools() {
  const btn = $('btn-compare');
  if (!btn) return;
  btn.addEventListener('click', () => {
    const a = $('cmp-a').value, b = $('cmp-b').value;
    const out = $('compare-result');
    if (!a || !b) { showToast('Pick two baselines to compare'); return; }
    if (a === b) { showToast('Pick two different baselines'); return; }
    btn.disabled = true;
    out.innerHTML = '<div class="report-empty">Comparing…</div>';
    fetch(`/api/report/diff?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`)
      .then(r => r.json())
      .then(j => {
        if (j.error) throw new Error(j.error);
        renderCompareResult(j);
      })
      .catch(e => {
        out.innerHTML = `<div class="report-empty" style="color:var(--threat-high)">Compare failed: ${escapeHtml(e.message)}</div>`;
        ZBSound.play('error');
      })
      .finally(() => { btn.disabled = false; });
  });
}

function renderCompareResult(j) {
  const out = $('compare-result');
  const li = f => `<div class="cmp-item"><span class="cmp-sev cmp-sev-${(f.severity || '').toLowerCase()}">${escapeHtml(f.severity || '?')}</span> <span class="cmp-tt">${escapeHtml(f.threat_type || '')}</span> ${escapeHtml(f.desc || '')}</div>`;
  const section = (title, arr, totalCount, color) => {
    const shown = (arr || []).slice(0, 50);
    return `<div class="cmp-section"><div class="cmp-head" style="color:${color}">${title} — ${totalCount}</div>` +
      (shown.length ? shown.map(li).join('') : '<div class="report-empty">none</div>') +
      (totalCount > shown.length ? `<div class="report-empty">…and ${totalCount - shown.length} more</div>` : '') + '</div>';
  };
  out.innerHTML =
    `<div class="cmp-meta">${escapeHtml(j.a)} → ${escapeHtml(j.b)} · ${j.persisting_count} unchanged</div>` +
    section('NEW FINDINGS', j.added, j.added_count, 'var(--threat-high)') +
    section('RESOLVED', j.resolved, j.resolved_count, 'var(--threat-clean)');
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
    // Settings shows the real reports path instead of a dead, editable "Default: Desktop" box.
    if (d.reports_dir && $('set-outdir')) $('set-outdir').value = d.reports_dir;
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
  } else if (format === 'client') {
    // Client-facing export: the raw JSON dump leaks internal plumbing (finding ids, fix
    // actions, FixParam command strings, protected/vendor flags) that means nothing to a
    // client and shouldn't leave the shop. Keep only what belongs in a writeup.
    const sevRank = { CRITICAL: 0, HIGH: 1, POSSIBLE: 2, CLEAN: 3, INFO: 4 };
    const rows = STATE.findings
      .slice()
      .sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9))
      .map(f => ({
        severity:    f.severity,
        category:    f.threat_type || 'Other',
        phase:       f.phase,
        detail:      f.line,
        attack_id:   (f.mitre && f.mitre.id) || '',
        attack_name: (f.mitre && f.mitre.name) || '',
        tactic:      (f.mitre && f.mitre.tactic) || '',
        observed_at: f.timestamp || '',
      }));
    const doc = {
      report:      'ZeroBreach incident findings',
      generated:   new Date().toISOString(),
      scan_mode:   STATE.scanMode,
      total:       rows.length,
      by_severity: rows.reduce((acc, r) => { acc[r.severity] = (acc[r.severity] || 0) + 1; return acc; }, {}),
      remediation: STATE.lastRemediation
        ? { applied: STATE.lastRemediation.applied, failed: STATE.lastRemediation.failed,
            skipped: STATE.lastRemediation.skipped, blocked: STATE.lastRemediation.blocked,
            executed: STATE.lastRemediation.when }
        : null,
      findings:    rows,
    };
    const blob = new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `zerobreach_client_report_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    ZBSound.play('confirm');
    showToast('Client report exported (internal fields stripped)');
  }
}

// ── Boot ──────────────────────────────────────────────────────────────────────
window.addEventListener('load', () => setTimeout(runBoot, 100));
