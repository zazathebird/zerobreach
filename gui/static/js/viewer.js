/* viewer.js — offline report viewer. Vanilla ES2019, no build step, no remote origins.
   Everything rendered into markup goes through escHtml(); every CSV cell goes through
   csvCell(). Both rules are enforced by tools/tests/Test-ViewerAssets.ps1. */
(function () {
  'use strict';

  // ------------------------------------------------------------------ security helpers ----

  // The one HTML-escaping helper. All five characters — four is the usual mistake.
  function escHtml(value) {
    return String(value === null || value === undefined ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // The one CSV formula-injection guard: a leading = + - @ TAB or CR is neutralised, because
  // correct quoting alone does not stop a spreadsheet evaluating the cell.
  function csvCell(value) {
    var s = String(value === null || value === undefined ? '' : value);
    if (/^[=+\-@\t\r]/.test(s)) { s = "'" + s; }
    return '"' + s.replace(/"/g, '""') + '"';
  }

  // ------------------------------------------------------------------ model ----

  var SEV_RANK = { CRITICAL: 0, HIGH: 1, POSSIBLE: 2, INFO: 3, OTHER: 4 };
  var SEV_KEYS = ['CRITICAL', 'HIGH', 'POSSIBLE', 'INFO', 'OTHER'];
  var PAGE_SIZE = 100;

  function sevKey(s) {
    var k = String(s || '').trim().toUpperCase();
    return (k === 'CRITICAL' || k === 'HIGH' || k === 'POSSIBLE' || k === 'INFO') ? k : 'OTHER';
  }
  function sevRank(s) { return SEV_RANK[sevKey(s)]; }
  function isCap(f) { return String(f && f.ID || '').indexOf('GROUPCAP_') === 0; }
  function groupLabel(f) {
    var g = String(f.Group || '').trim();
    if (!g) { g = String(f.Phase || '').trim(); }
    return g || '(ungrouped)';
  }

  function parseRecord(name, text) {
    var data = JSON.parse(text);
    if (!data || Object.prototype.toString.call(data.Findings) !== '[object Array]') {
      throw new Error(name + ': no Findings array — this is not a run record.');
    }
    var real = [];
    var caps = [];
    data.Findings.forEach(function (f) {
      if (f && typeof f === 'object') { (isCap(f) ? caps : real).push(f); }
    });
    real.sort(function (a, b) {
      var r = sevRank(a.Severity) - sevRank(b.Severity);
      return r !== 0 ? r : String(a.ID || '') < String(b.ID || '') ? -1 : 1;
    });
    var counts = { CRITICAL: 0, HIGH: 0, POSSIBLE: 0, INFO: 0, OTHER: 0 };
    var groups = {};
    var groupOrder = [];
    real.forEach(function (f) {
      counts[sevKey(f.Severity)] += 1;
      var g = groupLabel(f);
      if (!groups[g]) { groups[g] = { label: g, rows: [], rank: 4 }; groupOrder.push(g); }
      groups[g].rows.push(f);
      var r = sevRank(f.Severity);
      if (r < groups[g].rank) { groups[g].rank = r; }
    });
    groupOrder.sort(function (a, b) {
      var r = groups[a].rank - groups[b].rank;
      if (r !== 0) { return r; }
      r = groups[b].rows.length - groups[a].rows.length;
      return r !== 0 ? r : (a < b ? -1 : 1);
    });
    return {
      name: name,
      host: String(data.Host || ''),
      mode: String(data.Mode || ''),
      window: String(data.TimeWindow || ''),
      timestamp: String(data.Timestamp || ''),
      riskScore: Number(data.RiskScore) || 0,
      riskLabel: String(data.RiskLabel || ''),
      recovered: Object.prototype.toString.call(data.RecoveredErrors) === '[object Array]' ? data.RecoveredErrors.length : 0,
      real: real,
      caps: caps,
      counts: counts,
      groups: groups,
      groupOrder: groupOrder
    };
  }

  // ------------------------------------------------------------------ state ----

  var state = {
    files: [],
    active: 0,
    view: 'group',           // 'group' | 'flat'
    q: '',
    sevs: { CRITICAL: true, HIGH: true, POSSIBLE: true, INFO: true, OTHER: true },
    group: '',
    page: 1,
    open: {}                 // group label -> true (lazy row rendering)
  };

  function byId(id) { return document.getElementById(id); }

  // ------------------------------------------------------------------ fragment (deep link) ----
  // The fragment is untrusted input: whitelist keys, whitelist enum values, cap lengths,
  // and never let a parse failure break the page. Values only ever feed filters and are
  // escaped like any other data on the way back into markup.

  function readFragment() {
    var out = {};
    try {
      var raw = String(window.location.hash || '').replace(/^#/, '');
      if (raw.length > 2000) { return out; }
      raw.split('&').forEach(function (pair) {
        var i = pair.indexOf('=');
        if (i < 1) { return; }
        var k = decodeURIComponent(pair.slice(0, i));
        var v = decodeURIComponent(pair.slice(i + 1));
        if (k === 'q' || k === 'group') { out[k] = v.slice(0, 200); }
        else if (k === 'view' && (v === 'flat' || v === 'group')) { out.view = v; }
        else if (k === 'page') {
          var n = parseInt(v, 10);
          if (isFinite(n) && n >= 1 && n <= 9999) { out.page = n; }
        }
        else if (k === 'sev') {
          var chosen = {};
          v.split(',').forEach(function (s) {
            if (SEV_KEYS.indexOf(s) !== -1) { chosen[s] = true; }
          });
          if (Object.keys(chosen).length > 0) { out.sev = chosen; }
        }
      });
    }
    catch (e) { return {}; }
    return out;
  }

  function applyFragment() {
    var f = readFragment();
    if (f.q !== undefined) { state.q = f.q; }
    if (f.group !== undefined) { state.group = f.group; }
    if (f.view) { state.view = f.view; }
    if (f.page) { state.page = f.page; }
    if (f.sev) {
      SEV_KEYS.forEach(function (k) { state.sevs[k] = !!f.sev[k]; });
    }
  }

  function writeFragment() {
    var parts = [];
    if (state.q) { parts.push('q=' + encodeURIComponent(state.q)); }
    var offSevs = SEV_KEYS.filter(function (k) { return !state.sevs[k]; });
    if (offSevs.length > 0) {
      parts.push('sev=' + SEV_KEYS.filter(function (k) { return state.sevs[k]; }).map(encodeURIComponent).join(','));
    }
    if (state.group) { parts.push('group=' + encodeURIComponent(state.group)); }
    if (state.view !== 'group') { parts.push('view=' + encodeURIComponent(state.view)); }
    if (state.page > 1) { parts.push('page=' + state.page); }
    try {
      window.history.replaceState(null, '', parts.length ? '#' + parts.join('&') : '#');
    }
    catch (e) { /* history API unavailable: the deep link is a convenience, not a dependency */ }
  }

  // ------------------------------------------------------------------ filtering ----

  function rowMatches(f) {
    if (!state.sevs[sevKey(f.Severity)]) { return false; }
    if (state.group && groupLabel(f) !== state.group) { return false; }
    if (state.q) {
      var hay = (String(f.ID || '') + ' ' + String(f.Phase || '') + ' ' + String(f.Description || '') + ' ' +
        String(f.Target || '') + ' ' + String(f.ThreatType || '') + ' ' + groupLabel(f)).toLowerCase();
      if (hay.indexOf(state.q.toLowerCase()) === -1) { return false; }
    }
    return true;
  }

  function filteredRows() {
    var file = state.files[state.active];
    if (!file) { return []; }
    return file.real.filter(rowMatches);
  }

  // ------------------------------------------------------------------ rendering ----

  function sevBadgeHtml(sevText) {
    var key = sevKey(sevText).toLowerCase();
    var shown = String(sevText || 'UNSET');
    return '<span class="vw-badge sev-' + escHtml(key) + '">' + escHtml(shown) + '</span>';
  }

  function rowHtml(f) {
    var action = String(f.FixAction || '');
    if (f.FixParam) { action += ' (' + String(f.FixParam) + ')'; }
    return '<tr>' +
      '<td>' + sevBadgeHtml(f.Severity) + '</td>' +
      '<td><code>' + escHtml(f.ID) + '</code></td>' +
      '<td>' + escHtml(f.Phase) + '</td>' +
      '<td>' + escHtml(f.Description) + '</td>' +
      '<td><code>' + escHtml(f.Target) + '</code></td>' +
      '<td>' + escHtml(action) + '</td>' +
      '</tr>';
  }

  function renderSummaries() {
    var el = byId('summaries');
    el.innerHTML = state.files.map(function (file) {
      return '<article class="vw-card">' +
        '<h3>' + escHtml(file.name) + '</h3>' +
        '<dl>' +
        '<dt>Machine</dt><dd>' + escHtml(file.host) + '</dd>' +
        '<dt>Mode</dt><dd>' + escHtml(file.mode) + '</dd>' +
        '<dt>Window</dt><dd>' + escHtml(file.window) + '</dd>' +
        '<dt>Run</dt><dd>' + escHtml(file.timestamp) + '</dd>' +
        '<dt>Risk</dt><dd>' + escHtml(String(file.riskScore)) + (file.riskLabel ? ' — ' + escHtml(file.riskLabel) : '') + '</dd>' +
        '<dt>Recovered errors</dt><dd>' + escHtml(String(file.recovered)) + '</dd>' +
        '</dl>' +
        '<div class="vw-counts">' + SEV_KEYS.map(function (k) {
          return sevBadgeHtml(k) + ' ' + escHtml(String(file.counts[k]));
        }).join(' ') + '</div>' +
        '</article>';
    }).join('');
  }

  function renderTabs() {
    var el = byId('tabs');
    if (state.files.length < 2) { el.innerHTML = ''; return; }
    el.innerHTML = state.files.map(function (file, i) {
      return '<button type="button" role="tab" data-tab="' + escHtml(String(i)) + '" aria-selected="' +
        (i === state.active ? 'true' : 'false') + '">' + escHtml(file.name) + '</button>';
    }).join('');
  }

  function renderCapNote() {
    var el = byId('capNote');
    var file = state.files[state.active];
    if (!file || file.caps.length === 0) { el.hidden = true; return; }
    el.hidden = false;
    el.innerHTML = '<strong>Rows were suppressed at scan time.</strong> ' +
      escHtml(String(file.caps.length)) + ' group(s) hit the flood cap; counts below are floors, not totals: ' +
      file.caps.map(function (c) { return escHtml(c.Description || c.ID); }).join(' — ');
  }

  function renderChips() {
    var el = byId('sevChips');
    var file = state.files[state.active];
    var visible = SEV_KEYS.filter(function (k) { return k !== 'OTHER' || (file && file.counts.OTHER > 0); });
    el.innerHTML = visible.map(function (k) {
      return '<label class="vw-chip"><input type="checkbox" data-sev="' + escHtml(k) + '"' +
        (state.sevs[k] ? ' checked' : '') + '> ' + escHtml(k) +
        ' <b>' + escHtml(String(file ? file.counts[k] : 0)) + '</b></label>';
    }).join('');
  }

  function renderGroupSelect() {
    var sel = byId('groupSel');
    var file = state.files[state.active];
    while (sel.options.length > 1) { sel.remove(1); }
    if (!file) { return; }
    file.groupOrder.forEach(function (g) {
      var opt = document.createElement('option');
      opt.value = g;
      opt.textContent = g + ' (' + file.groups[g].rows.length + ')';
      sel.appendChild(opt);
    });
    sel.value = state.group;
    if (sel.value !== state.group) { state.group = ''; sel.value = ''; }
  }

  function renderTable() {
    var tbody = byId('tbody');
    var pager = byId('pager');
    var file = state.files[state.active];
    if (!file) { tbody.innerHTML = ''; pager.innerHTML = ''; return; }

    if (state.view === 'group') {
      // Group-collapsed mode: only group header rows exist until a group is opened, so a
      // 1,200-row record never builds 1,200 DOM rows up front.
      var parts = [];
      file.groupOrder.forEach(function (g) {
        var rows = file.groups[g].rows.filter(rowMatches);
        if (rows.length === 0) { return; }
        var isOpen = !!state.open[g];
        parts.push('<tr class="vw-ghead"><td colspan="6"><button type="button" data-group="' + escHtml(g) +
          '" aria-expanded="' + (isOpen ? 'true' : 'false') + '">' + (isOpen ? '▾ ' : '▸ ') + escHtml(g) +
          ' <span class="vw-gcount">' + escHtml(String(rows.length)) + ' shown</span></button></td></tr>');
        if (isOpen) { parts.push(rows.map(rowHtml).join('')); }
      });
      tbody.innerHTML = parts.length ? parts.join('') : '<tr class="vw-empty"><td colspan="6">' + escHtml('No findings match the current filters.') + '</td></tr>';
      pager.innerHTML = '';
      return;
    }

    var all = filteredRows();
    var pages = Math.max(1, Math.ceil(all.length / PAGE_SIZE));
    if (state.page > pages) { state.page = pages; }
    var slice = all.slice((state.page - 1) * PAGE_SIZE, state.page * PAGE_SIZE);
    tbody.innerHTML = slice.length ? slice.map(rowHtml).join('') : '<tr class="vw-empty"><td colspan="6">' + escHtml('No findings match the current filters.') + '</td></tr>';
    pager.innerHTML = '<button type="button" data-page="prev"' + (state.page <= 1 ? ' disabled' : '') + '>' + escHtml('Previous') + '</button>' +
      '<span>page ' + escHtml(String(state.page)) + ' of ' + escHtml(String(pages)) + ' — ' + escHtml(String(all.length)) + ' finding(s)</span>' +
      '<button type="button" data-page="next"' + (state.page >= pages ? ' disabled' : '') + '>' + escHtml('Next') + '</button>';
  }

  function renderComparison() {
    var el = byId('cmp');
    if (state.files.length !== 2) { el.hidden = true; return; }
    el.hidden = false;
    var older = state.files[0];
    var newer = state.files[1];
    var LIST_CAP = 200;

    var oldIds = {};
    older.real.forEach(function (f) { oldIds[String(f.ID || '')] = true; });
    var newIds = {};
    newer.real.forEach(function (f) { newIds[String(f.ID || '')] = true; });
    var added = newer.real.filter(function (f) { return !oldIds[String(f.ID || '')]; });
    var resolved = older.real.filter(function (f) { return !newIds[String(f.ID || '')]; });
    var persisting = newer.real.length - added.length;

    function listHtml(rows) {
      var shown = rows.slice(0, LIST_CAP);
      var html = '<table class="vw-tbl"><thead><tr><th>Severity</th><th>ID</th><th>Description</th></tr></thead><tbody>' +
        shown.map(function (f) {
          return '<tr><td>' + sevBadgeHtml(f.Severity) + '</td><td><code>' + escHtml(f.ID) + '</code></td><td>' + escHtml(f.Description) + '</td></tr>';
        }).join('') + '</tbody></table>';
      if (rows.length > LIST_CAP) {
        html += '<p class="vw-sub">' + escHtml('Showing the first ' + LIST_CAP + ' of ' + rows.length + '. Export CSV for the full list.') + '</p>';
      }
      return html;
    }

    el.innerHTML = '<h2>' + escHtml('What changed: ' + older.name + ' → ' + newer.name) + '</h2>' +
      '<p>' + escHtml(resolved.length + ' resolved, ' + added.length + ' new, ' + persisting + ' present in both (joined on ID; flood-cap markers excluded).') + '</p>' +
      '<h3>' + escHtml('Resolved (' + resolved.length + ')') + '</h3>' + (resolved.length ? listHtml(resolved) : '<p class="vw-sub">' + escHtml('Nothing has cleared.') + '</p>') +
      '<h3>' + escHtml('New (' + added.length + ')') + '</h3>' + (added.length ? listHtml(added) : '<p class="vw-sub">' + escHtml('Nothing new.') + '</p>');
  }

  function renderAll() {
    if (state.files.length === 0) { return; }
    byId('app').hidden = false;
    renderSummaries();
    renderTabs();
    renderCapNote();
    renderChips();
    renderGroupSelect();
    renderTable();
    renderComparison();
    byId('viewToggle').textContent = state.view === 'group' ? 'View: groups' : 'View: flat list';
    byId('viewToggle').setAttribute('aria-pressed', state.view === 'group' ? 'true' : 'false');
    byId('q').value = state.q;
    writeFragment();
  }

  // ------------------------------------------------------------------ loading ----

  function showError(message) {
    var el = byId('loadError');
    el.hidden = !message;
    el.textContent = message || '';
  }

  function loadFiles(fileList) {
    var files = Array.prototype.slice.call(fileList || []);
    if (files.length === 0) { return; }
    showError('');
    var pending = files.length;
    var loaded = [];
    var errors = [];
    files.forEach(function (f) {
      var reader = new FileReader();
      reader.onload = function () {
        try { loaded.push(parseRecord(f.name, String(reader.result))); }
        catch (e) { errors.push(e && e.message ? e.message : (f.name + ': unreadable')); }
        if (--pending === 0) { finish(); }
      };
      reader.onerror = function () {
        errors.push(f.name + ': could not be read');
        if (--pending === 0) { finish(); }
      };
      reader.readAsText(f);
    });
    function finish() {
      if (errors.length > 0) { showError(errors.join(' | ')); }
      if (loaded.length === 0) { return; }
      state.files = state.files.concat(loaded);
      // Oldest first: with two files the comparison reads older -> newer. ISO timestamps
      // sort lexically; missing ones sort first and the comparison header names both files.
      state.files.sort(function (a, b) { return a.timestamp < b.timestamp ? -1 : 1; });
      state.active = state.files.length - 1;
      state.open = {};
      state.page = 1;
      renderAll();
    }
  }

  // ------------------------------------------------------------------ events ----

  function bind() {
    var drop = byId('drop');
    byId('fileInput').addEventListener('change', function (e) { loadFiles(e.target.files); e.target.value = ''; });
    ['dragover', 'dragenter'].forEach(function (type) {
      drop.addEventListener(type, function (e) { e.preventDefault(); drop.classList.add('vw-over'); });
    });
    ['dragleave', 'drop'].forEach(function (type) {
      drop.addEventListener(type, function (e) { e.preventDefault(); drop.classList.remove('vw-over'); });
    });
    drop.addEventListener('drop', function (e) {
      if (e.dataTransfer && e.dataTransfer.files) { loadFiles(e.dataTransfer.files); }
    });

    var qTimer = null;
    byId('q').addEventListener('input', function (e) {
      if (qTimer) { clearTimeout(qTimer); }
      qTimer = setTimeout(function () {
        state.q = String(e.target.value || '').slice(0, 200);
        state.page = 1;
        renderTable(); renderComparison(); writeFragment();
      }, 150);
    });

    byId('sevChips').addEventListener('change', function (e) {
      var k = e.target && e.target.getAttribute('data-sev');
      if (k && SEV_KEYS.indexOf(k) !== -1) {
        state.sevs[k] = !!e.target.checked;
        state.page = 1;
        renderTable(); writeFragment();
      }
    });

    byId('groupSel').addEventListener('change', function (e) {
      state.group = String(e.target.value || '');
      state.page = 1;
      renderTable(); writeFragment();
    });

    byId('viewToggle').addEventListener('click', function () {
      state.view = state.view === 'group' ? 'flat' : 'group';
      state.page = 1;
      renderAll();
    });

    byId('tbody').addEventListener('click', function (e) {
      var btn = e.target && e.target.closest ? e.target.closest('button[data-group]') : null;
      if (btn) {
        var g = btn.getAttribute('data-group');
        state.open[g] = !state.open[g];
        renderTable();
      }
    });

    byId('pager').addEventListener('click', function (e) {
      var dir = e.target && e.target.getAttribute('data-page');
      if (dir === 'prev' && state.page > 1) { state.page -= 1; renderTable(); writeFragment(); }
      if (dir === 'next') { state.page += 1; renderTable(); writeFragment(); }
    });

    byId('tabs').addEventListener('click', function (e) {
      var idx = e.target && e.target.getAttribute('data-tab');
      if (idx !== null && idx !== undefined && state.files[Number(idx)]) {
        state.active = Number(idx);
        state.open = {};
        state.page = 1;
        renderAll();
      }
    });

    byId('csvBtn').addEventListener('click', function () {
      var rows = filteredRows();
      var cols = ['ID', 'Severity', 'Phase', 'Group', 'ThreatType', 'Description', 'Target', 'FixAction', 'FixParam', 'Timestamp'];
      var lines = [cols.map(csvCell).join(',')];
      rows.forEach(function (f) {
        lines.push(cols.map(function (c) { return csvCell(f[c]); }).join(','));
      });
      var blob = new Blob([lines.join('\r\n')], { type: 'text/csv' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'scythe_findings_filtered.csv';
      document.body.appendChild(a);
      a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    });

    window.addEventListener('hashchange', function () {
      applyFragment();
      renderAll();
    });
  }

  applyFragment();
  bind();
})();
