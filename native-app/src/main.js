import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

const statusEl = document.getElementById('status');
const errEl = document.getElementById('err');

function showError(msg) {
  statusEl.textContent = 'failed to start the local engine';
  errEl.style.display = 'block';
  errEl.textContent = msg;
}

// The Rust side spawns ZeroBreach-Server.ps1 in the app's setup hook and emits
// 'zerobreach://server-ready' with the actual URL once the HTTP listener responds.
// Navigating the WHOLE window (not an iframe) to that URL hands off to the existing,
// already-proven gui/templates/index.html + app.js — this shell's only job is to get
// a native window open and the local server running behind it, nothing more.
listen('zerobreach://server-ready', (event) => {
  statusEl.textContent = 'engine ready — loading console…';
  window.location.replace(event.payload);
});

listen('zerobreach://server-error', (event) => {
  showError(String(event.payload));
});

listen('zerobreach://server-status', (event) => {
  statusEl.textContent = String(event.payload);
});

// In case the setup hook already finished before this listener attached (window
// reload, etc.), ask once directly too.
invoke('get_server_status')
  .then((s) => {
    if (s && s.ready && s.url) window.location.replace(s.url);
    else if (s && s.error) showError(s.error);
  })
  .catch(() => {});
