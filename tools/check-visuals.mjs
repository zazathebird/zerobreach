#!/usr/bin/env node
// ZeroBreach VFX checker — drives Chrome/Edge over the DevTools Protocol against
// gui/static/fx-preview.html (which loads the REAL themes.js / fx.js).
//   node tools/check-visuals.mjs          → run the self-test audit + capture a gallery, print PASS/FAIL
//   node tools/check-visuals.mjs --open   → just open the interactive harness in your browser
// No npm deps: uses Node's global fetch + WebSocket (Node 22+) and a temp browser profile.
import { execFile, spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const PAGE = join(ROOT, 'gui', 'static', 'fx-preview.html');
const OUT  = join(ROOT, 'fx-audit');
const PROF = join(tmpdir(), 'zb-vfx-profile');

const CANDIDATES = [
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
];
const BROWSER = CANDIDATES.find(existsSync);
if (!BROWSER) { console.error('No Chrome/Edge found.'); process.exit(2); }
if (!existsSync(PAGE)) { console.error('Missing harness:', PAGE); process.exit(2); }

const url = (q) => pathToFileURL(PAGE).href + (q ? '?' + q : '');
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

if (process.argv.includes('--open')) {
  console.log('Opening interactive harness:', url());
  execFile(BROWSER, ['--new-window', url()]);
  process.exit(0);
}

const THEMES = ['kraken-blue','gannon-orange','threat-red','ghost-green','wopr','outrun','overwatch','blacksite','kraken'];
const VIEWS  = ['launchpad','scanmonitor','findings','remediation','report','ioc','settings'];

// ── minimal CDP client over one WebSocket ──
class CDP {
  constructor(ws) { this.ws = ws; this.id = 0; this.pending = new Map(); this.handlers = new Map();
    ws.addEventListener('message', (e) => {
      const m = JSON.parse(e.data);
      if (m.id && this.pending.has(m.id)) {
        const { resolve, reject } = this.pending.get(m.id); this.pending.delete(m.id);
        m.error ? reject(new Error(m.error.message)) : resolve(m.result);
      } else if (m.method && this.handlers.has(m.method)) this.handlers.get(m.method)(m.params);
    });
  }
  send(method, params = {}) { const id = ++this.id;
    return new Promise((resolve, reject) => { this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params })); });
  }
  on(method, fn) { this.handlers.set(method, fn); }
}

async function navigate(cdp, target) {
  let loaded; const p = new Promise(r => { loaded = r; });
  cdp.on('Page.loadEventFired', () => loaded());
  await cdp.send('Page.navigate', { url: target });
  await Promise.race([p, sleep(8000)]);
  await sleep(150);
}
async function evaluate(cdp, expression, awaitPromise = false) {
  const r = await cdp.send('Runtime.evaluate', { expression, awaitPromise, returnByValue: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || 'eval error');
  return r.result.value;
}
async function screenshot(cdp, file) {
  const { data } = await cdp.send('Page.captureScreenshot', { format: 'png' });
  writeFileSync(file, Buffer.from(data, 'base64'));
}

async function main() {
  mkdirSync(OUT, { recursive: true });
  rmSync(PROF, { recursive: true, force: true });

  console.log('Browser :', BROWSER);
  console.log('Harness :', PAGE, '\n');

  const child = spawn(BROWSER, [
    '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    `--user-data-dir=${PROF}`, '--window-size=1366,800', '--remote-debugging-port=0',
    '--remote-allow-origins=*', 'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });

  // discover the chosen debugging port from DevToolsActivePort
  const portFile = join(PROF, 'DevToolsActivePort');
  let port = 0;
  for (let i = 0; i < 100 && !port; i++) {
    await sleep(100);
    if (existsSync(portFile)) port = parseInt(readFileSync(portFile, 'utf8').split('\n')[0], 10);
  }
  if (!port) { child.kill(); throw new Error('browser did not expose a debugging port'); }

  // open a tab and connect
  const tab = await (await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent('about:blank')}`, { method: 'PUT' })).json();
  const ws = new WebSocket(tab.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.addEventListener('open', res); ws.addEventListener('error', rej); });
  const cdp = new CDP(ws);
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');

  let exitCode = 2;
  try {
    // 1) self-test audit
    console.log('Running self-test audit …');
    await navigate(cdp, url('audit=1'));
    const a = await evaluate(cdp, 'window.__auditPromise', true);
    await screenshot(cdp, join(OUT, 'AUDIT_REPORT.png'));
    if (!a) throw new Error('audit produced no result');

    console.log(`\n  Themes : ${a.themes.pass}/${a.themes.total}`);
    for (const r of a.themeRows)
      console.log(`    ${r.pass ? 'PASS' : 'FAIL'}  ${r.name.padEnd(16)} lit ${String(r.paint).padStart(6)}%  Δ ${String(r.anim).padStart(6)}%  ${r.why || ''}`);
    console.log(`\n  Views  : ${a.views.pass}/${a.views.total}`);
    for (const r of a.viewRows)
      console.log(`    ${r.pass ? 'PASS' : 'FAIL'}  ${r.view.padEnd(14)} opacity ${r.active}  ${r.why || ''}`);
    console.log(`\n  OFF hides per-view layer: ${a.offHidesLayer ? 'YES' : 'NO'}`);

    // 2) eyeball gallery
    console.log('\nCapturing gallery …');
    for (const t of THEMES) { await navigate(cdp, url(`theme=${t}&view=launchpad&fx=full`)); await sleep(500); await screenshot(cdp, join(OUT, 'theme__' + t + '.png')); process.stdout.write('.'); }
    for (const v of VIEWS)  { await navigate(cdp, url(`theme=kraken-blue&view=${v}&fx=full`)); await sleep(500); await screenshot(cdp, join(OUT, 'view__' + v + '.png')); process.stdout.write('.'); }
    console.log('\n');

    console.log(`VERDICT: ${a.verdict}`);
    console.log(`Gallery + AUDIT_REPORT.png in: ${OUT}`);
    exitCode = a.verdict === 'PASS' ? 0 : 1;
  } finally {
    try { ws.close(); } catch {}
    child.kill();
  }
  process.exit(exitCode);
}

main().catch(e => { console.error('Runner error:', e.message); process.exit(2); });
