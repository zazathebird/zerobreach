/* ═══════════════════════════════════════════════════════════════════════════
   ZEROBREACH — THE KRAKEN UNLOCK CINEMATIC
   Typing "kraken" summons a ~19s full-screen set piece:
     0 TARGET LOCK   — your typed word gets signature-locked
     1 INTRUSION     — klaxon, RGB-split glitch, the console is breached
     2 DECRYPT       — cipher wall, 12 blocks crack one by one
     3 SHATTER       — flashbang; the screen breaks into glass shards
     4 DESCENT       — sink 11,034m through real ocean zones, sonar pinging
     5 CONTACT       — biomass incalculable; eyes open; tentacles; ROAR
     6 HANDSHAKE     — the kraken doesn't attack. It interfaces. Neural veins.
     7 REBIRTH       — THE ABYSS ACCEPTS YOU. Console reborn in KRAKEN theme.
   Click or ESC skips straight to the unlock. All audio synthesized (ZBSound).
   ═══════════════════════════════════════════════════════════════════════════ */
'use strict';

const ZBKraken = (() => {
  let running = false, finished = false;
  let ov, cv, ctx, bg, flash, els = {};
  let w = 0, h = 0, raf = 0, t0 = 0;
  let shards = [], cracks = [], bubbles = [], rings = [], tents = [], veins = [], maxDepthV = 1;
  const HEX = '0123456789ABCDEF';
  const snd = n => window.ZBSound && ZBSound.play(n);
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const ez = p => 1 - Math.pow(1 - p, 3);                       // ease-out cubic
  const ezio = p => p < .5 ? 4 * p * p * p : 1 - Math.pow(-2 * p + 2, 3) / 2;

  // ── timeline anchors (ms) ──
  const T = { INTRUDE: 1400, DECRYPT: 3200, SHATTER: 6600, DESCENT: 8400, CONTACT: 11600, ROAR: 12300, SHAKE: 14400, REBIRTH: 17400, END: 19600 };

  function build() {
    ov = document.createElement('div'); ov.id = 'kraken-cinematic';
    ov.innerHTML =
      '<div class="kr-bg"></div><canvas class="kr-cv"></canvas><div class="kr-flash"></div>' +
      '<div class="kr-ghost"></div><div class="kr-sig"></div>' +
      '<div class="kr-warn">&#9888; CLASSIFIED PROTOCOL DETECTED</div>' +
      '<div class="kr-dec"><div class="kr-dec-title">DECRYPTING ABYSSAL PROTOCOL</div><div class="kr-blocks"></div><div class="kr-pct">0%</div></div>' +
      '<div class="kr-depth"><div class="kr-depth-num">0</div><div class="kr-depth-m">METERS</div><div class="kr-zone">SUNLIGHT ZONE</div><div class="kr-press">PRESSURE: 1 ATM</div></div>' +
      '<div class="kr-contact">CONTACT // BIOMASS: INCALCULABLE</div>' +
      '<div class="kr-hand"></div>' +
      '<div class="kr-final"><div class="kr-final-title"></div><div class="kr-final-sub">GOD MODE &mdash; ABYSSAL PROTOCOL ENGAGED</div></div>' +
      '<div class="kr-skip">CLICK OR ESC TO SKIP</div>';
    document.body.appendChild(ov);
    bg = ov.querySelector('.kr-bg'); cv = ov.querySelector('.kr-cv'); flash = ov.querySelector('.kr-flash');
    ['ghost', 'sig', 'warn', 'dec', 'depth', 'contact', 'hand', 'final', 'skip'].forEach(k => els[k] = ov.querySelector('.kr-' + k));
    els.blocks = ov.querySelector('.kr-blocks'); els.pct = ov.querySelector('.kr-pct');
    els.dnum = ov.querySelector('.kr-depth-num'); els.zone = ov.querySelector('.kr-zone'); els.press = ov.querySelector('.kr-press');
    els.ftitle = ov.querySelector('.kr-final-title');
    for (let i = 0; i < 12; i++) { const b = document.createElement('span'); b.className = 'kr-blk'; b.textContent = hex4(); els.blocks.appendChild(b); }
    ctx = cv.getContext('2d');
    resize(); window.addEventListener('resize', resize);
  }
  function hex4() { let s = ''; for (let i = 0; i < 4; i++) s += HEX[(Math.random() * 16) | 0]; return s; }
  function resize() { w = window.innerWidth; h = window.innerHeight; cv.width = w; cv.height = h; }
  function show(el, on) { if (el) el.style.opacity = on ? 1 : 0; }

  // ── one-shot events ──
  function buildEvents() {
    const locks = [];           // 12 cipher blocks lock on an accelerating curve
    for (let i = 0; i < 12; i++) locks.push({ at: T.DECRYPT + 400 + 2700 * (1 - Math.pow(1 - (i + 1) / 12, 2)), fn: () => lockBlock(i) });
    return [
      { at: 0,    fn: () => { snd('lock'); show(els.ghost, 1); show(els.skip, 1); } },
      { at: 250,  fn: () => snd('tick') }, { at: 500, fn: () => snd('tick') }, { at: 750, fn: () => snd('tick') },
      { at: 900,  fn: () => { show(els.sig, 1); els.sig.textContent = 'SIGNATURE ACCEPTED // ABYSSAL CLEARANCE α-0'; snd('confirm'); } },
      { at: T.INTRUDE,        fn: () => { show(els.ghost, 0); show(els.sig, 0); show(els.warn, 1); ov.classList.add('kr-red'); snd('klaxon'); window.ZBFX && ZBFX.shake('hard', 700); } },
      { at: T.INTRUDE + 300,  fn: () => snd('glitch') },
      { at: T.INTRUDE + 900,  fn: () => { snd('glitch'); window.ZBFX && ZBFX.shake('med', 400); } },
      { at: T.DECRYPT,        fn: () => { show(els.warn, 0); ov.classList.remove('kr-red'); bg.style.opacity = .92; show(els.dec, 1); snd('open'); } },
      ...locks,
      { at: T.SHATTER - 300,  fn: () => snd('danger') },
      { at: T.SHATTER,        fn: () => { show(els.dec, 0); doFlash(); snd('flashbang'); snd('shatter'); makeCracks(); window.ZBFX && ZBFX.shake('hard', 800); } },
      { at: T.SHATTER + 480,  fn: () => { bg.style.opacity = 1; makeShards(); } },
      { at: T.DESCENT,        fn: () => { snd('splash'); snd('descend'); show(els.depth, 1); makeBubbles(); } },
      { at: T.DESCENT + 800,  fn: () => ping() }, { at: T.DESCENT + 1800, fn: () => ping() }, { at: T.DESCENT + 2600, fn: () => ping() },
      { at: T.CONTACT - 900,  fn: () => snd('heartbeat') }, { at: T.CONTACT - 300, fn: () => snd('heartbeat') },
      { at: T.CONTACT,        fn: () => { show(els.depth, 0); show(els.contact, 1); snd('alert'); makeTentacles(); } },
      { at: T.ROAR,           fn: () => { snd('kraken'); window.ZBFX && ZBFX.shake('hard', 1200); rings.push({ t: 0 }); } },
      { at: T.ROAR + 900,     fn: () => snd('heartbeat') },
      { at: T.SHAKE,          fn: () => { show(els.contact, 0); makeVeins(); snd('surge'); show(els.hand, 1); els.hand.innerHTML = 'NEURAL HANDSHAKE: LEVIATHAN &#8652; OPERATOR'; } },
      { at: T.SHAKE + 1700,   fn: () => { els.hand.innerHTML = 'THE ABYSS ACCEPTS YOU.'; snd('confirm'); } },
      { at: T.REBIRTH,        fn: () => { show(els.hand, 0); unlock(); show(els.final, 1); snd('complete'); window.ZBFX && ZBFX.decrypt(els.ftitle, 'K R A K E N', 1300); bg.style.transition = 'opacity 1.8s'; bg.style.opacity = 0; } },
      { at: T.END,            fn: () => finish() },
    ];
  }
  function doFlash() { flash.style.transition = 'none'; flash.style.opacity = 1; requestAnimationFrame(() => requestAnimationFrame(() => { flash.style.transition = 'opacity .9s'; flash.style.opacity = 0; })); }
  function lockBlock(i) { const b = els.blocks.children[i]; if (!b) return; b.classList.add('locked'); snd('thunk'); window.ZBFX && ZBFX.shake('low', 180); els.pct.textContent = Math.round(((i + 1) / 12) * 100) + '%'; }
  function ping() { rings.push({ t: 0, sonar: 1 }); snd('sonar'); }

  // ── scene element generators ──
  function makeCracks() {
    cracks = [];
    const cx = w / 2, cy = h / 2;
    for (let i = 0; i < 26; i++) {
      const a = (i / 26) * Math.PI * 2 + Math.random() * .3;
      let x = cx, y = cy, seg = [[x, y]];
      const len = Math.max(w, h) * (0.5 + Math.random() * 0.4);
      const steps = 9 + (Math.random() * 5 | 0);
      for (let s = 1; s <= steps; s++) {
        const r = (s / steps) * len, j = (Math.random() - .5) * 60;
        seg.push([cx + Math.cos(a) * r + Math.cos(a + 1.57) * j, cy + Math.sin(a) * r + Math.sin(a + 1.57) * j]);
      }
      cracks.push(seg);
    }
  }
  function makeShards() {
    shards = [];
    const cx = w / 2, cy = h / 2;
    for (let ring = 0; ring < 5; ring++) for (let i = 0; i < 14; i++) {
      const a = (i / 14) * Math.PI * 2 + ring * .22 + Math.random() * .2;
      const r0 = ring * Math.min(w, h) * .12 + 20;
      const p = [cx + Math.cos(a) * r0, cy + Math.sin(a) * r0];
      const verts = [];
      for (let v = 0; v < 3; v++) { const va = a + v * 2.1 + Math.random(); const vr = 30 + Math.random() * 90; verts.push([Math.cos(va) * vr, Math.sin(va) * vr]); }
      shards.push({ x: p[0], y: p[1], vx: Math.cos(a) * (3 + Math.random() * 7), vy: Math.sin(a) * (3 + Math.random() * 7) + 1, rot: Math.random() * 6, vr: (Math.random() - .5) * .25, verts, a: 1 });
    }
  }
  function makeBubbles() { bubbles = Array.from({ length: 70 }, () => ({ x: Math.random() * w, y: h + Math.random() * h, r: 1 + Math.random() * 4, v: 1.5 + Math.random() * 3.5 })); }
  function makeTentacles() {
    tents = [];
    const edges = [[0, .3], [0, .75], [1, .25], [1, .7], [.3, 1], [.72, 1]];
    edges.forEach((e, i) => {
      const bx = e[0] === 0 ? -60 : e[0] === 1 ? w + 60 : e[0] * w;
      const by = e[1] === 1 ? h + 60 : e[1] * h;
      tents.push({ bx, by, tx: w * (.32 + Math.random() * .36), ty: h * (.3 + Math.random() * .4), ph: i * 1.3, born: performance.now() });
    });
  }
  function makeVeins() {
    veins = []; maxDepthV = 8;
    const grow = (x, y, ang, depth) => {
      if (depth > maxDepthV || veins.length > 2600) return;   // hard cap — keeps old GPUs smooth
      const n = depth < 2 ? 3 : (Math.random() < .5 ? 2 : 1);
      for (let i = 0; i < n; i++) {
        const a2 = ang + (Math.PI / 4) * ((Math.random() * 3 | 0) - 1);
        const len = 28 + Math.random() * 70;
        const x2 = x + Math.cos(a2) * len, y2 = y + Math.sin(a2) * len;
        veins.push({ x1: x, y1: y, x2, y2, d: depth });
        grow(x2, y2, a2, depth + 1);
      }
    };
    for (let k = 0; k < 6; k++) grow(w / 2, h / 2, (k / 6) * Math.PI * 2, 0);
  }

  // ── per-frame scene rendering ──
  function frame(now) {
    raf = requestAnimationFrame(frame);
    const t = now - t0;
    while (events.length && t >= events[0].at) events.shift().fn();
    ctx.clearRect(0, 0, w, h);
    const cs = getComputedStyle(document.body);
    const AC = cs.getPropertyValue('--accent').trim() || '#19FFD0';

    if (t < T.INTRUDE) {                                   // ACT 0 — target lock
      const p = ez(clamp(t / 900, 0, 1));
      const bw = 460 * (2 - p), bh = 160 * (2 - p), cx = w / 2, cy = h / 2 - 20, L = 26;
      ctx.strokeStyle = AC; ctx.lineWidth = 2; ctx.shadowColor = AC; ctx.shadowBlur = 10; ctx.globalAlpha = p;
      [[-1, -1], [1, -1], [-1, 1], [1, 1]].forEach(c => {
        const x = cx + c[0] * bw / 2, y = cy + c[1] * bh / 2;
        ctx.beginPath(); ctx.moveTo(x, y + c[1] * -L); ctx.lineTo(x, y); ctx.lineTo(x + c[0] * -L, y); ctx.stroke();
      });
      ctx.globalAlpha = 1; ctx.shadowBlur = 0;
    } else if (t < T.DECRYPT) {                            // ACT 1 — glitch slices
      if (Math.random() < .65) for (let i = 0; i < 7; i++) {
        const y = Math.random() * h, sh = 4 + Math.random() * 26, off = (Math.random() - .5) * 90;
        ctx.fillStyle = i % 2 ? 'rgba(255,0,51,.16)' : 'rgba(0,212,255,.13)';
        ctx.fillRect(off, y, w, sh);
      }
    } else if (t < T.SHATTER) {                            // ACT 2 — cipher rain
      ctx.font = '13px "JetBrains Mono",monospace'; ctx.fillStyle = AC; ctx.globalAlpha = .14;
      for (let i = 0; i < 60; i++) ctx.fillText(hex4(), Math.random() * w, Math.random() * h);
      ctx.globalAlpha = 1;
    } else if (t < T.DESCENT) {                            // ACT 3 — cracks + shards
      const cp = clamp((t - T.SHATTER) / 480, 0, 1);
      if (cp < 1) {
        ctx.strokeStyle = 'rgba(230,255,250,.85)'; ctx.lineWidth = 1.2; ctx.shadowColor = AC; ctx.shadowBlur = 6;
        cracks.forEach(seg => {
          const n = Math.max(2, Math.floor(seg.length * cp));
          ctx.beginPath(); ctx.moveTo(seg[0][0], seg[0][1]);
          for (let i = 1; i < n; i++) ctx.lineTo(seg[i][0], seg[i][1]);
          ctx.stroke();
        });
        ctx.shadowBlur = 0;
      }
      shards.forEach(s => {
        s.x += s.vx; s.y += s.vy; s.vy += .25; s.rot += s.vr; s.a = Math.max(0, s.a - .012);
        if (s.a <= 0) return;
        ctx.save(); ctx.translate(s.x, s.y); ctx.rotate(s.rot); ctx.globalAlpha = s.a;
        ctx.beginPath(); ctx.moveTo(s.verts[0][0], s.verts[0][1]); ctx.lineTo(s.verts[1][0], s.verts[1][1]); ctx.lineTo(s.verts[2][0], s.verts[2][1]); ctx.closePath();
        ctx.fillStyle = 'rgba(8,28,38,.92)'; ctx.fill();
        ctx.strokeStyle = AC; ctx.globalAlpha = s.a * .7; ctx.lineWidth = 1; ctx.stroke();
        ctx.restore();
      });
      ctx.globalAlpha = 1;
    } else if (t < T.REBIRTH) {                            // ACTS 4–6 — the abyss
      const dp = clamp((t - T.DESCENT) / (T.CONTACT - T.DESCENT), 0, 1);
      const dark = .25 + .75 * dp;                         // light dies as you sink
      const g = ctx.createLinearGradient(0, 0, 0, h);
      g.addColorStop(0, `rgba(2,${Math.round(40 * (1 - dark) + 8)},${Math.round(70 * (1 - dark) + 14)},1)`);
      g.addColorStop(1, 'rgba(0,4,6,1)');
      ctx.fillStyle = g; ctx.fillRect(0, 0, w, h);
      bubbles.forEach(b => {
        b.y -= b.v; b.x += Math.sin(b.y * .02) * .5;
        if (b.y < -10) { b.y = h + 10; b.x = Math.random() * w; }
        ctx.beginPath(); ctx.arc(b.x, b.y, b.r, 0, 7);
        ctx.strokeStyle = 'rgba(120,220,255,.35)'; ctx.lineWidth = 1; ctx.stroke();
      });
      rings.forEach(r => {
        r.t += 16;
        const rr = (r.t / 1400) * Math.max(w, h) * .8, a = Math.max(0, 1 - r.t / 1400);
        if (a <= 0) return;
        ctx.beginPath(); ctx.arc(w / 2, h / 2, rr, 0, 7);
        ctx.strokeStyle = AC; ctx.globalAlpha = a * (r.sonar ? .35 : .6); ctx.lineWidth = r.sonar ? 1.5 : 4; ctx.stroke();
        ctx.globalAlpha = 1;
      });
      rings = rings.filter(r => r.t < 1400);
      if (t < T.CONTACT) {                                 // depth gauge
        const depth = Math.round(11034 * ezio(dp));
        els.dnum.textContent = depth.toLocaleString();
        els.zone.textContent = depth < 200 ? 'SUNLIGHT ZONE' : depth < 1000 ? 'TWILIGHT ZONE' : depth < 4000 ? 'MIDNIGHT ZONE' : depth < 6000 ? 'ABYSSAL ZONE' : 'HADAL ZONE — CHALLENGER DEEP';
        els.press.textContent = 'PRESSURE: ' + Math.max(1, Math.round(depth / 10)).toLocaleString() + ' ATM';
      } else {                                             // ACT 5 — contact
        const ep = clamp((t - T.CONTACT - 300) / 900, 0, 1);
        tents.forEach(tn => {                              // tentacles reach in
          const tr = ez(clamp((now - tn.born - 300) / 1400, 0, 1));
          const tx = tn.bx + (tn.tx - tn.bx) * tr, ty = tn.by + (tn.ty - tn.by) * tr;
          const mx = (tn.bx + tx) / 2 + Math.sin(t * .002 + tn.ph) * 90;
          const my = (tn.by + ty) / 2 + Math.cos(t * .0017 + tn.ph) * 70;
          for (let pass = 0; pass < 2; pass++) {
            ctx.beginPath(); ctx.moveTo(tn.bx, tn.by); ctx.quadraticCurveTo(mx, my, tx, ty);
            ctx.strokeStyle = pass ? 'rgba(25,255,208,.25)' : 'rgba(4,22,18,.95)';
            ctx.lineWidth = pass ? 30 * (1 - tr * .4) : 26 * (1 - tr * .3) + 14;
            ctx.lineCap = 'round'; ctx.stroke();
          }
          for (let s = 1; s < 9; s++) {                    // suckers
            const u = s / 9, ix = (1 - u) * (1 - u) * tn.bx + 2 * (1 - u) * u * mx + u * u * tx, iy = (1 - u) * (1 - u) * tn.by + 2 * (1 - u) * u * my + u * u * ty;
            ctx.beginPath(); ctx.arc(ix, iy, 3.5 * (1 - u) + 1, 0, 7);
            ctx.fillStyle = 'rgba(25,255,208,.3)'; ctx.fill();
          }
        });
        if (ep > 0) {                                      // the eyes open
          [[w * .38, h * .4], [w * .62, h * .4]].forEach(e => {
            const ex = e[0] + Math.sin(t * .0011) * 8, ey = e[1] + Math.cos(t * .0009) * 5, er = Math.min(w, h) * .075;
            const gl = ctx.createRadialGradient(ex, ey, 0, ex, ey, er * 2.6);
            gl.addColorStop(0, 'rgba(25,255,208,.5)'); gl.addColorStop(1, 'transparent');
            ctx.fillStyle = gl; ctx.fillRect(ex - er * 3, ey - er * 3, er * 6, er * 6);
            ctx.save(); ctx.translate(ex, ey); ctx.scale(1, ep);
            ctx.beginPath(); ctx.ellipse(0, 0, er, er * .62, 0, 0, 7); ctx.fillStyle = '#0E5A48'; ctx.fill();
            ctx.beginPath(); ctx.ellipse(0, 0, er * .8, er * .5, 0, 0, 7); ctx.fillStyle = '#19FFD0'; ctx.shadowColor = '#19FFD0'; ctx.shadowBlur = 24; ctx.fill(); ctx.shadowBlur = 0;
            ctx.beginPath(); ctx.ellipse(0, 0, er * .14, er * .5, 0, 0, 7); ctx.fillStyle = '#001410'; ctx.fill();
            ctx.restore();
          });
        }
        if (t >= T.SHAKE) {                                // ACT 6 — neural veins
          const vp = clamp((t - T.SHAKE) / 1500, 0, 1);
          ctx.lineWidth = 1.4; ctx.shadowColor = AC; ctx.shadowBlur = 8;
          veins.forEach(v => {
            if (v.d / maxDepthV > vp) return;
            ctx.strokeStyle = AC; ctx.globalAlpha = .75 - v.d * .055;
            ctx.beginPath(); ctx.moveTo(v.x1, v.y1); ctx.lineTo(v.x2, v.y2); ctx.stroke();
            ctx.beginPath(); ctx.arc(v.x2, v.y2, 1.6, 0, 7); ctx.fillStyle = AC; ctx.fill();
          });
          ctx.globalAlpha = 1; ctx.shadowBlur = 0;
        }
      }
    }
    if (t >= T.END + 800) finish();
  }

  // ── lifecycle ──
  let events = [];
  function release() {
    if (running) return;
    running = true; finished = false;
    window.ZBSound && ZBSound.unlock();
    build();
    events = buildEvents();
    t0 = performance.now();
    raf = requestAnimationFrame(frame);
    ov.addEventListener('pointerdown', skip);
    document.addEventListener('keydown', escSkip);
  }
  function skip() { finish(); }
  function escSkip(e) { if (e.key === 'Escape') finish(); }

  function unlock() {
    localStorage.setItem('zb_god', '1');
    window.ZBThemes && ZBThemes.apply('kraken');
    if (!document.getElementById('god-badge')) {
      const hr = document.getElementById('header-right');
      if (hr) { const b = document.createElement('div'); b.id = 'god-badge'; b.textContent = '🐙 ABYSSAL'; hr.insertBefore(b, hr.firstChild); }
    }
    if (window.addLogLine) addLogLine('[KRAKEN UNLEASHED] // ABYSSAL PROTOCOL ENGAGED — GOD MODE ACTIVE', 'HUNT');
    document.dispatchEvent(new CustomEvent('zb-god-unlocked'));
  }

  function finish() {
    if (finished) return;
    finished = true; cancelAnimationFrame(raf);
    window.removeEventListener('resize', resize);
    document.removeEventListener('keydown', escSkip);
    unlock();
    ov.style.transition = 'opacity .7s';
    ov.style.opacity = 0;
    setTimeout(() => { ov.remove(); running = false; }, 750);
  }

  return { release, isRunning: () => running };
})();
window.ZBKraken = ZBKraken;
