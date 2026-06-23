/* ═══════════════════════════════════════════════════════════════════════════
   ZEROBREACH — CINEMATIC VFX LAYER + TEXT EFFECTS (vanilla, no framework)
   One full-viewport canvas runs a stack of renderers chosen by the active
   theme's vfx profile; CSS overlay divs handle scanlines/noise/CRT/vignette.
   Everything is gated by an intensity tier so old laptops stay smooth:
     OFF (cap 0) · LITE (0.55, static overlays only) · FULL (1.0) · MAX (1.5)
   ═══════════════════════════════════════════════════════════════════════════ */
'use strict';

const ZBFX = (() => {

  // ── canvas renderer factories (ported from PirateLife fx layer) ──────────
  function makeRain(accent) {
    let cols = [], w = 0, h = 0, fontSize = 16;
    // Half-width katakana + digits + symbols — the iconic Matrix digital-rain glyph set.
    const glyphs = 'ｦｧｨｩｪｫｬｭｮｯｰｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789:=*+<>¦"╌';
    const g = () => glyphs[(Math.random() * glyphs.length) | 0];
    return {
      resize(W, H) {
        w = W; h = H;
        fontSize = Math.max(13, Math.round(W / 90));
        const n = Math.floor(W / fontSize);
        cols = Array.from({ length: n }, () => ({ y: Math.random() * -H, sp: 0.55 + Math.random() * 0.8 }));
      },
      draw(ctx) {
        // Low-alpha wash instead of a hard clear: leaves a fading tail behind each head.
        ctx.fillStyle = 'rgba(0,0,0,0.055)'; ctx.fillRect(0, 0, w, h);
        ctx.font = fontSize + 'px "JetBrains Mono",monospace';
        for (let i = 0; i < cols.length; i++) {
          const c = cols[i], x = i * fontSize;
          // Bright near-white leading glyph with accent glow — the falling "head".
          ctx.fillStyle = '#e6fff0'; ctx.shadowColor = accent; ctx.shadowBlur = 10;
          ctx.fillText(g(), x, c.y);
          ctx.shadowBlur = 0;
          // Two accent-green glyphs trailing just behind it.
          ctx.fillStyle = accent;
          ctx.fillText(g(), x, c.y - fontSize);
          ctx.fillStyle = 'rgba(130,255,170,.4)';
          ctx.fillText(g(), x, c.y - fontSize * 2);
          c.y += fontSize * c.sp;
          if (c.y > h + Math.random() * 280) { c.y = -fontSize * ((Math.random() * 14) | 0); c.sp = 0.55 + Math.random() * 0.8; }
        }
      },
      opaque: true,
    };
  }

  function makeParticles(accent, density) {
    let pts = [], w = 0, h = 0;
    return {
      resize(W, H) { w = W; h = H; const n = Math.floor((W * H) / 26000 * (density || 1)); pts = Array.from({ length: n }, () => ({ x: Math.random() * W, y: Math.random() * H, vx: (Math.random() - .5) * .25, vy: (Math.random() - .5) * .25, r: Math.random() * 1.6 + .4 })); },
      draw(ctx) {
        for (const p of pts) {
          p.x += p.vx; p.y += p.vy;
          if (p.x < 0) p.x += w; if (p.x > w) p.x -= w; if (p.y < 0) p.y += h; if (p.y > h) p.y -= h;
          ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, 7); ctx.fillStyle = accent; ctx.globalAlpha = .5; ctx.fill();
        }
        ctx.globalAlpha = 1;
        for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) {
          const a = pts[i], b = pts[j], dx = a.x - b.x, dy = a.y - b.y, d = dx * dx + dy * dy;
          if (d < 9000) { ctx.strokeStyle = accent; ctx.globalAlpha = (1 - d / 9000) * .12; ctx.lineWidth = .5; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke(); }
        }
        ctx.globalAlpha = 1;
      },
    };
  }

  function makeGridFloor(accent, accent2) {
    let w = 0, h = 0;
    return {
      resize(W, H) { w = W; h = H; },
      draw(ctx, t) {
        const horizon = h * 0.52, vp = w / 2, off = (t * 0.05) % 40;
        ctx.lineWidth = 1;
        for (let i = 0; i < 22; i++) {
          const z = i * 40 + off; const y = horizon + (z * z) / (h * 1.4);
          if (y > h) break;
          ctx.strokeStyle = accent; ctx.globalAlpha = Math.max(0, 1 - (y - horizon) / (h - horizon)) * 0.4;
          ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
        }
        for (let i = -20; i <= 20; i++) {
          const x = vp + i * (w / 18);
          ctx.strokeStyle = i % 5 === 0 ? accent2 : accent; ctx.globalAlpha = i % 5 === 0 ? 0.3 : 0.16;
          ctx.beginPath(); ctx.moveTo(vp, horizon); ctx.lineTo(x, h); ctx.stroke();
        }
        ctx.globalAlpha = 1;
        const g = ctx.createLinearGradient(0, horizon - 50, 0, horizon + 8);
        g.addColorStop(0, 'transparent'); g.addColorStop(1, accent);
        ctx.globalAlpha = .12; ctx.fillStyle = g; ctx.fillRect(0, horizon - 50, w, 58); ctx.globalAlpha = 1;
      },
    };
  }

  function makeRadar(accent) {
    let w = 0, h = 0;
    return {
      resize(W, H) { w = W; h = H; },
      draw(ctx, t) {
        const cx = w * 0.5, cy = h * 0.5, R = Math.min(w, h) * 0.42;
        ctx.strokeStyle = accent; ctx.globalAlpha = 0.1; ctx.lineWidth = 1;
        for (let r = R / 4; r <= R; r += R / 4) { ctx.beginPath(); ctx.arc(cx, cy, r, 0, 7); ctx.stroke(); }
        ctx.beginPath(); ctx.moveTo(cx - R, cy); ctx.lineTo(cx + R, cy); ctx.moveTo(cx, cy - R); ctx.lineTo(cx, cy + R); ctx.stroke();
        const ang = (t * 0.0009) % (Math.PI * 2);
        if (ctx.createConicGradient) {
          const g = ctx.createConicGradient(ang, cx, cy);
          g.addColorStop(0, accent); g.addColorStop(0.08, 'transparent'); g.addColorStop(1, 'transparent');
          ctx.globalAlpha = 0.15; ctx.fillStyle = g; ctx.beginPath(); ctx.arc(cx, cy, R, 0, 7); ctx.fill();
        }
        ctx.globalAlpha = 0.4; ctx.strokeStyle = accent;
        ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(cx + Math.cos(ang) * R, cy + Math.sin(ang) * R); ctx.stroke();
        ctx.globalAlpha = 1;
      },
    };
  }

  function makeEmbers(accent) {
    let pts = [], w = 0, h = 0;
    return {
      resize(W, H) { w = W; h = H; pts = Array.from({ length: Math.floor(W / 14) }, () => ({ x: Math.random() * W, y: Math.random() * H, vy: -(Math.random() * .6 + .2), r: Math.random() * 1.8 + .5, a: Math.random() })); },
      draw(ctx) {
        for (const p of pts) {
          p.y += p.vy; p.x += Math.sin(p.y * 0.02) * 0.3;
          if (p.y < -5) { p.y = h + 5; p.x = Math.random() * w; }
          ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, 7); ctx.fillStyle = accent; ctx.shadowColor = accent; ctx.shadowBlur = 8; ctx.globalAlpha = p.a * .55; ctx.fill();
        }
        ctx.shadowBlur = 0; ctx.globalAlpha = 1;
      },
    };
  }

  function makeStarfield(accent, accent2) {
    let stars = [], w = 0, h = 0;
    return {
      resize(W, H) { w = W; h = H; const n = Math.floor((W * H) / 9000); stars = Array.from({ length: n }, () => ({ x: (Math.random() - .5) * W, y: (Math.random() - .5) * H, z: Math.random() * W, c: Math.random() < .12 ? accent2 : accent })); },
      draw(ctx) {
        ctx.fillStyle = 'rgba(0,0,0,0.25)'; ctx.fillRect(0, 0, w, h);
        const cx = w / 2, cy = h / 2;
        for (const s of stars) {
          s.z -= 1.4; if (s.z < 1) { s.z = w; s.x = (Math.random() - .5) * w; s.y = (Math.random() - .5) * h; }
          const k = 128 / s.z, px = cx + s.x * k, py = cy + s.y * k;
          if (px < 0 || px > w || py < 0 || py > h) continue;
          ctx.globalAlpha = (1 - s.z / w); ctx.fillStyle = s.c;
          ctx.beginPath(); ctx.arc(px, py, Math.max(.2, (1 - s.z / w) * 1.8), 0, 7); ctx.fill();
        }
        ctx.globalAlpha = 1;
      },
      opaque: true,
    };
  }

  // ── intensity tiers ───────────────────────────────────────────────────────
  const INTENSITY = {
    off:  { label: 'OFF',     cap: 0,    desc: 'No background FX · max performance' },
    lite: { label: 'LITE',    cap: 0.55, desc: 'Static overlays only · old laptops' },
    full: { label: 'FULL',    cap: 1.0,  desc: 'Animated FX · balanced (default)' },
    max:  { label: 'MAXIMUM', cap: 1.5,  desc: 'Everything · GPU recommended' },
  };

  // ── state ─────────────────────────────────────────────────────────────────
  let canvas = null, ctx2d = null, rafId = 0, renderers = [], overlays = {};
  let theme = null;
  let intensity = localStorage.getItem('zb_fx') || 'full';
  if (!INTENSITY[intensity]) intensity = 'full';

  const OVERLAY_KEYS = ['aurora', 'grid', 'scanlines', 'crt', 'noise', 'vignette', 'alarm', 'flicker'];

  function init() {
    if (canvas) return;
    canvas = document.createElement('canvas');
    canvas.id = 'fx-canvas';
    document.body.insertBefore(canvas, document.body.firstChild);
    ctx2d = canvas.getContext('2d');
    OVERLAY_KEYS.forEach(k => {
      const d = document.createElement('div');
      d.className = 'fx-' + k;
      d.style.display = 'none';
      document.body.appendChild(d);
      overlays[k] = d;
    });
    window.addEventListener('resize', resize);
  }

  let w = 0, h = 0;
  function resize() {
    if (!canvas) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
    w = window.innerWidth; h = window.innerHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    canvas.style.width = w + 'px'; canvas.style.height = h + 'px';
    ctx2d.setTransform(dpr, 0, 0, dpr, 0, 0);
    renderers.forEach(r => r.resize(w, h));
  }

  function rebuild() {
    if (!canvas) init();
    cancelAnimationFrame(rafId);
    renderers = [];
    ctx2d && ctx2d.clearRect(0, 0, w || 1, h || 1);
    const cap = INTENSITY[intensity].cap;
    const vfx = (theme && theme.vfx) || {};
    const on = k => vfx[k] !== undefined && cap > 0 && vfx[k] <= cap;

    const cs = getComputedStyle(document.body);
    const accent  = cs.getPropertyValue('--accent').trim()   || '#00D4FF';
    const accent2 = cs.getPropertyValue('--accent-2').trim() || accent;

    if (on('rain'))      renderers.push(makeRain(accent));
    if (on('gridfloor')) renderers.push(makeGridFloor(accent, accent2));
    if (on('radar'))     renderers.push(makeRadar(accent));
    if (on('embers'))    renderers.push(makeEmbers(accent2));
    if (on('starfield')) renderers.push(makeStarfield(accent, accent2));
    if (on('particles')) renderers.push(makeParticles(accent, vfx.particles));

    OVERLAY_KEYS.forEach(k => { if (overlays[k]) overlays[k].style.display = on(k) ? 'block' : 'none'; });

    if (!renderers.length) return;
    resize();
    const needsClear = !renderers.some(r => r.opaque);
    const fpsCap = renderers.some(r => r.opaque) ? 22 : 33;
    const minDelta = 1000 / fpsCap;
    const start = performance.now();
    let last = 0;
    const loop = (now) => {
      rafId = requestAnimationFrame(loop);
      if (now - last < minDelta) return; last = now;
      if (needsClear) ctx2d.clearRect(0, 0, w, h);
      const t = now - start;
      renderers.forEach(r => r.draw(ctx2d, t));
    };
    rafId = requestAnimationFrame(loop);
  }

  // ── text effects ──────────────────────────────────────────────────────────
  const CRYPT = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*<>?/\\|';

  // Scramble-decrypt el's text into `text` over `duration` ms.
  function decrypt(el, text, duration = 600, onDone) {
    if (!el) return;
    if (el._zbDecrypt) cancelAnimationFrame(el._zbDecrypt);
    let startTime = 0;
    const step = (ts) => {
      if (!startTime) startTime = ts;
      const p = Math.min(1, (ts - startTime) / duration);
      const reveal = Math.floor(p * text.length);
      let s = '';
      for (let i = 0; i < text.length; i++) {
        if (text[i] === ' ') { s += ' '; continue; }
        s += i < reveal ? text[i] : CRYPT[(Math.random() * CRYPT.length) | 0];
      }
      el.textContent = s;
      if (p < 1) el._zbDecrypt = requestAnimationFrame(step);
      else { el.textContent = text; el._zbDecrypt = 0; if (onDone) onDone(); }
    };
    el._zbDecrypt = requestAnimationFrame(step);
  }

  // Animated count-up with cubic ease-out.
  function countUp(el, to, dur = 900, suffix = '') {
    if (!el) return;
    if (el._zbCount) cancelAnimationFrame(el._zbCount);
    let start = 0;
    const step = (ts) => {
      if (!start) start = ts;
      const p = Math.min(1, (ts - start) / dur);
      const e = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(to * e) + suffix;
      if (p < 1) el._zbCount = requestAnimationFrame(step);
      else el._zbCount = 0;
    };
    el._zbCount = requestAnimationFrame(step);
  }

  // Brief whole-app shake (CSS class lives in fx.css).
  function shake(strength = 'med', dur = 400) {
    const app = document.getElementById('app');
    if (!app) return;
    const cls = 'zb-shake-' + strength;
    app.classList.remove('zb-shake-low', 'zb-shake-med', 'zb-shake-hard');
    void app.offsetWidth;
    app.classList.add(cls);
    setTimeout(() => app.classList.remove(cls), dur);
  }

  return {
    INTENSITY, init,
    applyTheme(t) { theme = t; rebuild(); },
    setIntensity(tier) { if (INTENSITY[tier]) { intensity = tier; localStorage.setItem('zb_fx', tier); rebuild(); } },
    getIntensity() { return intensity; },
    decrypt, countUp, shake,
  };
})();
window.ZBFX = ZBFX;
