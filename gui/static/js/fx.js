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

  // ─────────────────────────────────────────────────────────────────────────
  //  BESPOKE PER-THEME RENDERERS (added 2026-06-23)
  //  One signature visual per theme so no two backgrounds look alike. Each is a
  //  self-contained factory returning { resize, draw(ctx,t), opaque? }. The older
  //  shared renderers above (rain/particles/gridfloor/radar/embers/starfield) are
  //  left untouched — these only ADD new looks.
  // ─────────────────────────────────────────────────────────────────────────

  // KRAKEN-BLUE — "classic console" oscilloscope: a cyan signal sweeps L→R with a
  // bright phosphor head, a persistent fading trace, and a faint reticle grid.
  // (WarGames / Hackers terminal-scope vibe.)
  function makeWaveform(accent, accent2) {
    let w = 0, h = 0, ph = 0;
    return {
      opaque: true,
      resize(W, H) { w = W; h = H; },
      draw(ctx, t) {
        ctx.fillStyle = 'rgba(0,0,0,0.10)'; ctx.fillRect(0, 0, w, h);
        // faint scope grid
        ctx.strokeStyle = accent; ctx.globalAlpha = 0.05; ctx.lineWidth = 1;
        for (let y = 0; y < h; y += 46) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }
        for (let x = 0; x < w; x += 46) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke(); }
        ctx.globalAlpha = 1;
        ph = (t * 0.0016);
        const mid = h * 0.5, amp = h * 0.22;
        const wave = (x) => mid
          + Math.sin(x * 0.012 + ph) * amp * 0.55
          + Math.sin(x * 0.043 - ph * 1.7) * amp * 0.28
          + Math.sin(x * 0.0021 + ph * 0.4) * amp * 0.5;
        ctx.lineWidth = 2; ctx.strokeStyle = accent; ctx.shadowColor = accent; ctx.shadowBlur = 12;
        ctx.globalAlpha = 0.85; ctx.beginPath();
        for (let x = 0; x <= w; x += 6) { const y = wave(x); x === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y); }
        ctx.stroke(); ctx.shadowBlur = 0;
        // bright sweeping head
        const hx = (t * 0.18) % w, hy = wave(hx);
        ctx.fillStyle = accent2 || '#ffffff'; ctx.shadowColor = accent2 || accent; ctx.shadowBlur = 18;
        ctx.beginPath(); ctx.arc(hx, hy, 3.2, 0, 7); ctx.fill(); ctx.shadowBlur = 0;
        ctx.globalAlpha = 1;
      },
    };
  }

  // GANNON-ORANGE — molten PCB: glowing data pulses race along orthogonal circuit
  // traces, occasionally branching, leaving a warm fade. (Tron / Watch_Dogs ops board.)
  function makeCircuit(accent, accent2) {
    let w = 0, h = 0, traces = [], pulses = [];
    function build() {
      traces = []; pulses = [];
      const step = 64, cols = Math.max(2, Math.floor(w / step)), rows = Math.max(2, Math.floor(h / step));
      for (let i = 0; i <= cols; i++) traces.push({ vert: true, p: i * step });
      for (let j = 0; j <= rows; j++) traces.push({ vert: false, p: j * step });
      const n = Math.min(70, Math.floor((cols + rows) * 0.9));
      for (let k = 0; k < n; k++) pulses.push(spawn());
    }
    function spawn() {
      const vert = Math.random() < 0.5;
      const span = vert ? h : w;
      return { vert, lane: (Math.floor(Math.random() * (vert ? (w / 64) : (h / 64))) + 1) * 64,
               pos: Math.random() * span, sp: (0.6 + Math.random() * 1.6) * (Math.random() < .5 ? 1 : -1),
               len: 40 + Math.random() * 90, a: 0.4 + Math.random() * 0.6 };
    }
    return {
      resize(W, H) { w = W; h = H; build(); },
      draw(ctx) {
        ctx.strokeStyle = accent; ctx.globalAlpha = 0.06; ctx.lineWidth = 1;
        for (const tr of traces) {
          ctx.beginPath();
          if (tr.vert) { ctx.moveTo(tr.p, 0); ctx.lineTo(tr.p, h); } else { ctx.moveTo(0, tr.p); ctx.lineTo(w, tr.p); }
          ctx.stroke();
        }
        ctx.globalAlpha = 1; ctx.lineWidth = 2; ctx.lineCap = 'round';
        for (const p of pulses) {
          p.pos += p.sp;
          const span = p.vert ? h : w;
          if (p.pos < -p.len || p.pos > span + p.len) { Object.assign(p, spawn()); continue; }
          const x1 = p.vert ? p.lane : p.pos, y1 = p.vert ? p.pos : p.lane;
          const x2 = p.vert ? p.lane : p.pos - Math.sign(p.sp) * p.len, y2 = p.vert ? p.pos - Math.sign(p.sp) * p.len : p.lane;
          const grad = ctx.createLinearGradient(x1, y1, x2, y2);
          grad.addColorStop(0, accent2 || accent); grad.addColorStop(1, 'transparent');
          ctx.strokeStyle = grad; ctx.shadowColor = accent2 || accent; ctx.shadowBlur = 10; ctx.globalAlpha = p.a;
          ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke();
          ctx.fillStyle = '#fff'; ctx.beginPath(); ctx.arc(x1, y1, 1.8, 0, 7); ctx.fill();
        }
        ctx.shadowBlur = 0; ctx.globalAlpha = 1; ctx.lineCap = 'butt';
      },
    };
  }

  // THREAT-RED — DEFCON board: arcing missile trajectories streak between random
  // launch/impact points across a faint hostile world-grid, blooming on impact.
  // (WarGames "Global Thermonuclear War" map.)
  function makeMissileMap(accent, accent2) {
    let w = 0, h = 0, arcs = [], blooms = [];
    function spawn() {
      const x1 = Math.random() * w, y1 = h * (0.5 + Math.random() * 0.5);
      const x2 = Math.random() * w, y2 = h * (0.3 + Math.random() * 0.5);
      return { x1, y1, x2, y2, cx: (x1 + x2) / 2 + (Math.random() - .5) * w * 0.2, cy: Math.min(y1, y2) - (120 + Math.random() * 180), t: 0, sp: 0.004 + Math.random() * 0.006 };
    }
    function qpt(a, p) { const u = 1 - p; return { x: u * u * a.x1 + 2 * u * p * a.cx + p * p * a.x2, y: u * u * a.y1 + 2 * u * p * a.cy + p * p * a.y2 }; }
    return {
      resize(W, H) { w = W; h = H; arcs = Array.from({ length: 7 }, spawn); blooms = []; },
      draw(ctx) {
        // hostile grid
        ctx.strokeStyle = accent; ctx.globalAlpha = 0.04; ctx.lineWidth = 1;
        for (let y = h * 0.2; y < h; y += 54) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }
        for (let x = 0; x < w; x += 70) { ctx.beginPath(); ctx.moveTo(x, h * 0.2); ctx.lineTo(x, h); ctx.stroke(); }
        ctx.globalAlpha = 1;
        for (let i = 0; i < arcs.length; i++) {
          const a = arcs[i]; a.t += a.sp;
          // drawn trail up to current t
          ctx.strokeStyle = accent; ctx.lineWidth = 1.5; ctx.globalAlpha = 0.5; ctx.beginPath();
          const segs = 24, upto = Math.min(1, a.t);
          for (let s = 0; s <= segs; s++) { const p = (s / segs) * upto; const pt = qpt(a, p); s === 0 ? ctx.moveTo(pt.x, pt.y) : ctx.lineTo(pt.x, pt.y); }
          ctx.stroke();
          // warhead head
          if (a.t < 1) {
            const hd = qpt(a, a.t); ctx.fillStyle = accent2 || '#fff'; ctx.shadowColor = accent2 || accent; ctx.shadowBlur = 14;
            ctx.globalAlpha = 1; ctx.beginPath(); ctx.arc(hd.x, hd.y, 2.6, 0, 7); ctx.fill(); ctx.shadowBlur = 0;
          } else { blooms.push({ x: a.x2, y: a.y2, r: 0 }); arcs[i] = spawn(); }
        }
        ctx.globalAlpha = 1;
        for (let i = blooms.length - 1; i >= 0; i--) {
          const b = blooms[i]; b.r += 1.6;
          ctx.strokeStyle = accent2 || accent; ctx.lineWidth = 2; ctx.globalAlpha = Math.max(0, 1 - b.r / 48);
          ctx.beginPath(); ctx.arc(b.x, b.y, b.r, 0, 7); ctx.stroke();
          if (b.r > 48) blooms.splice(i, 1);
        }
        ctx.globalAlpha = 1;
      },
    };
  }

  // GHOST-GREEN — recon topography: slow-breathing contour lines drift like a
  // night-vision terrain map, with sparse sensor blips. Low emission, no hard edges.
  function makeContour(accent, accent2) {
    let w = 0, h = 0, blips = [];
    return {
      resize(W, H) { w = W; h = H; blips = Array.from({ length: 5 }, () => ({ x: Math.random() * W, y: Math.random() * H, t: Math.random() })); },
      draw(ctx, t) {
        const ph = t * 0.0004;
        ctx.lineWidth = 1;
        for (let k = 0; k < 7; k++) {
          const base = (h / 7) * k + (h / 14);
          ctx.strokeStyle = k % 3 === 0 ? (accent2 || accent) : accent;
          ctx.globalAlpha = 0.12; ctx.beginPath();
          for (let x = 0; x <= w; x += 10) {
            const y = base
              + Math.sin(x * 0.006 + ph * 6 + k) * 22
              + Math.sin(x * 0.018 - ph * 9 + k * 1.7) * 9;
            x === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
          }
          ctx.stroke();
        }
        ctx.globalAlpha = 1;
        for (const b of blips) {
          b.t += 0.01; const pulse = (Math.sin(b.t) + 1) / 2;
          ctx.fillStyle = accent2 || accent; ctx.shadowColor = accent2 || accent; ctx.shadowBlur = 10;
          ctx.globalAlpha = 0.15 + pulse * 0.45;
          ctx.beginPath(); ctx.arc(b.x, b.y, 1.6 + pulse * 1.4, 0, 7); ctx.fill();
        }
        ctx.shadowBlur = 0; ctx.globalAlpha = 1;
      },
    };
  }

  // OVERWATCH — AR hacking HUD: bracketed target tags lock onto roaming points,
  // a vertical scan-line sweeps and re-tags contacts. (Cyberpunk 2077 / Watch_Dogs.)
  function makeDataTags(accent, accent2) {
    let w = 0, h = 0, tags = [], scan = 0;
    const codes = ['0x4F','SYS','ICE','NET','PWN','ROOT','0xA3','DAEMON','PROC','SOCK','0xFF','NODE'];
    function spawn() { return { x: Math.random() * w, y: Math.random() * h, vx: (Math.random() - .5) * .3, vy: (Math.random() - .5) * .3, code: codes[(Math.random() * codes.length) | 0], lock: 0 }; }
    return {
      resize(W, H) { w = W; h = H; tags = Array.from({ length: Math.min(14, Math.floor(W / 110)) }, spawn); },
      draw(ctx) {
        scan = (scan + 2.2) % w;
        // sweeping scan line
        ctx.strokeStyle = accent2 || accent; ctx.globalAlpha = 0.25; ctx.lineWidth = 2;
        ctx.beginPath(); ctx.moveTo(scan, 0); ctx.lineTo(scan, h); ctx.stroke();
        ctx.globalAlpha = 1; ctx.font = '10px "JetBrains Mono",monospace';
        for (const tg of tags) {
          tg.x += tg.vx; tg.y += tg.vy;
          if (tg.x < 20 || tg.x > w - 20) tg.vx *= -1; if (tg.y < 20 || tg.y > h - 20) tg.vy *= -1;
          if (Math.abs(tg.x - scan) < 6) tg.lock = 1;       // re-lock as the scan passes
          tg.lock = Math.max(0, tg.lock - 0.012);
          const s = 9 + tg.lock * 4;
          ctx.strokeStyle = accent; ctx.globalAlpha = 0.3 + tg.lock * 0.6; ctx.lineWidth = 1;
          // corner brackets
          const cb = (ox, oy, sx, sy) => { ctx.beginPath(); ctx.moveTo(tg.x + ox, tg.y + oy + sy * 4); ctx.lineTo(tg.x + ox, tg.y + oy); ctx.lineTo(tg.x + ox + sx * 4, tg.y + oy); ctx.stroke(); };
          cb(-s, -s, 1, 1); cb(s, -s, -1, 1); cb(-s, s, 1, -1); cb(s, s, -1, -1);
          ctx.fillStyle = accent2 || accent; ctx.beginPath(); ctx.arc(tg.x, tg.y, 1.5, 0, 7); ctx.fill();
          if (tg.lock > 0.15) { ctx.fillStyle = accent; ctx.globalAlpha = tg.lock; ctx.fillText(tg.code, tg.x + s + 4, tg.y + 3); }
        }
        ctx.globalAlpha = 1;
      },
    };
  }

  // WOPR — NORAD wireframe globe: an amber lat/long sphere rotates with sweeping
  // longitude lines. (WarGames defense-mainframe console.)
  function makeGlobe(accent, accent2) {
    let w = 0, h = 0;
    return {
      resize(W, H) { w = W; h = H; },
      draw(ctx, t) {
        const cx = w * 0.5, cy = h * 0.5, R = Math.min(w, h) * 0.34, rot = t * 0.00035;
        ctx.strokeStyle = accent; ctx.lineWidth = 1;
        // latitude rings (flattened ellipses)
        for (let i = 1; i < 7; i++) {
          const lat = (i / 7) * Math.PI - Math.PI / 2, ry = Math.cos(lat) * R, yy = cy + Math.sin(lat) * R;
          ctx.globalAlpha = 0.12; ctx.beginPath(); ctx.ellipse(cx, yy, ry, ry * 0.32, 0, 0, 7); ctx.stroke();
        }
        // rotating longitude lines
        for (let j = 0; j < 10; j++) {
          const ang = rot + (j / 10) * Math.PI * 2, sx = Math.cos(ang);
          ctx.globalAlpha = 0.08 + Math.abs(sx) * 0.14;
          ctx.beginPath(); ctx.ellipse(cx, cy, Math.abs(sx) * R, R, 0, 0, 7); ctx.stroke();
        }
        // outline + a brighter sweeping meridian
        ctx.globalAlpha = 0.3; ctx.lineWidth = 1.4; ctx.beginPath(); ctx.arc(cx, cy, R, 0, 7); ctx.stroke();
        const sweep = Math.cos(rot * 3);
        ctx.strokeStyle = accent2 || accent; ctx.globalAlpha = 0.5; ctx.shadowColor = accent2 || accent; ctx.shadowBlur = 10;
        ctx.beginPath(); ctx.ellipse(cx, cy, Math.abs(sweep) * R, R, 0, 0, 7); ctx.stroke();
        ctx.shadowBlur = 0; ctx.globalAlpha = 1;
      },
    };
  }

  // BLACKSITE — redacted void: slow mono grain, a single classified scan bar, and
  // occasional sliding redaction blocks. Deliberately minimal & cold.
  function makeRedact(accent, accent2) {
    let w = 0, h = 0, bars = [], scan = 0;
    function spawn() { const y = Math.random() * h; return { x: -Math.random() * 300, y, ww: 60 + Math.random() * 220, sp: 0.3 + Math.random() * 0.8 }; }
    return {
      resize(W, H) { w = W; h = H; bars = Array.from({ length: 8 }, spawn); },
      draw(ctx) {
        // sparse grain
        ctx.globalAlpha = 0.04; ctx.fillStyle = accent;
        for (let i = 0; i < 40; i++) ctx.fillRect((Math.random() * w) | 0, (Math.random() * h) | 0, 1, 1);
        // redaction blocks
        ctx.globalAlpha = 0.06; ctx.fillStyle = accent;
        for (const b of bars) {
          b.x += b.sp; if (b.x > w + 40) Object.assign(b, spawn(), { x: -b.ww });
          ctx.fillRect(b.x, b.y, b.ww, 7);
        }
        // single classified scan bar
        scan = (scan + 0.6) % h;
        ctx.globalAlpha = 0.10; ctx.fillStyle = accent2 || accent; ctx.fillRect(0, scan, w, 2);
        ctx.globalAlpha = 1;
      },
    };
  }

  // OUTRUN — synthwave sun: a banded neon sun hangs over a glowing horizon haze.
  // Pairs with the existing grid-floor but stands on its own. (80s Outrun/Hotline Miami.)
  function makeSynthSun(accent, accent2) {
    let w = 0, h = 0;
    return {
      resize(W, H) { w = W; h = H; },
      draw(ctx, t) {
        const cx = w * 0.5, horizon = h * 0.52, R = Math.min(w, h) * 0.26, cyc = horizon - R * 0.35;
        // sun disc with horizontal cutout bands
        const g = ctx.createLinearGradient(cx, cyc - R, cx, cyc + R);
        g.addColorStop(0, accent2 || accent); g.addColorStop(1, accent);
        ctx.save();
        ctx.beginPath(); ctx.arc(cx, cyc, R, 0, 7); ctx.clip();
        ctx.fillStyle = g; ctx.globalAlpha = 0.55; ctx.fillRect(cx - R, cyc - R, R * 2, R * 2);
        // bands (more frequent toward the bottom)
        ctx.globalAlpha = 1; ctx.fillStyle = '#000';
        for (let i = 0; i < 9; i++) { const by = cyc + (i / 9) * R * 0.9; const bh = 2 + i * 0.9; ctx.fillRect(cx - R, by, R * 2, bh); }
        ctx.restore();
        // soft glow halo
        ctx.globalAlpha = 0.12; ctx.fillStyle = accent2 || accent; ctx.shadowColor = accent2 || accent; ctx.shadowBlur = 40;
        ctx.beginPath(); ctx.arc(cx, cyc, R * 0.9, 0, 7); ctx.fill(); ctx.shadowBlur = 0;
        // horizon haze line with a slow shimmer
        const shimmer = 0.18 + Math.sin(t * 0.001) * 0.06;
        ctx.globalAlpha = shimmer; ctx.strokeStyle = accent2 || accent; ctx.lineWidth = 2;
        ctx.beginPath(); ctx.moveTo(0, horizon); ctx.lineTo(w, horizon); ctx.stroke();
        ctx.globalAlpha = 1;
      },
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
    // bespoke per-theme signatures (added 2026-06-23)
    if (on('waveform'))  renderers.push(makeWaveform(accent, accent2));
    if (on('circuit'))   renderers.push(makeCircuit(accent, accent2));
    if (on('missilemap'))renderers.push(makeMissileMap(accent, accent2));
    if (on('contour'))   renderers.push(makeContour(accent, accent2));
    if (on('datatags'))  renderers.push(makeDataTags(accent, accent2));
    if (on('globe'))     renderers.push(makeGlobe(accent, accent2));
    if (on('redact'))    renderers.push(makeRedact(accent, accent2));
    if (on('synthsun'))  renderers.push(makeSynthSun(accent, accent2));

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
