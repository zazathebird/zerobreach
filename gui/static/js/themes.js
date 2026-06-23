/* ═══════════════════════════════════════════════════════════════════════════
   ZEROBREACH — THEME ENGINE
   Each theme = CSS custom properties (ZeroBreach var vocabulary) + a VFX
   profile + a sound palette. Live-swappable. Vars are set inline on <body>
   so they win over the legacy body.theme-* class rules in main.css.
   The KRAKEN theme is secret until god mode is unlocked (type "kraken").
   ═══════════════════════════════════════════════════════════════════════════ */
'use strict';

const ZBThemes = (() => {

  function rgb(hex) {
    const h = hex.replace('#', '');
    return [parseInt(h.substr(0, 2), 16), parseInt(h.substr(2, 2), 16), parseInt(h.substr(4, 2), 16)].join(',');
  }

  // d: { accent, accent2, bg0, bg1, bg2, bgHover, text, textMid, textDim }
  function vars(d) {
    const a = rgb(d.accent);
    return {
      '--accent':        d.accent,
      '--accent-2':      d.accent2 || d.accent,
      '--accent-glow':   `rgba(${a},0.25)`,
      '--accent-dim':    `rgba(${a},0.08)`,
      '--bg-base':       d.bg0,
      '--bg-panel':      d.bg1,
      '--bg-glass':      d.bg1 + 'EB',
      '--bg-raised':     d.bg2,
      '--bg-hover':      d.bgHover,
      '--border':        `rgba(${a},0.18)`,
      '--border-bright': `rgba(${a},0.5)`,
      '--text':          d.text,
      '--text-mid':      d.textMid,
      '--text-dim':      d.textDim,
    };
  }

  // VFX flag weights are gated by the intensity tier cap (see fx.js):
  // a flag runs when weight <= cap. grid/scanlines may also carry opacity.
  const THEMES = [
    {
      id: 'kraken-blue', name: 'KRAKEN BLUE', tagline: 'Tactical cyan · the classic console',
      sound: { base: 300, wave: 'triangle' },
      vfx: { waveform: 0.6, scanlines: 0.4, vignette: 0.5 },
      vars: vars({ accent: '#00D4FF', accent2: '#FF2D55', bg0: '#050A0F', bg1: '#070E17', bg2: '#0A1520', bgHover: '#0D1E30', text: '#C8E8F8', textMid: '#6A8A9A', textDim: '#3A5A70' }),
    },
    {
      id: 'gannon-orange', name: 'GANNON ORANGE', tagline: 'MSP protocol · molten ops',
      sound: { base: 280, wave: 'sawtooth' },
      vfx: { circuit: 0.6, scanlines: 0.5, vignette: 0.5 },
      vars: vars({ accent: '#FF6B00', accent2: '#FFD23D', bg0: '#0C0703', bg1: '#140B04', bg2: '#1D1106', bgHover: '#2A1808', text: '#FFE0C2', textMid: '#B08868', textDim: '#6E4F35' }),
    },
    {
      id: 'threat-red', name: 'THREAT RED', tagline: 'DEFCON 1 · maximum threat posture',
      sound: { base: 200, wave: 'sawtooth' },
      vfx: { missilemap: 0.7, scanlines: 0.5, vignette: 0.5, alarm: 1.1 },
      vars: vars({ accent: '#FF0033', accent2: '#FF9A3B', bg0: '#0A0202', bg1: '#130404', bg2: '#1E0707', bgHover: '#2A0A0A', text: '#FFD2D2', textMid: '#A86868', textDim: '#6B3434' }),
    },
    {
      id: 'ghost-green', name: 'GHOST GREEN', tagline: 'Stealth recon · low emission',
      sound: { base: 260, wave: 'sine' },
      vfx: { contour: 0.5, scanlines: 0.2, vignette: 0.5 },
      vars: vars({ accent: '#00FF88', accent2: '#8AB4FF', bg0: '#040906', bg1: '#06110B', bg2: '#091A10', bgHover: '#0D2618', text: '#C8F8DE', textMid: '#6A9A82', textDim: '#3A7055' }),
    },
    {
      id: 'construct', name: 'CONSTRUCT', tagline: 'Digital rain · phosphor green',
      sound: { base: 220, wave: 'square' },
      vfx: { rain: 0.9, scanlines: 0.5, vignette: 0.5, crt: 0.8, flicker: 0.8 },
      vars: vars({ accent: '#22FF66', accent2: '#9BFF4D', bg0: '#000300', bg1: '#02160A', bg2: '#04230F', bgHover: '#053015', text: '#9BFFBF', textMid: '#43D97A', textDim: '#2A8A4F' }),
    },
    {
      id: 'wopr', name: 'WOPR', tagline: '80s mainframe · amber phosphor',
      sound: { base: 240, wave: 'square' },
      vfx: { globe: 0.6, scanlines: 0.5, vignette: 0.5, crt: 0.6, flicker: 0.8 },
      vars: vars({ accent: '#FFB340', accent2: '#FF7A1A', bg0: '#0A0600', bg1: '#140D02', bg2: '#1D1404', bgHover: '#221806', text: '#FFCF8A', textMid: '#D99A45', textDim: '#9C6E2E' }),
    },
    {
      id: 'grid', name: 'GRID', tagline: 'Light-cycle neon · cyan + orange',
      sound: { base: 340, wave: 'sine' },
      vfx: { gridfloor: 0.8, particles: 0.7, scanlines: 0.3, vignette: 0.5 },
      vars: vars({ accent: '#39E6FF', accent2: '#FF8A3D', bg0: '#000208', bg1: '#020812', bg2: '#041020', bgHover: '#06182C', text: '#D6F6FF', textMid: '#6FC6E6', textDim: '#3D7E9C' }),
    },
    {
      id: 'outrun', name: 'OUTRUN', tagline: 'Neon sunset · magenta + cyan',
      sound: { base: 300, wave: 'sawtooth' },
      vfx: { gridfloor: 0.8, synthsun: 0.5, aurora: 0.4, scanlines: 0.4, vignette: 0.5 },
      vars: vars({ accent: '#FF4DCB', accent2: '#46E0FF', bg0: '#0A0218', bg1: '#150828', bg2: '#1F0F3A', bgHover: '#241046', text: '#FFD9F4', textMid: '#C98FD6', textDim: '#8A5AA0' }),
    },
    {
      id: 'overwatch', name: 'OVERWATCH', tagline: 'Cyberpunk tactical HUD · cyan + red',
      sound: { base: 300, wave: 'triangle' },
      vfx: { datatags: 0.6, scanlines: 0.5, noise: 0.8, vignette: 0.5, flicker: 0.8 },
      vars: vars({ accent: '#00D4FF', accent2: '#FF2D55', bg0: '#020610', bg1: '#0A1520', bg2: '#0F1E2E', bgHover: '#102438', text: '#C8E8FF', textMid: '#7EA9C9', textDim: '#4A7A9B' }),
    },
    {
      id: 'nebula', name: 'NEBULA', tagline: 'Deep space · violet + gold',
      sound: { base: 270, wave: 'sine' },
      vfx: { starfield: 0.8, aurora: 0.4, particles: 0.7, scanlines: 0.3, vignette: 0.5 },
      vars: vars({ accent: '#B18CFF', accent2: '#FFCF6A', bg0: '#070512', bg1: '#0E0A1F', bg2: '#15102E', bgHover: '#1A1336', text: '#E9E2FF', textMid: '#B3A4D6', textDim: '#7A6BA0' }),
    },
    {
      id: 'cheyenne', name: 'CHEYENNE', tagline: 'Command center · jade + amber',
      sound: { base: 280, wave: 'sine' },
      vfx: { radar: 0.8, grid: 0.6, particles: 0.3, scanlines: 0.5, vignette: 0.5 },
      vars: vars({ accent: '#3FE0C0', accent2: '#FFB000', bg0: '#03080C', bg1: '#071119', bg2: '#0A1922', bgHover: '#0D2230', text: '#CFE8E0', textMid: '#7FB0A6', textDim: '#4D7A72' }),
    },
    {
      id: 'blacksite', name: 'BLACKSITE', tagline: 'Stealth minimal · mono on void',
      sound: { base: 260, wave: 'sine' },
      vfx: { redact: 0.5, vignette: 0.5, scanlines: 0.2 },
      vars: vars({ accent: '#E8EDF2', accent2: '#8AB4FF', bg0: '#08090B', bg1: '#0F1113', bg2: '#16191C', bgHover: '#1B1F23', text: '#E8EDF2', textMid: '#9AA3AC', textDim: '#626B73' }),
    },
    {
      id: 'kraken', name: 'KRAKEN', tagline: 'Abyssal depths · god mode', secret: true,
      sound: { base: 170, wave: 'sawtooth' },
      vfx: { rain: 0.9, embers: 0.8, aurora: 0.4, scanlines: 0.5, vignette: 0.5, crt: 1.1, flicker: 0.8 },
      vars: vars({ accent: '#19FFD0', accent2: '#16E0FF', bg0: '#000806', bg1: '#021613', bg2: '#042420', bgHover: '#063029', text: '#B6FFF0', textMid: '#5FD9C2', textDim: '#338A7A' }),
    },
  ];

  const MAP = Object.fromEntries(THEMES.map(t => [t.id, t]));

  function isGod() { return localStorage.getItem('zb_god') === '1'; }

  function apply(id, opts) {
    const t = MAP[id] || THEMES[0];
    if (t.secret && !isGod() && !(opts && opts.force)) return MAP['kraken-blue'];
    const st = document.body.style;
    for (const k in t.vars) st.setProperty(k, t.vars[k]);
    // legacy body.theme-* classes are superseded by inline vars; clear them
    document.body.classList.remove('theme-orange', 'theme-red', 'theme-green');
    document.body.dataset.theme = t.id;
    localStorage.setItem('zb_theme', t.id);
    if (window.ZBSound) ZBSound.setTheme(t);
    if (window.ZBFX) ZBFX.applyTheme(t);
    document.dispatchEvent(new CustomEvent('zb-theme', { detail: t }));
    return t;
  }

  function current() { return MAP[document.body.dataset.theme] || MAP[localStorage.getItem('zb_theme')] || THEMES[0]; }
  function visible() { return THEMES.filter(t => isGod() || !t.secret); }

  function restore() { apply(localStorage.getItem('zb_theme') || 'kraken-blue'); }

  return { THEMES, MAP, apply, current, visible, restore, isGod };
})();
window.ZBThemes = ZBThemes;
