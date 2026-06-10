/* ═══════════════════════════════════════════════════════════════════════════
   ZEROBREACH — SOUND ENGINE (Web Audio, fully synthesized — no audio files)
   Ported from PirateLife PLSound, extended with cinematic SFX for the
   Kraken unlock sequence. AudioContext is created lazily on first user
   gesture (browser autoplay policy). Theme sets base frequency + waveform.
   ═══════════════════════════════════════════════════════════════════════════ */
'use strict';

const ZBSound = (() => {
  let ctx = null, master = null;
  let muted  = (localStorage.getItem('zb_muted') === '1');
  let volume = parseFloat(localStorage.getItem('zb_vol') || '0.5');
  let base = 300, wave = 'triangle';
  let ambient = null;

  function ensure() {
    if (ctx) return ctx;
    try {
      ctx = new (window.AudioContext || window.webkitAudioContext)();
      master = ctx.createGain();
      master.gain.value = muted ? 0 : volume;
      master.connect(ctx.destination);
    } catch (e) { ctx = null; }
    return ctx;
  }
  function resume() { if (ctx && ctx.state === 'suspended') ctx.resume(); }

  function tone({ f = base, type = wave, dur = 0.12, vol = 0.3, attack = 0.005, decay, slideTo, when = 0 }) {
    if (!ensure() || muted) return;
    resume();
    const t0 = ctx.currentTime + when;
    const osc = ctx.createOscillator();
    const g = ctx.createGain();
    osc.type = type; osc.frequency.setValueAtTime(f, t0);
    if (slideTo) osc.frequency.exponentialRampToValueAtTime(Math.max(40, slideTo), t0 + dur);
    g.gain.setValueAtTime(0, t0);
    g.gain.linearRampToValueAtTime(vol, t0 + attack);
    g.gain.exponentialRampToValueAtTime(0.0001, t0 + (decay || dur));
    osc.connect(g); g.connect(master);
    osc.start(t0); osc.stop(t0 + (decay || dur) + 0.02);
  }

  function noise({ dur = 0.18, vol = 0.18, hp = 800, lp = 0, when = 0 }) {
    if (!ensure() || muted) return; resume();
    const t0 = ctx.currentTime + when;
    const n = Math.floor(ctx.sampleRate * dur);
    const buf = ctx.createBuffer(1, n, ctx.sampleRate);
    const d = buf.getChannelData(0);
    for (let i = 0; i < n; i++) d[i] = (Math.random() * 2 - 1) * (1 - i / n);
    const src = ctx.createBufferSource(); src.buffer = buf;
    let node = src;
    if (hp) { const f = ctx.createBiquadFilter(); f.type = 'highpass'; f.frequency.value = hp; node.connect(f); node = f; }
    if (lp) { const f = ctx.createBiquadFilter(); f.type = 'lowpass';  f.frequency.value = lp; node.connect(f); node = f; }
    const g = ctx.createGain(); g.gain.value = vol;
    node.connect(g); g.connect(master); src.start(t0);
  }

  const sounds = {
    // ── UI feedback ──
    hover:    () => tone({ f: base * 2.2, dur: 0.05, vol: 0.05, type: 'sine' }),
    click:    () => { tone({ f: base * 1.6, dur: 0.06, vol: 0.16 }); noise({ dur: 0.05, vol: 0.05, hp: 2000 }); },
    on:       () => tone({ f: base, slideTo: base * 2, dur: 0.12, vol: 0.18 }),
    off:      () => tone({ f: base * 1.6, slideTo: base * 0.7, dur: 0.12, vol: 0.14 }),
    tab:      () => tone({ f: base * 1.3, dur: 0.07, vol: 0.11, type: 'sine' }),
    open:     () => tone({ f: base * 0.8, slideTo: base * 1.5, dur: 0.16, vol: 0.15 }),
    close:    () => tone({ f: base * 1.5, slideTo: base * 0.7, dur: 0.14, vol: 0.13 }),
    confirm:  () => { tone({ f: base, dur: 0.1, vol: 0.2 }); tone({ f: base * 1.5, dur: 0.14, vol: 0.18, when: 0.08 }); },
    // ── scan / threat events ──
    deploy:   () => { tone({ f: base * 0.7, slideTo: base * 1.8, dur: 0.5, vol: 0.25, type: 'sawtooth' }); noise({ dur: 0.4, vol: 0.1, hp: 400 }); },
    tick:     () => tone({ f: base * 3, dur: 0.02, vol: 0.04, type: 'square' }),
    step:     () => tone({ f: base * 1.2, dur: 0.04, vol: 0.07, type: 'sine' }),
    scan:     () => tone({ f: base * 1.4, slideTo: base * 0.8, dur: 0.5, vol: 0.09, type: 'sine' }),
    complete: () => [0, 0.12, 0.24].forEach((w, i) => tone({ f: base * (1 + i * 0.5), dur: 0.2, vol: 0.2, when: w })),
    error:    () => { tone({ f: base * 0.5, type: 'square', dur: 0.18, vol: 0.22 }); tone({ f: base * 0.47, type: 'square', dur: 0.18, vol: 0.2, when: 0.1 }); },
    alert:    () => { tone({ f: base * 1.5, dur: 0.12, vol: 0.2, type: 'square' }); tone({ f: base * 1.5, dur: 0.12, vol: 0.18, type: 'square', when: 0.22 }); },
    danger:   () => { tone({ f: base * 0.6, type: 'sawtooth', dur: 0.3, vol: 0.22 }); tone({ f: base * 0.6 * 1.02, type: 'sawtooth', dur: 0.3, vol: 0.18 }); },
    boot:     () => { tone({ f: base * 0.5, slideTo: base * 2, dur: 1.1, vol: 0.18, type: 'sine' }); noise({ dur: 0.5, vol: 0.07, hp: 300 }); },
    lock:     () => { tone({ f: base * 1.4, slideTo: base * 0.5, dur: 0.3, vol: 0.2, type: 'square' }); noise({ dur: 0.18, vol: 0.08, hp: 600 }); },
    // ── Kraken cinematic SFX ──
    klaxon:   () => { for (let i = 0; i < 3; i++) { tone({ f: 660, slideTo: 440, dur: 0.28, vol: 0.22, type: 'sawtooth', when: i * 0.36 }); tone({ f: 663, slideTo: 442, dur: 0.28, vol: 0.16, type: 'square', when: i * 0.36 }); } },
    glitch:   () => { for (let i = 0; i < 6; i++) tone({ f: 200 + Math.random() * 2400, dur: 0.03, vol: 0.1, type: 'square', when: i * 0.04 }); noise({ dur: 0.25, vol: 0.12, hp: 1200 }); },
    thunk:    () => { tone({ f: 110, slideTo: 55, dur: 0.12, vol: 0.32, type: 'sine' }); noise({ dur: 0.06, vol: 0.14, hp: 80, lp: 900 }); },
    shatter:  () => { noise({ dur: 0.7, vol: 0.3, hp: 2500 }); for (let i = 0; i < 14; i++) tone({ f: 1800 + Math.random() * 4200, dur: 0.05 + Math.random() * 0.2, vol: 0.07, type: 'triangle', when: Math.random() * 0.45 }); tone({ f: 70, slideTo: 38, dur: 0.5, vol: 0.3, type: 'sine' }); },
    flashbang:() => { noise({ dur: 1.1, vol: 0.26, hp: 60, lp: 4000 }); tone({ f: 3200, dur: 1.4, vol: 0.06, type: 'sine' }); },
    splash:   () => { noise({ dur: 0.9, vol: 0.2, hp: 300, lp: 2400 }); tone({ f: 180, slideTo: 60, dur: 0.7, vol: 0.18, type: 'sine' }); },
    bubble:   () => tone({ f: 300 + Math.random() * 500, slideTo: 900 + Math.random() * 600, dur: 0.12, vol: 0.05, type: 'sine' }),
    sonar:    () => { tone({ f: 1180, dur: 0.5, decay: 1.6, vol: 0.16, type: 'sine' }); tone({ f: 1180, dur: 0.5, decay: 2.2, vol: 0.05, type: 'sine', when: 0.18 }); },
    descend:  () => { tone({ f: 160, slideTo: 42, dur: 2.6, vol: 0.14, type: 'sine' }); noise({ dur: 2.4, vol: 0.05, hp: 0, lp: 500 }); },
    heartbeat:() => { tone({ f: 58, dur: 0.1, vol: 0.34, type: 'sine' }); tone({ f: 52, dur: 0.1, vol: 0.28, type: 'sine', when: 0.22 }); },
    kraken:   () => {
      // deep abyssal roar: descending sawtooth swell + noise wash + rising sub
      tone({ f: base * 1.2,  slideTo: base * 0.35, dur: 1.4, vol: 0.3,  type: 'sawtooth' });
      tone({ f: base * 0.6,  slideTo: base * 0.28, dur: 1.4, vol: 0.22, type: 'sawtooth', when: 0.05 });
      tone({ f: base * 0.25, slideTo: base * 1.2,  dur: 1.6, vol: 0.18, type: 'sine',     when: 0.2 });
      noise({ dur: 1.2, vol: 0.16, hp: 200 });
      [0.5, 0.7, 0.95, 1.25].forEach((w, i) => tone({ f: base * (1 + i * 0.4), dur: 0.18, vol: 0.16, when: w }));
    },
    surge:    () => { tone({ f: 80, slideTo: 640, dur: 1.8, vol: 0.2, type: 'sawtooth' }); noise({ dur: 1.6, vol: 0.1, hp: 200 }); [0, 0.15, 0.3, 0.45, 0.6].forEach((w, i) => tone({ f: 220 * (1 + i * 0.5), dur: 0.3, vol: 0.12, when: 1.2 + w })); },
  };

  function play(name) { const fn = sounds[name]; if (fn) try { fn(); } catch (e) {} }

  function startAmbient() {
    if (!ensure() || muted || ambient) return; resume();
    const o1 = ctx.createOscillator(), o2 = ctx.createOscillator(), g = ctx.createGain(), lfo = ctx.createOscillator(), lg = ctx.createGain();
    o1.type = 'sine'; o1.frequency.value = base * 0.25; o2.type = 'sine'; o2.frequency.value = base * 0.25 * 1.01;
    lfo.frequency.value = 0.08; lg.gain.value = 0.02; lfo.connect(lg); lg.connect(g.gain);
    g.gain.value = 0.03; o1.connect(g); o2.connect(g); g.connect(master);
    o1.start(); o2.start(); lfo.start();
    ambient = { stop() { try { o1.stop(); o2.stop(); lfo.stop(); } catch (e) {} } };
  }
  function stopAmbient() { if (ambient) { ambient.stop(); ambient = null; } }

  return {
    play,
    setTheme(t) { if (t && t.sound) { base = t.sound.base; wave = t.sound.wave; } },
    setMuted(m) { muted = m; localStorage.setItem('zb_muted', m ? '1' : '0'); if (master) master.gain.value = m ? 0 : volume; if (m) stopAmbient(); },
    isMuted() { return muted; },
    setVolume(v) { volume = v; localStorage.setItem('zb_vol', String(v)); if (master && !muted) master.gain.value = v; },
    getVolume() { return volume; },
    startAmbient, stopAmbient,
    unlock() { ensure(); resume(); },
  };
})();
window.ZBSound = ZBSound;
