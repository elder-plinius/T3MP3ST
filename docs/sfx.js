/* t3mp3st sfx — synthesized sound effects for operator feedback (no audio assets).
   Loaded by every leaf page BEFORE its main script so the EventSource wrapper below
   can piggyback on the page's own /api/events connection:
     • SSE 'finding'    → discovery blip (severity-aware: critical/high = darker triple)
     • SSE 'credential' → vault coin (credential banked to the Evidence Vault)
     • #egressIpBadge red states (egress-leak / egress-no-ip / egress-error) → ominous drone
     • red → healthy transition → soft all-clear
   Mute chip is injected next to the egress badge; preference persists in localStorage.
   All audio is synthesized with Web Audio (context unlocks on the first operator gesture). */
(function () {
    'use strict';
    if (window.__t3SfxLoaded) return;
    window.__t3SfxLoaded = true;

    // ── preferences ──────────────────────────────────────────────────────────
    var LS_KEY = 't3mp3st_sfx_v1';
    var cfg = { enabled: true, volume: 0.8 };
    try {
        var saved = JSON.parse(localStorage.getItem(LS_KEY) || 'null');
        if (saved && typeof saved === 'object') {
            cfg.enabled = saved.enabled !== false;
            cfg.volume = typeof saved.volume === 'number' ? Math.min(1, Math.max(0, saved.volume)) : 0.8;
        }
    } catch (e) { /* corrupted prefs — defaults stand */ }
    function persistPrefs() {
        try { localStorage.setItem(LS_KEY, JSON.stringify(cfg)); } catch (e) { /* private mode */ }
    }

    // ── audio context (unlocked by the first operator gesture) ───────────────
    var ctx = null;
    var master = null;
    function audio() {
        if (!cfg.enabled) return null;
        try {
            if (!ctx) {
                var AC = window.AudioContext || window.webkitAudioContext;
                if (!AC) return null;
                ctx = new AC();
            }
            if (ctx.state === 'suspended') { ctx.resume().catch(function () { }); }
            return ctx.state === 'closed' ? null : ctx;
        } catch (e) { return null; }
    }
    function ensureMaster(c) {
        if (!master || master.context !== c) {
            master = c.createGain();
            master.connect(c.destination);
        }
        master.gain.value = cfg.volume;
    }
    ['pointerdown', 'keydown', 'touchstart'].forEach(function (evt) {
        window.addEventListener(evt, function () { audio(); }, { once: false, passive: true });
    });

    // ── synth primitives ─────────────────────────────────────────────────────
    function note(freq, start, dur, type, vol, glideTo) {
        var t0 = ctx.currentTime + start;
        var osc = ctx.createOscillator();
        var g = ctx.createGain();
        osc.type = type;
        osc.frequency.setValueAtTime(freq, t0);
        if (glideTo) osc.frequency.exponentialRampToValueAtTime(glideTo, t0 + dur);
        g.gain.setValueAtTime(0.0001, t0);
        g.gain.exponentialRampToValueAtTime(vol, t0 + 0.012);
        g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
        osc.connect(g); g.connect(master);
        osc.start(t0); osc.stop(t0 + dur + 0.06);
    }
    // Two detuned saws through a lowpass — beating interval = unease. Used by the ominous drone.
    function dronePair(f1, f2, start, dur, vol, cutoff, glideRatio) {
        var t0 = ctx.currentTime + start;
        var filter = ctx.createBiquadFilter();
        filter.type = 'lowpass';
        filter.frequency.value = cutoff || 260;
        var g = ctx.createGain();
        g.gain.setValueAtTime(0.0001, t0);
        g.gain.exponentialRampToValueAtTime(vol, t0 + 0.35);
        g.gain.setValueAtTime(vol, t0 + dur * 0.55);
        g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
        filter.connect(g); g.connect(master);
        [f1, f2].forEach(function (f) {
            var osc = ctx.createOscillator();
            osc.type = 'sawtooth';
            osc.frequency.setValueAtTime(f, t0);
            osc.frequency.exponentialRampToValueAtTime(f * (glideRatio || 0.89), t0 + dur);
            osc.connect(filter);
            osc.start(t0); osc.stop(t0 + dur + 0.1);
        });
    }

    // ── the effects ──────────────────────────────────────────────────────────
    function fxDiscovery() {                       // bright two-note sonar ping — new intel
        note(1318.5, 0, 0.09, 'sine', 0.12);
        note(1975.5, 0.06, 0.08, 'sine', 0.05);
    }
    function fxCritical() {                        // dark descending triple — critical/high finding
        note(523.3, 0, 0.1, 'square', 0.13);
        note(392.0, 0.1, 0.1, 'square', 0.13);
        note(261.6, 0.2, 0.18, 'square', 0.14);
    }
    function fxVault() {                           // coin deposit — credential banked to the vault
        note(987.8, 0, 0.07, 'triangle', 0.14);
        note(1318.5, 0.07, 0.22, 'triangle', 0.12);
        note(659.3, 0.07, 0.22, 'sine', 0.06);
    }
    function fxOminous() {                         // red egress — the exit IP is gone/leaking
        dronePair(55.0, 58.27, 0, 3.0, 0.17, 240, 0.89);     // A1 + B♭1-ish beat, sliding down
        dronePair(466.2, 493.9, 0.7, 1.8, 0.035, 900, 0.94); // faint high dissonance
        note(36.7, 0, 0.7, 'sine', 0.26, 29.0);              // sub thump
    }
    function fxAllClear() {                        // egress restored — soft rising fifth
        note(587.3, 0, 0.12, 'triangle', 0.08);
        note(880.0, 0.13, 0.2, 'triangle', 0.08);
    }

    // ── dispatch + burst throttling (a 100-finding sweep must not become a siren) ──
    var GAPS = { discovery: 900, discovery_crit: 900, vault: 1100, ominous: 5000, allclear: 5000 };
    var lastPlay = {};
    function play(name) {
        if (!cfg.enabled) return false;
        var now = Date.now();
        if (lastPlay[name] && now - lastPlay[name] < (GAPS[name] || 500)) return false;
        var c = audio();
        if (!c) return false;
        lastPlay[name] = now;
        try {
            ensureMaster(c);
            switch (name) {
                case 'discovery': fxDiscovery(); break;
                case 'discovery_crit': fxCritical(); break;
                case 'vault': fxVault(); break;
                case 'ominous': fxOminous(); break;
                case 'allclear': fxAllClear(); break;
                default: return false;
            }
            return true;
        } catch (e) { return false; }
    }

    // ── ride the page's own EventSource — zero extra server connections ─────
    function severityFromEvent(e) {
        try {
            var data = JSON.parse(e.data);
            return String((data.finding && data.finding.severity) || 'info').toLowerCase();
        } catch (err) { return 'info'; }
    }
    if (window.EventSource && !EventSource.prototype.__t3SfxPatched) {
        var origAdd = EventSource.prototype.addEventListener;
        EventSource.prototype.__t3SfxPatched = true;
        EventSource.prototype.addEventListener = function (type, fn, opts) {
            try {
                if (type === 'finding' && !this.__t3SfxFinding) {
                    this.__t3SfxFinding = true;
                    origAdd.call(this, 'finding', function (e) {
                        var sev = severityFromEvent(e);
                        play(sev === 'critical' || sev === 'high' ? 'discovery_crit' : 'discovery');
                    });
                }
                if (type === 'credential' && !this.__t3SfxCred) {
                    this.__t3SfxCred = true;
                    origAdd.call(this, 'credential', function () { play('vault'); });
                }
            } catch (e) { /* never break the host page */ }
            return origAdd.call(this, type, fn, opts);
        };
    }

    // ── egress badge monitor — ominous sting on red, all-clear on recovery ───
    function badgeIsRed() {
        var b = document.getElementById('egressIpBadge');
        if (!b || !b.classList) return null;
        return b.classList.contains('egress-leak') || b.classList.contains('egress-no-ip') || b.classList.contains('egress-error');
    }
    var lastRed = null;
    setInterval(function () {
        var red = badgeIsRed();
        if (red === null) return;
        if (lastRed === null) {
            lastRed = red;
            if (red) setTimeout(function () { play('ominous'); }, 400); // already red at load
            return;
        }
        if (red && !lastRed) play('ominous');
        else if (!red && lastRed) play('allclear');
        lastRed = red;
    }, 1500);

    // ── mute chip, parked next to the egress badge (fallback: bottom-right) ──
    function chipLabel() { return cfg.enabled ? '🔊' : '🔇'; }
    function injectChip() {
        if (document.getElementById('t3sfxChip')) return;
        var chip = document.createElement('button');
        chip.id = 't3sfxChip';
        chip.type = 'button';
        chip.title = 'Sound effects — click to ' + (cfg.enabled ? 'mute' : 'unmute');
        chip.textContent = chipLabel();
        chip.style.cssText = 'margin-left:6px;padding:3px 7px;font-size:12px;line-height:1;cursor:pointer;' +
            'border-radius:6px;border:1px solid rgba(255,255,255,0.18);background:rgba(255,255,255,0.06);color:#cfd;';
        chip.addEventListener('click', function () {
            cfg.enabled = !cfg.enabled;
            persistPrefs();
            chip.textContent = chipLabel();
            chip.title = 'Sound effects — click to ' + (cfg.enabled ? 'mute' : 'unmute');
            if (cfg.enabled) play('vault');
        });
        var badge = document.getElementById('egressIpBadge');
        if (badge && badge.parentNode) badge.parentNode.insertBefore(chip, badge.nextSibling);
        else {
            chip.style.cssText += ';position:fixed;right:12px;bottom:12px;z-index:99999;';
            document.body.appendChild(chip);
        }
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', injectChip);
    else injectChip();

    // ── public API ───────────────────────────────────────────────────────────
    window.t3Sfx = {
        play: play,
        enabled: function () { return cfg.enabled; },
        setEnabled: function (v) { cfg.enabled = !!v; persistPrefs(); return cfg.enabled; },
        toggle: function () { cfg.enabled = !cfg.enabled; persistPrefs(); return cfg.enabled; },
        setVolume: function (v) { cfg.volume = Math.min(1, Math.max(0, Number(v) || 0)); persistPrefs(); return cfg.volume; }
    };
})();
