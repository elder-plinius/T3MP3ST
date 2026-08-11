/* T3MP3ST War Room — sound notifications for mission lifecycle.
   Polls /api/mission/status (like the UI) and plays Web Audio tones on:
   - mission completed  -> success chime
   - mission aborted / stalled / refused -> error buzz
   Toggle button (speaker) bottom-left; preference saved in localStorage. */
(function () {
  'use strict';

  var LS_KEY = 't3mp3st_sounds';
  var enabled = true;
  try { enabled = localStorage.getItem(LS_KEY) !== 'off'; } catch (e) {}

  var AudioCtx = window.AudioContext || window.webkitAudioContext;
  var ctx = null;
  function ensureCtx() {
    if (!ctx && AudioCtx) { try { ctx = new AudioCtx(); } catch (e) {} }
    if (ctx && ctx.state === 'suspended') { try { ctx.resume(); } catch (e) {} }
    return ctx;
  }

  function tone(freq, start, dur, type, vol) {
    if (!ctx) return;
    var osc = ctx.createOscillator();
    var gain = ctx.createGain();
    osc.type = type || 'sine';
    osc.frequency.value = freq;
    gain.gain.setValueAtTime(0, ctx.currentTime + start);
    gain.gain.linearRampToValueAtTime(vol || 0.2, ctx.currentTime + start + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + start + dur);
    osc.connect(gain).connect(ctx.destination);
    osc.start(ctx.currentTime + start);
    osc.stop(ctx.currentTime + start + dur + 0.05);
  }

  function playSuccess() {
    if (!ensureCtx() || !enabled) return;
    tone(523.25, 0, 0.35, 'sine', 0.22);   // C5
    tone(659.25, 0.12, 0.35, 'sine', 0.22); // E5
    tone(783.99, 0.24, 0.5, 'sine', 0.22);  // G5
  }

  function playError() {
    if (!ensureCtx() || !enabled) return;
    tone(220, 0, 0.28, 'square', 0.14);
    tone(196, 0.32, 0.42, 'square', 0.14);
  }

  function playStart() {
    if (!ensureCtx() || !enabled) return;
    tone(440, 0, 0.18, 'sine', 0.14);
    tone(554.37, 0.1, 0.22, 'sine', 0.14);
  }

  var last = { status: null, id: null, stall: null };
  function check() {
    fetch('/api/mission/status', { signal: AbortSignal.timeout(8000) })
      .then(function (r) { return r.json(); })
      .then(function (s) {
        var status = s.mission && s.mission.status;
        var id = s.mission && s.mission.id;
        var stall = s.stallReason || null;
        if (!status || status === 'planning') { last.status = status; last.id = id; last.stall = stall; return; }
        if (id !== last.id) {
          // new mission started
          if (status === 'active') { playStart(); last.status = status; last.id = id; last.stall = stall; return; }
        }
        if (last.status === 'active' && status === 'completed') playSuccess();
        else if (last.status === 'active' && (status === 'aborted' || status === 'failed')) playError();
        else if (status === 'active' && stall && !last.stall) playError();
        last.status = status; last.id = id; last.stall = stall;
      })
      .catch(function () {});
  }

  function addToggle() {
    if (document.getElementById('t3mp3st-sound-toggle')) return;
    var btn = document.createElement('button');
    btn.id = 't3mp3st-sound-toggle';
    btn.textContent = enabled ? '\uD83D\uDD0A' : '\uD83D\uDD07';
    btn.title = 'Sound alerts: ' + (enabled ? 'ON' : 'OFF');
    btn.setAttribute('aria-label', 'Toggle sound alerts');
    btn.style.cssText = 'position:fixed;bottom:12px;left:12px;z-index:99999;' +
      'background:#102534;color:#9baeb8;border:1px solid #1e4053;border-radius:6px;' +
      'padding:4px 10px;font:600 12px/1.4 JetBrains Mono,monospace;cursor:pointer;';
    btn.addEventListener('click', function () {
      enabled = !enabled;
      try { localStorage.setItem(LS_KEY, enabled ? 'on' : 'off'); } catch (e) {}
      btn.textContent = enabled ? '\uD83D\uDD0A' : '\uD83D\uDD07';
      btn.title = 'Sound alerts: ' + (enabled ? 'ON' : 'OFF');
    });
    document.body.appendChild(btn);
  }

  function boot() {
    addToggle();
    check();
    setInterval(check, 3000);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
