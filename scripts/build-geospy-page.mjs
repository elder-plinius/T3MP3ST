#!/usr/bin/env node
/**
 * Generates docs/geospy.html from docs/about.html's shell.
 * Buffer-level surgery with ASCII anchors â about.html has invalid UTF-8.
 */
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DOCS = join(ROOT, 'docs');

function once(s, needle) {
  const i = s.indexOf(needle);
  if (i < 0) throw new Error(`anchor not found: ${JSON.stringify(needle)}`);
  if (s.indexOf(needle, i + needle.length) >= 0) throw new Error(`anchor not unique: ${JSON.stringify(needle)}`);
  return i;
}

const GEOSPY_CONTENT = `
<style>
  .gs-wrap { max-width: 1100px; margin: 0 auto; }
  .gs-hero { border: 1px solid rgba(47,255,210,0.30); border-radius: 14px; padding: 20px 22px; margin-bottom: 16px;
             background: linear-gradient(135deg, rgba(47,255,210,0.10), rgba(100,150,255,0.06)); display:flex; gap:16px; align-items:center; flex-wrap:wrap; }
  .gs-hero h2 { color: #2fffd2; font-size: 20px; margin:0 0 6px; letter-spacing:0.5px; }
  .gs-hero p { font-size: 13px; color:#9baeb8; margin:0; line-height:1.55; }
  .gs-badge { display:inline-flex; align-items:center; gap:6px; font-size:11px; letter-spacing:1px; text-transform:uppercase;
              background: rgba(47,255,210,0.14); border:1px solid rgba(47,255,210,0.35); color:#2fffd2; padding:4px 10px; border-radius:20px; }
  .gs-grid { display:grid; grid-template-columns: 1.15fr 0.85fr; gap:14px; }
  @media (max-width: 900px){ .gs-grid{grid-template-columns:1fr;} }
  .gs-card { background: rgba(0,0,0,0.32); border:1px solid rgba(255,255,255,0.08); border-radius:12px; padding:14px 16px; }
  .gs-card h3 { color:#e0e0e0; font-size:13px; letter-spacing:0.6px; text-transform:uppercase; margin:0 0 10px; display:flex; align-items:center; gap:8px; }
  .gs-card h3 .accent{color:#2fffd2;}
  .gs-drop { border:2px dashed rgba(47,255,210,0.28); border-radius:12px; padding:28px 18px; text-align:center;
             background: rgba(47,255,210,0.04); cursor:pointer; transition: all .18s; }
  .gs-drop.drag { border-color:#2fffd2; background: rgba(47,255,210,0.10); transform: scale(1.01); }
  .gs-drop small{color:#6f8794; font-size:12px;}
  .gs-row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  .gs-btn { appearance:none; border:1px solid rgba(47,255,210,0.35); background: linear-gradient(135deg, #0e2a22, #123a30); color:#2fffd2;
            padding:9px 16px; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer; letter-spacing:0.3px; }
  .gs-btn:hover{ background: linear-gradient(135deg, #143d2f, #1a4d3f); }
  .gs-btn:disabled{ opacity:0.45; cursor:not-allowed; }
  .gs-btn.secondary{ background: rgba(255,255,255,0.06); border-color: rgba(255,255,255,0.14); color:#cbd8e0; }
  .gs-btn.secondary:hover{ background: rgba(255,255,255,0.10); }
  .gs-btn.active{ background: linear-gradient(135deg, #1a4d3f, #2fffd2); color:#001a14; border-color:#2fffd2; }
  .gs-meta { font-size:12px; color:#7a8a94; }
  .gs-kv { display:grid; grid-template-columns: 110px 1fr; gap:4px 10px; font-size:12.5px; }
  .gs-kv dt{ color:#6f8794; }
  .gs-kv dd{ color:#cbd8e0; word-break:break-word; }
  .gs-pill { display:inline-block; font-size:11px; padding:2px 8px; border-radius:10px; border:1px solid rgba(255,255,255,0.14); color:#9baeb8; background: rgba(255,255,255,0.04); margin:2px 4px 2px 0; }
  .gs-pill.high{ border-color: rgba(46,213,115,0.45); color:#2ed573; background: rgba(46,213,115,0.10); }
  .gs-pill.med{ border-color: rgba(255,177,66,0.45); color:#ffb142; background: rgba(255,177,66,0.10); }
  .gs-pill.low{ border-color: rgba(112,161,255,0.45); color:#70a1ff; background: rgba(112,161,255,0.10); }
  .gs-pill.none{ border-color: rgba(255,71,87,0.35); color:#ff6b78; background: rgba(255,71,87,0.08); }
  .gs-map { height: 360px; border-radius:10px; overflow:hidden; border:1px solid rgba(255,255,255,0.08); background:#0a141d; position:relative; isolation: isolate; z-index: 1; }  /* map must not paint above sticky header/nav: leaflet panes sit at 200-700 but header is 50 in the shell — pin header/sidebar above */  .header { z-index: 900 !important; }  .sidebar { z-index: 901 !important; }  .gs-ws { isolation: isolate; }  #gsMapWrap { isolation: isolate; }
  .gs-clue { font-size:12.5px; color:#9baeb8; padding:6px 10px; border-left:2px solid rgba(47,255,210,0.35); background: rgba(47,255,210,0.04); margin:6px 0; border-radius:0 8px 8px 0; }
  .gs-source { font-size:11px; letter-spacing:0.7px; text-transform:uppercase; padding:3px 8px; border-radius:6px; font-weight:700; }
  .gs-source.exif{ background: rgba(46,213,115,0.14); color:#2ed573; border:1px solid rgba(46,213,115,0.35); }
  .gs-source.vision{ background: rgba(112,161,255,0.14); color:#70a1ff; border:1px solid rgba(112,161,255,0.35); }
  .gs-source.hybrid{ background: linear-gradient(135deg, rgba(46,213,115,0.18), rgba(112,161,255,0.18)); color:#e0e0e0; border:1px solid rgba(47,255,210,0.35); }
  .gs-warn { border:1px solid rgba(255,170,0,0.40); background: rgba(255,170,0,0.08); color:#ffcf6b; border-radius:8px; padding:8px 12px; font-size:12.5px; }
  .gs-url-row { display:flex; gap:8px; margin-top:8px; }
  .gs-url-row input, .gs-url-row select{ flex:1; background: rgba(0,0,0,0.35); border:1px solid rgba(255,255,255,0.10); color:#cbd8e0; padding:8px 10px; border-radius:8px; font-size:12.5px; }
  .gs-url-row select{ flex:0 0 100%; max-width: 100%; cursor:pointer; }
  .gs-foot { font-size:11px; color:#5f7582; margin-top:10px; line-height:1.5; }
  .gs-exif-preview { margin-top:10px; font-size:12.5px; border:1px solid rgba(255,255,255,0.06); border-radius:8px; padding:10px 12px; background: rgba(255,255,255,0.03); display:none; }
  @keyframes gsDropPin { 0%{ transform: translateY(-40px); opacity:0; } 60%{ transform: translateY(6px); opacity:1; } 80%{ transform: translateY(-4px);} 100%{ transform: translateY(0); opacity:1; } }
  .gs-pin-drop { animation: gsDropPin 0.55s cubic-bezier(0.34,1.56,0.64,1) forwards; }
  /* ---- workspace: image lines up with map ---- */
  .gs-ws { min-height: 380px; display:flex; flex-direction:column; }
  .gs-preview { display:none; flex:1; min-height:344px; height:344px; border-radius:10px; overflow:hidden; border:1px solid rgba(255,255,255,0.08); background:
    repeating-conic-gradient(rgba(255,255,255,0.03) 0% 25%, transparent 0% 50%) 50% / 22px 22px, #050b10; align-items:center; justify-content:center; }
  .gs-preview img, .gs-preview video { width:100%; height:100%; display:block; object-fit:contain; background:transparent; }
  .gs-empty { height: 344px; min-height:344px; flex:1; border:1px dashed rgba(255,255,255,0.10); border-radius:10px; display:flex; align-items:center; justify-content:center; flex-direction:column; gap:6px; color:#5f7582; font-size:12.5px; background: rgba(255,255,255,0.02); }
  .gs-heic { display:none; text-align:center; padding:24px; color:#ffb142; font-size:13px; line-height:1.7; }
  /* ---- decluttered results: collapsible sections ---- */
  .gs-details { background: rgba(0,0,0,0.32); border:1px solid rgba(255,255,255,0.08); border-radius:12px; padding:0; margin-top:12px; overflow:hidden; }
  .gs-details > summary { cursor:pointer; list-style:none; padding:11px 16px; font-size:12px; letter-spacing:0.8px; text-transform:uppercase; color:#8ba3b0; font-weight:700; display:flex; align-items:center; gap:8px; user-select:none; }
  .gs-details > summary::-webkit-details-marker { display:none; }
  .gs-details > summary::before { content:'+'; color:#2fffd2; font-size:14px; width:14px; }
  .gs-details[open] > summary::before { content:'â'; }
  .gs-details[open] > summary { border-bottom:1px solid rgba(255,255,255,0.06); color:#cbd8e0; }
  .gs-details > .gs-details-body { padding:14px 16px; }
  .gs-badge-count { font-size:10.5px; padding:1px 7px; border-radius:9px; background: rgba(47,255,210,0.12); color:#2fffd2; border:1px solid rgba(47,255,210,0.30); }
  .gs-verdict { display:flex; flex-wrap:wrap; align-items:center; gap:8px 12px; }
  .gs-place-big { font-size:20px; font-weight:800; color:#e8f6f0; letter-spacing:0.2px; line-height:1.25; }
  .gs-coord-chip { font-family: ui-monospace,Consolas,monospace; font-size:12.5px; color:#2fffd2; background:rgba(47,255,210,0.08); border:1px solid rgba(47,255,210,0.30); padding:3px 9px; border-radius:7px; white-space:nowrap; }
  .gs-actions { display:flex; gap:6px; flex-wrap:wrap; margin-left:auto; }
  .gs-actions a, .gs-actions button { font-size:11.5px; padding:5px 10px; border-radius:7px; text-decoration:none; }
  .gs-h { font-size:11px; letter-spacing:0.9px; text-transform:uppercase; color:#6f8794; margin:14px 0 8px; padding-bottom:4px; border-bottom:1px solid rgba(255,255,255,0.07); font-weight:700; }
  .gs-h:first-child { margin-top:0; }
  .gs-lens-full .gs-url-row { display:block; }
  .gs-map-hint { font-size:11px; color:#5f7582; margin-top:6px; }
</style>

<div class="gs-wrap">
  <div class="gs-hero">
    <div style="flex:1; min-width:260px;">
      <div class="gs-badge">&#9673; GEOSPY LAB &mdash; SOCIAL ENGINEERING</div>
      <h2 style="margin-top:8px;">Image &amp; Video Geolocation</h2>
      <p>Drop a photo or video frame &mdash; we pull embedded GPS from EXIF and, when stripped, ask a vision model to read the scene like an analyst: landmarks, signage language, architecture, vegetation, terrain, sun angle. <b>Authorized research use only.</b></p>
    </div>
    <div style="min-width:220px; text-align:right;">
      <div id="gsVisionBadge" class="gs-meta">Checking vision provider...</div>
      <div class="gs-foot">EXIF is forensic truth. Vision is an AI guess &mdash; confidence is labeled. Video: first informative frame is auto-extracted on your device (no upload of raw video needed).</div>
    </div>
  </div>

  <div class="gs-grid">
    <!-- WORKSPACE LEFT: the upload, lined up with the map -->
    <div class="gs-card gs-ws" style="display:flex; flex-direction:column;">
      <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;"><span class="gs-h" style="margin:0; border:none; padding:0; flex:1;">Upload</span><span id="gsMeta" class="gs-meta"></span></div>
      <div id="gsEmpty" class="gs-empty" role="button" tabindex="0" title="Drop an image or video anywhere on this card">
        <div style="font-size:24px;">&#128247;</div>
        <div>Your image lines up here with the map</div>
        <div style="font-size:11px;">drop, paste (Ctrl+V), browse, or use the URL field below</div>
      </div>
      <div id="gsPreview" class="gs-preview">
        <img id="gsImg" alt="preview" style="display:none;" />
        <video id="gsVid" controls muted playsinline style="display:none;"></video>
        <canvas id="gsCanvas" style="display:none;"></canvas>
        <div id="gsHeicMsg" class="gs-heic"></div>
      </div>
      <div id="gsExifPreview" class="gs-exif-preview"></div>
      <div id="gsFrameHint" class="gs-meta" style="margin-top:6px; display:none;">Video: seek to the most telling frame, then hit LOCATE â the current frame will be sent.</div>
    </div>

    <!-- WORKSPACE RIGHT: the map -->
    <div class="gs-card gs-ws" style="display:flex; flex-direction:column;">
      <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;"><span class="gs-h" style="margin:0; border:none; padding:0; flex:1;">Map</span><button class="gs-btn secondary" id="gsSatToggle" style="font-size:11px; padding:4px 10px;">SATELLITE</button> <button class="gs-btn secondary" id="gs3dToggle" style="font-size:11px; padding:4px 10px;">3D</button></div>
      <div id="gsMapWrap" style="flex:1; position:relative; min-height:344px;">
        <div id="gsMap" style="position:absolute; inset:0; border-radius:10px; overflow:hidden; border:1px solid rgba(255,255,255,0.08); background:#0a141d;"></div>
        <div id="gsFrameWrap" style="display:none; position:absolute; inset:0; border-radius:10px; overflow:hidden; border:1px solid rgba(47,255,210,0.22); background:#010a12; z-index:5; flex-direction:column;">
          <div style="display:flex; align-items:center; gap:8px; padding:6px 8px; background:rgba(0,0,0,0.72); border-bottom:1px solid rgba(47,255,210,0.18); flex-shrink:0;">
            <button id="gsBackMap" class="gs-btn secondary" style="font-size:11px; padding:4px 8px;">&larr; Map</button>
            <span id="gsFrameLabel" class="gs-meta" style="flex:1; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;"></span>
            <a id="gsFramePop" href="#" target="_blank" rel="noopener" class="gs-meta" style="color:#2fffd2; text-decoration:none; font-size:11px;">Pop out &nearr;</a>
            <button id="gsFrameClose" class="gs-btn secondary" style="font-size:11px; padding:4px 8px;">&times;</button>
          </div>
          <iframe id="gsFrame" referrerpolicy="no-referrer" sandbox="allow-scripts allow-same-origin allow-popups allow-forms" style="width:100%; flex:1; border:0; background:#0a141d;"></iframe>
        </div>
      </div>
      <div class="gs-map-hint">Click map &rarr; <b>Maps 3D</b> in this window &middot; Right-click &rarr; <b>Street View</b> in this window &middot; Buttons stay in-window</div>
      <div class="gs-row" style="margin-top:6px;">
        <button id="gsOsmBtn" class="gs-btn secondary" style="font-size:12px; padding:5px 9px; display:none;">OSM</button>
        <button id="gsGmapsBtn" class="gs-btn secondary" style="font-size:12px; padding:5px 9px; display:none;">Google Maps</button>
        <button id="gsEarthBtn" class="gs-btn secondary" style="font-size:12px; padding:5px 9px; display:none;">Earth</button>
        <button id="gsStreetBtn" class="gs-btn secondary" style="font-size:12px; padding:5px 9px; display:none;">Street View</button>
        <span id="gsCoordLabel" class="gs-meta"></span>
      </div>
    </div>
  </div>

  <!-- INTAKE controls -->
  <div class="gs-card" style="margin-top:14px;">
    <div id="gsDrop" class="gs-drop" style="display:none;" tabindex="0" role="button" aria-label="Drop image or video here"></div>
    <input id="gsFile" type="file" accept="image/*,video/*" hidden />
    <div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px;">
      <div class="gs-url-row" style="margin-top:0;"><input id="gsUrl" placeholder="https://... image URL (optional) â fetched server-side" /></div>
      <div class="gs-url-row" style="margin-top:0;"><input id="gsContext" placeholder="Context (optional) â 'souk in Marrakech, afternoon'" /></div>
      <div class="gs-url-row" style="margin-top:0;"><input id="gsGuess" placeholder="Guess to validate (optional) â 'Paris?'" /></div>
      <div class="gs-url-row" style="margin-top:0;"><select id="gsModelSelect" title="Vision model override â Auto uses Settings default"><option value="">Auto (Settings default)</option></select></div>
      <div class="gs-url-row" style="margin-top:0;">
        <input id="gsApiKey" type="password" placeholder="Gemini API key (optional, this browser only)" autocomplete="off" spellcheck="false" />
        <button class="gs-btn secondary" id="gsApiKeySave" title="Save key in this browser only">Save</button>
        <button class="gs-btn secondary" id="gsApiKeyClear" title="Clear stored key">Clear</button>
      </div>
      <div class="gs-url-row" style="margin-top:0;">
        <button class="gs-btn" id="gsAnalyze" disabled style="flex:0 0 auto;">&#9889; LOCATE</button>
        <button class="gs-btn secondary" id="gsClear">Clear</button>
        <button class="gs-btn secondary" id="gsExport" style="display:none;">Export JSON</button>
        <label class="gs-meta" style="display:flex; align-items:center; gap:6px; cursor:pointer;"><input type="checkbox" id="gsVisionToggle" checked /> Vision</label>
      </div>
    </div>
    <div class="gs-foot" style="margin-top:8px;">Drop / paste a photo or video anywhere on this page &middot; EXIF GPS is parsed locally &middot; big photos are auto-compressed before the vision call (original kept for EXIF)</div>
  </div>

  <!-- RESULTS: verdict band + collapsible sections -->
  <div id="gsResults" style="display:none; margin-top:14px;">
    <div class="gs-card">
      <div class="gs-verdict">
        <div style="min-width:220px; flex:1;">
          <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;"><span class="gs-meta" style="letter-spacing:1px;">VERDICT</span><span id="gsSourcePill"></span><span id="gsConfPill"></span></div>
          <div id="gsPlace" class="gs-place-big" style="margin-top:5px;"></div>
          <div id="gsReverse" class="gs-meta" style="margin-top:3px;"></div>
        </div>
        <div style="display:flex; flex-direction:column; align-items:flex-end; gap:8px;">
          <span id="gsCoordChip" class="gs-coord-chip" style="display:none;"></span>
          <div id="gsActions" class="gs-actions"></div>
        </div>
      </div>
    </div>

    <details id="gsDAnalysis" class="gs-details" open>
      <summary>AI Analysis <span id="gsAnaCount" class="badge-count gs-badge-count" style="display:none;"></span></summary>
      <div class="gs-details-body">
        <div id="gsInterpretation" style="font-size:12.5px; color:#9baeb8; font-style:italic; background: rgba(255,255,255,0.03); border-left:2px solid rgba(100,150,255,0.35); padding:8px 10px; border-radius:0 8px 8px 0; margin-bottom:10px; display:none;"></div>
        <div id="gsVisionReason" style="font-size:13px; color:#cbd8e0; line-height:1.6; margin-bottom:4px;"></div>
        <div id="gsClues"></div>
        <div id="gsLandmarks" style="margin-top:8px;"></div>
        <div id="gsCandidates" style="margin-top:10px; display:none;"></div>
        <div id="gsVisionModel" class="gs-meta" style="margin-top:8px;"></div>
      </div>
    </details>

    <details id="gsDForensics" class="gs-details">
      <summary>Forensics &amp; Pivots <span id="gsForCount" class="badge-count gs-badge-count" style="display:none;"></span></summary>
      <div class="gs-details-body">
        <div id="gsExifBox"></div>
        <div id="gsDeviceIntel" style="margin-top:10px;"></div>
        <div class="gs-h">Pivots</div>
        <div id="gsPivots" style="display:flex; flex-wrap:wrap; gap:6px;"></div>
        <div id="gsHooksNote" class="gs-foot" style="margin-top:8px;"></div>
      </div>
    </details>

    <details id="gsDXcheck" class="gs-details">
      <summary>Google Cross-Check &mdash; Lens + Grounding <span id="gsXcCount" class="badge-count gs-badge-count" style="display:none;"></span></summary>
      <div class="gs-details-body">
        <div id="gsGrounding" style="display:none; margin-bottom:6px;"></div>
        <div id="gsLens" class="gs-lens-full" style="display:none;"></div>
        <div class="gs-warn" style="margin-top:10px;">&#9888; Lab use only â tracking links, cloned pages, and device hooks are receipted techniques for authorized assessments. Do not deploy against non-consenting targets.</div>
      </div>
    </details>
  </div>

  <div id="gsError" class="gs-warn" style="display:none; margin-top:14px;"></div>

  <div class="gs-foot" style="margin-top:14px; border-top:1px solid rgba(255,255,255,0.06); padding-top:10px;">
    How it works: <b>EXIF GPS</b> is parsed locally from JPEG APP1/TIFF (no upload needed for that check). <b>Vision AI</b> sends a compressed JPEG to your configured provider (OpenRouter / OpenAI / Gemini) with a geolocation prompt and optional context/guess â the image is not stored server-side. Results are logged to the Evidence Vault when a coordinate is produced. Inspired by the classic <b>Geospy</b> toolkit (Entynetproject) and <b>GeoIntel</b> (Gemini-powered multi-candidate analysis) â rebuilt here as a defensive lab.
  </div>
</div>

<script>
(function(){
  // Lazy API resolver â embed.js boots async, so T3MP3ST_API may not exist on first run.
  // Every call re-resolves; first success is cached.
  let _apiBase = null;
  function apiBase(){
    if (_apiBase !== null) return _apiBase;
    try {
      const braw = (window.T3MP3ST_API && window.T3MP3ST_API.baseUrl) ? String(window.T3MP3ST_API.baseUrl) : ''; const b = braw.endsWith('/') ? braw.slice(0,-1) : braw;
      if (b) { _apiBase = b; return b; }
    } catch(e){}
    return '';
  }
  function api(p){ const b = apiBase(); return (b ? b : '') + p; }
  // If embed.js loads late, pick up its baseUrl once
  window.addEventListener('t3mp3st:ready', function(){ try{ if(window.T3MP3ST_API && window.T3MP3ST_API.baseUrl){ const br=String(window.T3MP3ST_API.baseUrl); _apiBase = br.endsWith('/')?br.slice(0,-1):br; } }catch(e){} });
  // also poll briefly at boot â some shells set baseUrl after DOMContentLoaded
  let _poll = 0; const _int = setInterval(function(){ try{ if(window.T3MP3ST_API && window.T3MP3ST_API.baseUrl){ const br2=String(window.T3MP3ST_API.baseUrl); _apiBase = br2.endsWith('/')?br2.slice(0,-1):br2; clearInterval(_int);} }catch(e){} if(++_poll>20) clearInterval(_int); }, 250);

  const els = {
    drop: document.getElementById('gsDrop'),
    empty: document.getElementById('gsEmpty'),
    file: document.getElementById('gsFile'),
    url: document.getElementById('gsUrl'),
    ctx: document.getElementById('gsContext'),
    guess: document.getElementById('gsGuess'),
    modelSelect: document.getElementById('gsModelSelect'),
    apiKey: document.getElementById('gsApiKey'),
    apiKeySave: document.getElementById('gsApiKeySave'),
    apiKeyClear: document.getElementById('gsApiKeyClear'),
    preview: document.getElementById('gsPreview'),
    img: document.getElementById('gsImg'),
    vid: document.getElementById('gsVid'),
    canvas: document.getElementById('gsCanvas'),
    heicMsg: document.getElementById('gsHeicMsg'),
    exifPreview: document.getElementById('gsExifPreview'),
    analyze: document.getElementById('gsAnalyze'),
    clear: document.getElementById('gsClear'),
    exportBtn: document.getElementById('gsExport'),
    meta: document.getElementById('gsMeta'),
    frameHint: document.getElementById('gsFrameHint'),
    visionToggle: document.getElementById('gsVisionToggle'),
    visionBadge: document.getElementById('gsVisionBadge'),
    results: document.getElementById('gsResults'),
    error: document.getElementById('gsError'),
    mapEl: document.getElementById('gsMap'),
    satToggle: document.getElementById('gsSatToggle'),
    btn3d: document.getElementById('gs3dToggle'),
    coordLabel: document.getElementById('gsCoordLabel'),
    osm: document.getElementById('gsOsmBtn') || document.getElementById('gsOsmLink'),
    gmaps: document.getElementById('gsGmapsBtn') || document.getElementById('gsGmapsLink'),
    earth: document.getElementById('gsEarthBtn') || document.getElementById('gsEarthLink'),
    street: document.getElementById('gsStreetBtn') || document.getElementById('gsStreetLink'),
    coordChip: document.getElementById('gsCoordChip'),
    actions: document.getElementById('gsActions'),
    dAnalysis: document.getElementById('gsDAnalysis'),
    dForensics: document.getElementById('gsDForensics'),
    dXcheck: document.getElementById('gsDXcheck'),
    anaCount: document.getElementById('gsAnaCount'),
    forCount: document.getElementById('gsForCount'),
    xcCount: document.getElementById('gsXcCount'),
    sourcePill: document.getElementById('gsSourcePill'),
    confPill: document.getElementById('gsConfPill'),
    place: document.getElementById('gsPlace'),
    reverse: document.getElementById('gsReverse'),
    interpretation: document.getElementById('gsInterpretation'),
    reason: document.getElementById('gsVisionReason'),
    clues: document.getElementById('gsClues'),
    landmarks: document.getElementById('gsLandmarks'),
    candidates: document.getElementById('gsCandidates'),
    visionModel: document.getElementById('gsVisionModel'),
    exifBox: document.getElementById('gsExifBox'),
    deviceIntel: document.getElementById('gsDeviceIntel'),
    pivots: document.getElementById('gsPivots'),
    grounding: document.getElementById('gsGrounding'),
    lens: document.getElementById('gsLens'),
    hooksNote: document.getElementById('gsHooksNote'),
  };

  const GS_KEY_LS = 't3mp3st:geospy:geminiKey';
  function getStoredKey(){ try{ return (localStorage.getItem(GS_KEY_LS)||'').trim(); }catch(e){ return ''; } }
  function setStoredKey(v){ try{ if(v) localStorage.setItem(GS_KEY_LS, v); else localStorage.removeItem(GS_KEY_LS); }catch(e){} }
  let current = { b64: '', mime: 'image/jpeg', kind: 'image', w:0, h:0, bytes:0 };
  let map, marker, osmLayer, satLayer, satOn = false;
  setTimeout(function(){
    try{
      if(els.apiKey){ const k=getStoredKey(); if(k) els.apiKey.value=k; }
      if(els.apiKeySave) els.apiKeySave.addEventListener('click', function(){ const v=(els.apiKey&&els.apiKey.value.trim())||''; if(!v){ showError('Enter a Gemini API key first'); return; } setStoredKey(v); els.apiKeySave.textContent='Saved \u2713'; setTimeout(function(){ els.apiKeySave.textContent='Save'; }, 1400); clearError(); });
      if(els.apiKeyClear) els.apiKeyClear.addEventListener('click', function(){ setStoredKey(''); if(els.apiKey) els.apiKey.value=''; els.apiKeyClear.textContent='Cleared'; setTimeout(function(){ els.apiKeyClear.textContent='Clear'; }, 1200); });
    }catch(e){}
  }, 80);

  let lastVerdict = null;
  let leafletReady = typeof L !== 'undefined';

  function ensureMap(){
    if(map) return true;
    if(typeof L === 'undefined'){
      // Leaflet CDN may still be loading â poll briefly
      let tries = 0;
      const iv = setInterval(function(){
        if(typeof L !== 'undefined'){ clearInterval(iv); leafletReady = true; ensureMap(); }
        if(++tries > 20){ clearInterval(iv); els.mapEl.innerHTML = '<div style="padding:40px; text-align:center; color:#6f8794; font-size:13px;">Map unavailable â Leaflet failed to load.<br/>Coordinates and links still work below.</div>'; }
      }, 300);
      return false;
    }
    try {
      map = L.map('gsMap', { zoomControl:true }).setView([20,0], 2);
      osmLayer = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { attribution: '&copy; OpenStreetMap', maxZoom: 19 });
      satLayer = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', { attribution: 'Esri World Imagery', maxZoom: 19 });
      osmLayer.addTo(map);
      // Click map -> that point in Google Maps 3D; right-click -> Street View
      map.on('click', function(e){ openGmaps3D(e.latlng.lat, e.latlng.lng); });
      map.on('contextmenu', function(e){ openStreetView(e.latlng.lat, e.latlng.lng); });
      // invalidate after paint â container may have been hidden during init
      setTimeout(function(){ try{ map.invalidateSize(); }catch(e){} }, 250);
      return true;
    } catch(e){
      els.mapEl.innerHTML = '<div style="padding:20px; color:#ff6b78;">Map init failed: ' + String(e.message||e).slice(0,120) + '</div>';
      return false;
    }
  }
  // kick early, but also re-try on first setMap
  ensureMap();

  if(els.btn3d){
    els.btn3d.addEventListener('click', function(){
      const v = lastVerdict; const lat = v && v.lat, lon=v && v.lon;
      if(!Number.isFinite(lat) || !Number.isFinite(lon)){ showError('Run LOCATE first \u2014 no coordinate for 3D yet.'); return; }
      const la=Number(lat).toFixed(5), lo=Number(lon).toFixed(5);
      window.open('https://www.google.com/maps/@'+la+','+lo+',250a,35y,0h,45t/data=!3m1!1e3','_blank','noopener');
    });
  }
  if(els.satToggle){
    els.satToggle.addEventListener('click', function(){
      if(!map){ ensureMap(); if(!map) return; }
      // any embedded viewer goes away when toggling map layer
      try{ const w=document.getElementById('gsFrameWrap'); if(w) w.style.display='none'; }catch(e){}
      satOn = !satOn;
      try{
        if(satOn){ map.removeLayer(osmLayer); satLayer.addTo(map); els.satToggle.textContent = 'STREET'; els.satToggle.classList.add('active'); }
        else { map.removeLayer(satLayer); osmLayer.addTo(map); els.satToggle.textContent = 'SATELLITE'; els.satToggle.classList.remove('active'); }
      }catch(e){}
    });
  }

  // Map viewer — same-window embeds inside #gsMapWrap (no external tabs)
  function showMapLeaflet(){
    const w=document.getElementById('gsFrameWrap'), f=document.getElementById('gsFrame');
    if(w) w.style.display='none';
    if(f) f.removeAttribute('src');
    setTimeout(function(){ try{ map && map.invalidateSize(); }catch(e){} }, 120);
  }
  function showMapFrame(url, label){
    const w=document.getElementById('gsFrameWrap'), f=document.getElementById('gsFrame'), lb=document.getElementById('gsFrameLabel'), pop=document.getElementById('gsFramePop');
    if(!w||!f) { window.open(url,'_blank','noopener'); return; }
    const href = String(url||'#');
    f.src = href;
    if(lb) lb.textContent = label||href;
    if(pop) pop.href = href;
    w.style.display='flex'; w.style.flexDirection='column';
  }
  function osmEmbedUrl(lat, lon){ const la=Number(lat).toFixed(5), lo=Number(lon).toFixed(5); return 'https://www.openstreetmap.org/export/embed.html#map=16/'+la+'/'+lo; }
  function gmapsEmbedUrl(lat, lon){ const la=Number(lat).toFixed(6), lo=Number(lon).toFixed(6); return 'https://maps.google.com/maps?q='+la+','+lo+'&z=16&output=embed'; }
  function earthEmbedUrl(lat, lon){ const la=Number(lat).toFixed(6), lo=Number(lon).toFixed(6); return 'https://earth.google.com/web/@'+la+','+lo+',0a,1000d,35y,0h,0t,0r'; }
  function streetEmbedUrl(lat, lon){ const la=Number(lat).toFixed(6), lo=Number(lon).toFixed(6); return 'https://maps.google.com/maps?layer=c&cbll='+la+','+lo+'&cbp=12,0,0,0,1&output=svembed'; }
  function gmaps3dEmbedUrl(lat, lon){ const la=Number(lat).toFixed(6), lo=Number(lon).toFixed(6); return 'https://www.google.com/maps/@'+la+','+lo+',250a,35y,0h,45t/data=!3m1!1e3'; }
  function streetViewUrl(lat, lon){ const la=Number(lat).toFixed(6), lo=Number(lon).toFixed(6); return 'https://www.google.com/maps/@?api=1&map_action=pano&viewpoint='+la+','+lo; }
  function openGmaps3D(lat, lon){ showMapFrame(gmapsEmbedUrl(lat, lon), 'Google Maps — '+Number(lat).toFixed(5)+', '+Number(lon).toFixed(5)); }
  function openStreetView(lat, lon){ showMapFrame(streetEmbedUrl(lat, lon), 'Street View — '+Number(lat).toFixed(5)+', '+Number(lon).toFixed(5)); }
  function curLatLon(){ try{ if(!lastVerdict||!lastVerdict.candidates||!lastVerdict.candidates[0]) return null; const c=lastVerdict.candidates[0]; if(!Number.isFinite(c.lat)||!Number.isFinite(c.lon)) return null; return {lat:Number(c.lat), lon:Number(c.lon)}; }catch(e){ return null; } }
  // In-window delegations: verdict actions + locations cards (3D/Street View) and gs-pin (center map)
  (function bindFrameDelegations(){
    document.addEventListener('click', function(ev){
      const t = ev.target && ev.target.closest ? ev.target.closest('[data-act]') : null;
      if(!t) return;
      const act = String(t.getAttribute('data-act')||'').trim();
      const lat = parseFloat(t.getAttribute('data-lat')); const lon = parseFloat(t.getAttribute('data-lon'));
      const hasLL = Number.isFinite(lat) && Number.isFinite(lon);
      if(act==='Maps 3D' && hasLL){ ev.preventDefault(); showMapFrame(gmaps3dEmbedUrl(lat,lon), 'Maps 3D — '+lat.toFixed(5)+', '+lon.toFixed(5)); return; }
      if(act==='Street View' && hasLL){ ev.preventDefault(); showMapFrame(streetEmbedUrl(lat,lon), 'Street View — '+lat.toFixed(5)+', '+lon.toFixed(5)); return; }
      if(act==='OpenStreetMap true-center' && hasLL){ ev.preventDefault(); showMapFrame(osmEmbedUrl(lat,lon), 'OSM — '+lat.toFixed(5)+', '+lon.toFixed(5)); return; }
      if(act==='Google Earth true-center' && hasLL){ ev.preventDefault(); showMapFrame(earthEmbedUrl(lat,lon), 'Earth — '+lat.toFixed(5)+', '+lon.toFixed(5)); return; }
      if(act==='Lens reverse image (in-page)'){ // verdict lens link stacked with other docs — open url in frame if available
        const href = t.getAttribute('data-href') || t.getAttribute('href'); // buttons carry data-href
        if(href && /^https?:/i.test(href)){ ev.preventDefault(); showMapFrame(href, 'Lens'); return; }
        return;
      }
    });
    document.addEventListener('click', function(ev){
      const b = ev.target && ev.target.closest ? ev.target.closest('.gs-pin-btn') : null;
      if(!b) return; ev.preventDefault(); const la=parseFloat(b.getAttribute('data-lat')), lo=parseFloat(b.getAttribute('data-lon')); if(Number.isFinite(la)&&Number.isFinite(lo)) setMap(la,lo,(b.textContent||'').trim()||'Pinned');
    });
  })();
  (function bindTopFrameBtns(){
    function cur(){ return curLatLon(); }
    const ids = [['gsOsmBtn', function(p){ return p ? osmEmbedUrl(p.lat,p.lon) : '#'; }, 'OSM'], ['gsGmapsBtn', function(p){ return p ? gmapsEmbedUrl(p.lat,p.lon) : '#'; }, 'Google Maps'], ['gsEarthBtn', function(p){ return p ? earthEmbedUrl(p.lat,p.lon) : '#'; }, 'Earth'], ['gsStreetBtn', function(p){ return p ? streetEmbedUrl(p.lat,p.lon) : '#'; }, 'Street View']];
    ids.forEach(function(row){ const el=document.getElementById(row[0]); if(!el) return; el.addEventListener('click', function(ev){ ev.preventDefault(); const p=cur(); if(!p){ return; } const url=row[1](p); const lab=row[2]+' — '+p.lat.toFixed(5)+', '+p.lon.toFixed(5); showMapFrame(url,lab); }); });
    const back=document.getElementById('gsBackMap'), close=document.getElementById('gsFrameClose'); if(back) back.addEventListener('click', function(){ showMapLeaflet(); }); if(close) close.addEventListener('click', function(){ showMapLeaflet(); });
  })();

  function setMap(lat, lon, label){
    if(!ensureMap()) return;
    if(!map || !Number.isFinite(lat) || !Number.isFinite(lon)) return;
    const ll = [lat, lon];
    try{ map.invalidateSize(); }catch(e){}
    if(marker) { try{ map.removeLayer(marker); }catch(e){} marker = null; }
    // animated drop: marker with custom pane animation
    marker = L.marker(ll).addTo(map);
    // animate the icon via CSS class
    setTimeout(function(){
      try{
        const icon = marker.getElement && marker.getElement();
        if(icon) icon.classList.add('gs-pin-drop');
        else {
          const el = document.querySelector('.leaflet-marker-icon');
          if(el) el.classList.add('gs-pin-drop');
        }
      }catch(e){}
    }, 30);
    if(label) try{ marker.bindPopup(String(label).slice(0,160)).openPopup(); }catch(e){}
    // flyTo with animation â the "dropdown pin" effect
    try{ map.flyTo(ll, 14, { duration: 1.1, easeLinearity: 0.2 }); }catch{ map.setView(ll, 14); }
    setTimeout(function(){ try{ map.invalidateSize(); }catch(e){} }, 400);
    els.coordLabel.textContent = lat.toFixed(5) + ', ' + lon.toFixed(5);
    const la = lat.toFixed(5), lo = lon.toFixed(5);
    // keep legacy hrefs on els if present (compat), but new buttons drive the in-window viewer
    try{ if(els.osm) els.osm.href = 'https://www.openstreetmap.org/#map=16/' + la + '/' + lo; }catch(e){}
    try{ if(els.gmaps) els.gmaps.href = 'https://www.google.com/maps/search/?api=1&query=' + la + ',' + lo; }catch(e){}
    try{ if(els.earth) els.earth.href = 'https://earth.google.com/web/search/' + la + ',' + lo; }catch(e){}
    try{ if(els.street) els.street.href = 'https://www.google.com/maps/@?api=1&map_action=pano&viewpoint=' + la + ',' + lo; }catch(e){}
    ['gsOsmBtn','gsGmapsBtn','gsEarthBtn','gsStreetBtn'].forEach(function(id){ const b=document.getElementById(id); if(b) b.style.display='inline-flex'; });
  }

  async function checkStatus(){
    try{
      const r = await fetch(api('/api/geospy/status'));
      const j = await r.json();
      if(j.visionReady){
        els.visionBadge.innerHTML = '<span style="color:#2ed573;">&#9679; Vision ready</span> &mdash; ' + (j.model || j.provider) + ' <span style="opacity:0.6;">| EXIF forensics armed</span>';
      } else {
        els.visionBadge.innerHTML = '<span style="color:#ffb142;">&#9679; Vision not configured</span> &mdash; <a href="settings.html" style="color:#2fffd2;">Settings &rarr; API Keys</a> <span style="opacity:0.6;">| EXIF still works</span>';
        els.visionToggle.checked = false;
      }
      // populate model selector from visionModels (budget: show first 30)
      if(els.modelSelect && Array.isArray(j.visionModels)){
        const cur = els.modelSelect.value;
        // keep Auto + rebuild
        els.modelSelect.innerHTML = '<option value="">Auto (Settings default)</option>';
        const seen = new Set();
        for(let i=0;i<j.visionModels.length && i<50;i++){
          const m = j.visionModels[i];
          if(!m || !m.id || seen.has(m.id)) continue;
          seen.add(m.id);
          const opt = document.createElement('option');
          opt.value = m.id;
          opt.textContent = (m.label || m.id) + (m.provider ? ' ['+m.provider+']' : '');
          els.modelSelect.appendChild(opt);
        }
        // restore if still present
        if(cur && seen.has(cur)) els.modelSelect.value = cur;
        // default to server's model when present
        if(!cur && j.model && seen.has(j.model)) els.modelSelect.value = j.model;
      }
    }catch{ els.visionBadge.textContent = 'Status unavailable â server not reachable?'; }
  }
  checkStatus();

  function resetPreview(){
    if(current.objectUrl){ try{ URL.revokeObjectURL(current.objectUrl); }catch(e){} current.objectUrl = null; }
    if(els.file) els.file.value = '';
    try{ els.vid.pause(); }catch(e){}
    els.img.style.display='none'; try{ els.img.removeAttribute('src'); }catch(e){} els.img.src='';
    els.vid.style.display='none'; try{ els.vid.removeAttribute('src'); els.vid.load(); }catch(e){}
    if(els.heicMsg){ els.heicMsg.style.display='none'; els.heicMsg.textContent=''; els.heicMsg.innerHTML=''; }
    els.preview.style.display='none';
    if(els.empty) els.empty.style.display='flex';
    els.frameHint.style.display='none';
    els.exifPreview.style.display='none'; els.exifPreview.textContent='';
    current = { b64:'', mime:'image/jpeg', kind:'image', w:0, h:0, bytes:0 };
    els.analyze.disabled = true;
    els.meta.textContent='';
  }

  function showError(msg){
    els.error.style.display='block';
    els.error.textContent = msg;
  }
  function clearError(){ els.error.style.display=\'none\'; els.error.textContent=''; }

  function fileToB64(file){
    return new Promise(function(res, rej){
      const fr = new FileReader();
      fr.onload = function(){ const s = String(fr.result||''); const b64 = s.includes(',') ? s.split(',')[1] : s; res({ b64: b64, mime: file.type || 'image/jpeg', bytes: file.size }); };
      fr.onerror = function(){ rej(new Error('Failed to read file')); };
      fr.readAsDataURL(file);
    });
  }

  function canvasFromVideo(video){
    const w = video.videoWidth || 1280, h = video.videoHeight || 720;
    const maxW = 1280;
    let cw = w, ch = h;
    if(cw > maxW){ ch = Math.round(ch * maxW / cw); cw = maxW; }
    const c = document.createElement('canvas');
    c.width = cw; c.height = ch;
    const ctx = c.getContext('2d');
    ctx.drawImage(video, 0, 0, cw, ch);
    const dataUrl = c.toDataURL('image/jpeg', 0.82);
    return { b64: dataUrl.split(',')[1], mime:'image/jpeg', w:cw, h:ch };
  }

  function renderExifPreview(ex){
    if(!ex){ els.exifPreview.style.display=\'none\'; return; }
    let html = '';
    if(ex.hasGps){
      html += '<div style="color:#2ed573; font-weight:700;">&#9679; GPS found in EXIF: ' + Number(ex.lat).toFixed(6) + ', ' + Number(ex.lon).toFixed(6) + '</div>';
      if(ex.altitude!=null) html += '<div style="margin-top:4px; color:#9baeb8;">Altitude: ' + Math.round(ex.altitude) + ' m</div>';
      if(ex.make || ex.model) html += '<div style="margin-top:4px; color:#7a8a94;">Device: ' + String((ex.make||'')+' '+(ex.model||'')).trim().replace(/</g,'&lt;') + '</div>';
      if(ex.datetime) html += '<div style="color:#7a8a94;">Captured: ' + String(ex.datetime).replace(/</g,'&lt;') + '</div>';
      if(ex.raw && ex.raw.gpsTags) html += '<div style="margin-top:4px; font-size:11px; color:#5f7582;">GPS tags: ' + String(ex.raw.gpsTags).replace(/</g,'&lt;') + '</div>';
    } else {
      const hint = ex.strippedHint ? String(ex.strippedHint).replace(/</g,'&lt;') : 'No GPS tags in EXIF';
      html += '<div style="color:#ffb142;">&#9679; ' + hint + '</div>';
      if(ex.make || ex.model) html += '<div style="margin-top:4px; color:#7a8a94;">Device: ' + String((ex.make||'')+' '+(ex.model||'')).trim().replace(/</g,'&lt;') + '</div>';
      else html += '<div style="margin-top:4px; color:#6f8794; font-size:11px;">Tip: original photos from camera roll retain GPS; screenshots and social downloads strip it. Vision AI will still attempt a locate.</div>';
      if(ex.raw && ex.raw.ifd0Tags) html += '<div style="margin-top:4px; font-size:11px; color:#5f7582;">IFD0 tags present: ' + String(ex.raw.ifd0Tags).replace(/</g,'&lt;').slice(0,200) + '</div>';
    }
    els.exifPreview.innerHTML = html;
    els.exifPreview.style.display='block';
  }

  async function probeExif(b64){
    try{
      const r = await fetch(api('/api/geospy/exif'), { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ imageBase64: b64 }) });
      const j = await r.json();
      if(j && j.exif) renderExifPreview(j.exif);
    }catch(e){}
  }

  function showPreviewImage(){
    if(els.empty) els.empty.style.display=\'none\';
    els.preview.style.display=\'flex\';
  }

  async function handleFile(file){
    // clean previous video objectUrl
    if(current.objectUrl){ try{ URL.revokeObjectURL(current.objectUrl); }catch(e){} current.objectUrl = null; }
    if(els.heicMsg){ els.heicMsg.style.display='none'; els.heicMsg.innerHTML=''; }
    clearError(); els.results.style.display='none';
    if(!file){ return; }
    const t = (file.type||'').toLowerCase();
    const name = (file.name||'').toLowerCase();
    const extImage = /\\.(jpe?g|png|webp|heic|heif|bmp|gif|avif)$/i.test(name);
    const extVideo = /\.(mp4|mov|webm|m4v|avi|mkv)$/i.test(name);
    const isVideo = t.startsWith('video/') || (!t && extVideo);
    const isImage = t.startsWith('image/') || (!t && extImage) || (!isVideo && extImage);
    if(!isVideo && !isImage){ showError('Unsupported file -- use an image (JPEG/PNG/WEBP) or video (MP4/MOV/WEBM).'); return; }
    if(file.size > 25*1024*1024){ showError('File too large -- max 25 MB. Trim or compress and retry.'); return; }
    // HEIC/HEIF: Windows browsers cannot decode it in <img> -- use dedicated overlay, never destroy preview DOM
    const isHeic = t === 'image/heic' || t === 'image/heif' || /\.hei[cf]$/.test(name);
    if(isImage && isHeic){
      if(els.empty) els.empty.style.display='none';
      els.preview.style.display='flex';
      els.img.style.display='none'; try{ els.img.removeAttribute('src'); }catch(e){}
      els.vid.style.display='none'; try{ els.vid.pause(); els.vid.removeAttribute('src'); els.vid.load(); }catch(e){}
      if(els.heicMsg){
        els.heicMsg.innerHTML = '<div style="font-size:26px;">&#128247;</div><b>HEIC/HEIF photo -- Windows browsers cannot display it.</b><br/>The location work still cannot read it either. Convert first:<br/><span style="color:#9baeb8;">iPhone: Settings -> Camera -> Formats -> Most Compatible</span><br/><span style="color:#9baeb8;">or open the file in Paint / Photos and Save As JPEG, then drop it here</span>';
        els.heicMsg.style.display='block';
      }
      els.analyze.disabled = true;
      els.meta.textContent = file.name + ' -- HEIC -- convert to JPEG to analyze';
      showError('HEIC photo dropped -- convert to JPEG (or switch your camera to "Most Compatible") and drop it again.');
      return;
    }

    if(isImage){
      if(els.heicMsg) els.heicMsg.style.display='none';
      const data = await fileToB64(file);
      const b64 = data.b64, mime = data.mime, bytes = data.bytes;
      current = { b64: b64, mime: mime, kind:'image', w:0, h:0, bytes: bytes };
      // onload BEFORE src to avoid race on data: URLs; hide video, show image
      els.vid.style.display='none'; try{ els.vid.pause(); els.vid.removeAttribute('src'); els.vid.load(); }catch(e){}
      els.img.onload = function(){ current.w = els.img.naturalWidth; current.h = els.img.naturalHeight; els.meta.textContent += ' -- ' + current.w + 'x' + current.h; };
      els.img.onerror = function(){ showError('Preview failed to render -- try another file.'); els.meta.textContent += ' -- preview failed'; };
      els.img.src = 'data:' + mime + ';base64,' + b64;
      els.img.style.display='block';
      showPreviewImage();
      els.analyze.disabled = false;
      els.meta.textContent = file.name + ' -- ' + Math.round(bytes/1024) + ' KB -- ' + mime;
      // immediate EXIF probe -- this is the "not reading exif" fix: surface it on intake, not just after LOCATE
      probeExif(b64);
    } else {
      if(els.heicMsg) els.heicMsg.style.display='none';
      els.img.style.display='none'; try{ els.img.removeAttribute('src'); }catch(e){}
      // wire events BEFORE src
      els.vid.onloadedmetadata = function(){ current.w = els.vid.videoWidth; current.h = els.vid.videoHeight; };
      els.vid.onerror = function(){ showError('Video failed to load -- try MP4/MOV.'); if(current.objectUrl){ try{ URL.revokeObjectURL(current.objectUrl);}catch(e){} current.objectUrl=null; } };
      const url = URL.createObjectURL(file);
      els.vid.src = url;
      els.vid.style.display='block';
      showPreviewImage();
      els.frameHint.style.display='block';
      els.analyze.disabled = false;
      els.meta.textContent = file.name + ' -- ' + Math.round(file.size/1024) + ' KB -- video (seek to best frame, then LOCATE)';
      current = { b64:'', mime:'video/mp4', kind:'video', w:0, h:0, bytes: file.size, videoFile: file, objectUrl: url };
    }
  }

  // intake events
  if(els.empty){
    els.empty.addEventListener('click', function(){ els.file.click(); });
    els.empty.addEventListener('keydown', function(e){ if(e.key==='Enter' || e.key===' '){ e.preventDefault(); els.file.click(); }});
  }
  els.drop.addEventListener('click', function(){ els.file.click(); });
  els.drop.addEventListener('keydown', function(e){ if(e.key==='Enter' || e.key===' '){ e.preventDefault(); els.file.click(); }});
  els.file.addEventListener('change', function(){ const f=els.file.files && els.file.files[0]; if(f) handleFile(f); els.file.value=''; });
  // document-wide drag & drop -- drop anywhere on the page
  let dragDepth = 0;
  document.addEventListener('dragenter', function(e){ e.preventDefault(); dragDepth++; els.drop.classList.add('drag'); if(els.empty) els.empty.style.borderColor='rgba(47,255,210,0.5)'; });
  document.addEventListener('dragover', function(e){ e.preventDefault(); });
  document.addEventListener('dragleave', function(e){ e.preventDefault(); if(--dragDepth<=0){ dragDepth=0; els.drop.classList.remove('drag'); if(els.empty) els.empty.style.borderColor=''; } });
  document.addEventListener('drop', function(e){
    e.preventDefault(); dragDepth=0; els.drop.classList.remove('drag');
    if(els.empty) els.empty.style.borderColor='';
    const dt = e.dataTransfer;
    const f = dt && dt.files && dt.files[0];
    if(f){ handleFile(f); return; }
    // URL drop (e.g., dragging image from another tab)
    const uri = dt && (dt.getData('text/uri-list') || dt.getData('text/plain') || '');
    const u = (uri||'').trim().split(/\\s+/)[0] || '';
    if(u && /^https?:\/\/i.test(u)){ els.url.value = u; els.url.dispatchEvent(new KeyboardEvent('keydown', {key:'Enter'})); }
  });
  document.addEventListener('paste', async function(e){
    // Win copied file lives in clipboardData.files, not items
    if(e.clipboardData && e.clipboardData.files && e.clipboardData.files.length){
      const pf = [...e.clipboardData.files].find(function(f){ return /^image\\//.test(f.type) || /^video\\//.test(f.type) || /\.(jpe?g|png|webp|heic|heif|bmp|gif|mp4|mov|webm)$/i.test(f.name||''); });
      if(pf){ e.preventDefault(); await handleFile(pf); return; }
    }
    const items = [...(e.clipboardData && e.clipboardData.items || [])];
    const imgItem = items.find(function(i){ return i.type.startsWith('image/'); });
    if(imgItem){ const f = imgItem.getAsFile(); if(f) { e.preventDefault(); await handleFile(f); return; } }
    const vidItem = items.find(function(i){ return i.type.startsWith('video/'); });
    if(vidItem){ const f = vidItem.getAsFile(); if(f) { e.preventDefault(); await handleFile(f); return; } }
  });
  els.url.addEventListener('keydown', async function(e){
    if(e.key !== 'Enter') return;
    const u = els.url.value.trim(); if(!u) return;
    if(!(u.toLowerCase().startsWith('https://')||u.toLowerCase().startsWith('http://'))){ showError('Enter a valid http(s) image URL'); return; }
    clearError();
    try{
      els.url.disabled=true;
      const rr = await fetch(api('/api/geospy/fetch-image'), { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ imageUrl: u }) });
      const jj = await rr.json();
      if(!rr.ok) throw new Error(jj.error || ('HTTP '+rr.status));
      const b64 = jj.b64 || jj.imageBase64; const mime = jj.mime || 'image/jpeg';
      if(!b64) throw new Error('Server returned no image data');
      current = { b64: b64, mime: mime, kind:'image', w: jj.w||0, h: jj.h||0, bytes: Math.round(b64.length*0.75) };
      els.vid.style.display=\'none\'; try{ els.vid.pause(); els.vid.removeAttribute(\'src\'); els.vid.load(); }catch(e2){}
      els.img.onload = function(){ current.w = els.img.naturalWidth; current.h = els.img.naturalHeight; els.meta.textContent += ' â '+current.w+'x'+current.h; };
      els.img.onerror = function(){ showError('URL image preview failed to render â try downloading and dropping the file.'); };
      els.img.src = 'data:'+mime+';base64,'+b64;
      els.img.style.display=\'block\'; showPreviewImage(); els.analyze.disabled=false;
      els.meta.textContent = 'URL image â '+mime+' â '+Math.round(b64.length*0.75/1024)+' KB';
      probeExif(b64);
    }catch(err){ showError('Could not fetch URL via server: ' + (err.message||String(err)).slice(0,160) + ' â try downloading and dropping the file instead.'); }
    finally{ els.url.disabled=false; }
  });
  els.clear.addEventListener('click', function(){
    try{ const w=document.getElementById('gsFrameWrap'),f=document.getElementById('gsFrame'); if(w) w.style.display='none'; if(f) f.removeAttribute('src'); }catch(e){}
    resetPreview(); els.results.style.display=\'none\'; clearError(); els.url.value='';
    if(els.ctx) els.ctx.value=''; if(els.guess) els.guess.value='';
    els.exportBtn.style.display=\'none\'; lastVerdict=null;
    if(current.objectUrl) URL.revokeObjectURL(current.objectUrl);
    if(marker && map){ try{ map.removeLayer(marker); }catch(e){} marker=null; try{ map.setView([20,0],2); }catch(e){} }
    [els.osm, els.gmaps, els.earth, els.street].forEach(function(a){ if(a){ a.style.display=\'none\'; a.href=\'#\'; } });
    els.coordLabel.textContent='';
    if(els.coordChip) els.coordChip.style.display=\'none\';
    if(els.actions) els.actions.innerHTML=\'\';
  });

  els.exportBtn.addEventListener('click', function(){
    if(!lastVerdict){ showError('Nothing to export yet â run LOCATE first.'); return; }
    const blob = new Blob([JSON.stringify(lastVerdict, null, 2)], { type:'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const stamp = new Date().toISOString().replace(/[:.]/g,'-');
    a.href = url; a.download = 'geospy-' + stamp + '.json';
    document.body.appendChild(a); a.click();
    setTimeout(function(){ URL.revokeObjectURL(url); a.remove(); }, 1000);
  });

  function pillFor(conf){
    const c = String(conf||\'none\');
    if(c==='high') return '<span class="gs-pill high">HIGH</span>';
    if(c==='medium') return '<span class="gs-pill med">MEDIUM</span>';
    if(c==='low') return '<span class="gs-pill low">LOW</span>';
    return '<span class="gs-pill none">NONE</span>';
  }
  function sourcePill(src){
    const s = String(src||'vision');
    if(s==='exif') return '<span class="gs-source exif">EXIF GPS</span>';
    if(s==='hybrid') return '<span class="gs-source hybrid">EXIF + VISION</span>';
    return '<span class="gs-source vision">VISION AI</span>';
  }

  // Downscale big photos client-side before the vision call (10 MB JSON cap, faster upload).
  // The ORIGINAL b64 stays in current.b64 and rides along as exifImageBase64 â canvas re-encoding strips EXIF.
  function downscaleImage(b64, mime, maxW){
    return new Promise(function(res){
      try{
        const im = new Image();
        im.onload = function(){
          try{
            if(im.naturalWidth <= maxW && b64.length < 1_400_000){ res(null); return; } // small enough already
            const sc = Math.min(1, maxW / im.naturalWidth);
            const c = document.createElement('canvas');
            c.width = Math.max(1, Math.round(im.naturalWidth * sc));
            c.height = Math.max(1, Math.round(im.naturalHeight * sc));
            const ctx = c.getContext('2d');
            ctx.drawImage(im, 0, 0, c.width, c.height);
            const du = c.toDataURL('image/jpeg', 0.85);
            const nb = du.includes(',') ? du.split(',')[1] : du;
            if(nb && nb.length < b64.length) res({ b64: nb, mime:'image/jpeg', w:c.width, h:c.height });
            else res(null);
          }catch(e2){ res(null); }
        };
        im.onerror = function(){ res(null); };
        im.src = 'data:' + mime + ';base64,' + b64;
      }catch(e){ res(null); }
    });
  }

  function setBadge(el, n){
    if(!el) return;
    if(n > 0){ el.textContent = String(n); el.style.display='inline-block'; }
    else { el.style.display='none'; }
  }

  els.analyze.addEventListener('click', async function(){
    clearError();
    let b64 = current.b64, mime = current.mime;
    if(current.kind==='video'){
      if(!els.vid.videoWidth){ showError('Video not ready â wait for it to load, then seek to a clear frame.'); return; }
      try{
        if(els.vid.currentTime < 0.2 && els.vid.duration > 1) els.vid.currentTime = Math.min(1, els.vid.duration * 0.15);
        await new Promise(function(r){ setTimeout(r, 120); });
        const fr = canvasFromVideo(els.vid);
        b64 = fr.b64; mime = fr.mime;
      }catch(err){ showError('Could not extract video frame: ' + (err.message||String(err))); return; }
    }
    if(!b64 || b64.length < 100){ showError('No image data â drop an image or seek the video to a frame first.'); return; }

    els.analyze.disabled = true;
    els.analyze.textContent = 'Analyzing...';
    els.results.style.display=\'none\';

    try{
      const selModel = (els.modelSelect && els.modelSelect.value.trim()) || undefined;
      const inlineKey = (els.apiKey && els.apiKey.value.trim()) || getStoredKey() || undefined;
      // Vision payload: downscaled when the photo is big; EXIF always from the ORIGINAL
      let sendB64 = b64, sendMime = mime, exifB64;
      if(current.kind === 'image'){
        const ds = await downscaleImage(b64, mime, 1600);
        if(ds){ sendB64 = ds.b64; sendMime = ds.mime; exifB64 = b64 !== ds.b64 ? b64 : undefined; }
      }
      const _uFallback = els.url ? els.url.value.trim() : ''; const urlFallback = (!sendB64 || sendB64.length<100) && (_uFallback.toLowerCase().startsWith('https://')||_uFallback.toLowerCase().startsWith('http://')) ? _uFallback : undefined;
      const base = urlFallback ? { imageUrl: urlFallback, mime: sendMime } : { imageBase64: sendB64, mime: sendMime };
      if(exifB64) base.exifImageBase64 = exifB64;
      const payload = Object.assign(base, { doVision: els.visionToggle.checked, visionTimeoutMs: 25000, context: (els.ctx && els.ctx.value.trim()) || undefined, guess: (els.guess && els.guess.value.trim()) || undefined, model: selModel, apiKey: inlineKey });
      const headers = {'content-type':'application/json'};
      if(inlineKey) headers['x-api-key'] = inlineKey;
      const r = await fetch(api('/api/geospy/analyze'), {
        method:'POST',
        headers: headers,
        body: JSON.stringify(payload),
      });
      const j = await r.json();
      if(!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
      lastVerdict = j;
      els.exportBtn.style.display='inline-flex';

      els.results.style.display='block';
      els.sourcePill.innerHTML = sourcePill(j.source);
      els.confPill.innerHTML = pillFor(j.confidence);

      const lat = j.lat, lon = j.lon;
      const hasCoord = Number.isFinite(lat) && Number.isFinite(lon);
      // Verdict band: coord chip + one-click deep links (3D / Street View / OSM / Earth)
      if(els.coordChip){
        if(hasCoord){
          els.coordChip.textContent = Number(lat).toFixed(5) + ', ' + Number(lon).toFixed(5);
          els.coordChip.style.display='inline-block';
        } else { els.coordChip.style.display='none'; }
      }
      if(els.actions){
        if(hasCoord){
          const la2 = Number(lat).toFixed(5), lo2 = Number(lon).toFixed(5);
          const links = [
            ['Maps 3D &#9673;', 'https://www.google.com/maps/@'+la2+','+lo2+',250a,35y,0h,45t/data=!3m1!1e3', 'color:#2fffd2; border:1px solid rgba(47,255,210,0.4);'],
            ['Street View', 'https://www.google.com/maps/@?api=1&map_action=pano&viewpoint='+la2+','+lo2, ''],
            ['OSM &#8599;', 'https://www.openstreetmap.org/#map=16/'+la2+'/'+lo2, ''],
            ['Earth &#8599;', 'https://earth.google.com/web/search/'+la2+','+lo2, ''],
          ];
          els.actions.innerHTML = links.map(function(l){ return '<a class="gs-btn secondary" style="'+l[2]+'" href="'+l[1]+'" target="_blank" rel="noopener">'+l[0]+'</a>'; }).join('');
        } else { els.actions.innerHTML=''; }
      }
      els.place.textContent = j.vision && j.vision.place ? j.vision.place : (j.reverse && j.reverse.label ? j.reverse.label : (hasCoord ? lat.toFixed(5)+', '+lon.toFixed(5) : 'No location determined'));
      els.reverse.textContent = j.reverse && j.reverse.label ? j.reverse.label : (hasCoord ? '' : 'No coordinate â see clues and forensics below.');
      if(j.vision && j.vision.interpretation){
        els.interpretation.textContent = j.vision.interpretation;
        els.interpretation.style.display='block';
      } else { els.interpretation.textContent=''; els.interpretation.style.display=\'none\'; }
      els.reason.textContent = (j.vision && j.vision.reasoning) ? j.vision.reasoning : '';
      els.clues.innerHTML = '';
      const clues = (j.vision && j.vision.clues) || [];
      if(clues.length){
        els.clues.innerHTML = '<div class="gs-meta" style="margin-bottom:4px; font-weight:600;">Clues</div>' + clues.map(function(c){ return '<div class="gs-clue">'+ String(c).replace(/</g,'&lt;') +'</div>'; }).join('');
      }
      els.landmarks.innerHTML = '';
      const lms = (j.vision && j.vision.landmarks) || [];
      if(lms.length){
        els.landmarks.innerHTML = '<div class="gs-meta" style="font-weight:600;">Landmarks</div><div style="margin-top:4px;">' + lms.map(function(x){ return '<span class="gs-pill">'+ String(x).replace(/</g,'&lt;') +'</span>'; }).join('') + '</div>';
      }
      els.visionModel.textContent = j.vision ? ('Vision: ' + (j.vision.model||'unknown') + (j.vision.note ? ' â ' + j.vision.note : '')) : '';

      els.candidates.innerHTML = '';
      const locs = (j.vision && j.vision.locations) || [];
      if(locs.length){
        const rows = locs.map(function(l, i){
          const label = [l.city, l.state, l.country].filter(Boolean).join(', ') || ('Candidate ' + (i+1));
          const hasLL = Number.isFinite(l.lat) && Number.isFinite(l.lon);
          const coord = hasLL ? (Number(l.lat).toFixed(5)+', '+Number(l.lon).toFixed(5)) : 'no coord';
          const conf = String(l.confidence||'low');
          const expl = l.explanation ? String(l.explanation).replace(/</g,'&lt;').slice(0,220) : '';
          const gmaps = hasLL ? ('<button type="button" class="gs-btn secondary" data-act="Maps 3D" data-lat="'+Number(l.lat).toFixed(5)+'" data-lon="'+Number(l.lon).toFixed(5)+'" style="font-size:11px; padding:3px 7px; margin-left:6px; cursor:pointer;">3D</button> <button type="button" class="gs-btn secondary" data-act="Street View" data-lat="'+Number(l.lat).toFixed(5)+'" data-lon="'+Number(l.lon).toFixed(5)+'" style="font-size:11px; padding:3px 7px; margin-left:4px; cursor:pointer;">Street View</button> <button class="gs-btn secondary gs-pin-btn" data-lat="'+l.lat+'" data-lon="'+l.lon+'" style="font-size:10px; padding:3px 7px; margin-left:6px; cursor:pointer;">Pin</button>') : '';
          return '<div style="display:flex; gap:8px; align-items:flex-start; padding:7px 0; border-top:1px solid rgba(255,255,255,0.06);"><span class="gs-pill '+(conf==='high'?'high':conf==='medium'?'med':'low')+'" style="flex-shrink:0;">#'+(i+1)+' '+conf.toUpperCase()+'</span><div style="min-width:0; flex:1;"><div style="font-size:12.5px; color:#cbd8e0; font-weight:600;">'+ label.replace(/</g,'&lt;') +' <span style="font-weight:400; color:#6f8794;">'+ coord +'</span>'+ gmaps +'</div>'+ (expl ? '<div style="font-size:11.5px; color:#7a8a94; margin-top:3px; line-height:1.45;">'+ expl +'</div>' : '') +'</div></div>';
        }).join('');
        const title = locs.length===1 ? 'Top candidate \u2014 GeoIntel-style' : 'Ranked candidates \u2014 GeoIntel-style ('+locs.length+')';
        els.candidates.innerHTML = '<div class="gs-meta" style="font-weight:600; margin-bottom:4px;">'+title+'</div>' + rows;
        els.candidates.style.display='block';
        // wire Pin buttons (inline onclick can't see the closure-scoped Leaflet map)
        els.candidates.querySelectorAll('.gs-pin-btn').forEach(function(btn){
          btn.addEventListener('click', function(){
            const bla = Number(btn.getAttribute('data-lat')), blo = Number(btn.getAttribute('data-lon'));
            if(Number.isFinite(bla) && Number.isFinite(blo)) setMap(bla, blo, 'Candidate pin');
          });
        });
      } else { els.candidates.style.display=\'none\'; }

      const ex = j.exif || {};
      let exHtml = '';
      if(ex.hasGps){
        exHtml += '<div class="gs-kv"><dt>GPS</dt><dd><b style="color:#2ed573;">' + Number(ex.lat).toFixed(6) + ', ' + Number(ex.lon).toFixed(6) + '</b> &mdash; embedded in image</dd>';
        if(ex.altitude!=null) exHtml += '<dt>Altitude</dt><dd>' + Math.round(ex.altitude) + ' m</dd>';
        exHtml += '</div>';
      } else {
        exHtml += '<div class="gs-meta">' + (ex.strippedHint ? '&#9679; ' + String(ex.strippedHint).replace(/</g,'&lt;') : '&#9679; No GPS tags in EXIF') + '</div>';
      }
      if(ex.make || ex.model) exHtml += '<div class="gs-kv" style="margin-top:8px;"><dt>Device</dt><dd>' + String((ex.make||'') + ' ' + (ex.model||'')).trim().replace(/</g,'&lt;') + '</dd></div>';
      if(ex.datetime) exHtml += '<div class="gs-kv"><dt>Captured</dt><dd>' + String(ex.datetime).replace(/</g,'&lt;') + '</dd></div>';
      if(ex.raw && ex.raw.gpsTags) exHtml += '<div style="margin-top:6px; font-size:11px; color:#5f7582;">GPS tags: ' + String(ex.raw.gpsTags).replace(/</g,'&lt;') + '</div>';
      if(ex.raw && ex.raw.ifd0Tags) exHtml += '<div style="margin-top:6px; font-size:11px; color:#5f7582;">IFD0 tags: ' + String(ex.raw.ifd0Tags).replace(/</g,'&lt;').slice(0,200) + '</div>';
      exHtml += '<div class="gs-meta" style="margin-top:6px;">' + (ex.hasGps ? 'EXIF GPS is forensic truth â vision is not needed.' : 'Tip: original photos from camera roll retain GPS; screenshots and social downloads strip it.') + '</div>';
      els.exifBox.innerHTML = exHtml;

      // also sync the intake preview
      renderExifPreview(ex);

      els.deviceIntel.innerHTML = '';
      const intel = (j.hooks && j.hooks.deviceIntel) || [];
      if(intel.length) els.deviceIntel.innerHTML = intel.map(function(s){ return '<div class="gs-pill">'+ String(s).replace(/</g,'&lt;') +'</div>'; }).join('');

      els.pivots.innerHTML = '';
      const pivs = (j.hooks && j.hooks.pivots) || [];
      if(pivs.length) els.pivots.innerHTML = pivs.map(function(p){ return '<a href="' + String(p.url).replace(/"/g,'&quot;') + '" target="_blank" rel="noopener" class="gs-pill" style="text-decoration:none;">' + String(p.label).replace(/</g,'&lt;') + ' &#8599;</a>'; }).join('');
      // Google grounding second opinion + Lens push (like Google Images)
      const gg = j.googleGrounding;
      if(els.grounding){
        if(gg && Array.isArray(gg.hits) && gg.hits.length){
          els.grounding.innerHTML = '<div class="gs-meta" style="font-weight:600; margin-bottom:4px;">Google grounding â second opinion for "'+ String(gg.query).replace(/</g,'&lt;').slice(0,80) +'"</div>' + gg.hits.map(function(h){ return '<div style="padding:4px 0; border-top:1px solid rgba(255,255,255,0.06);"><a href="'+ String(h.url).replace(/"/g,'&quot;') +'" target="_blank" rel="noopener" style="color:#70a1ff; font-size:12.5px; text-decoration:none;">'+ String(h.title).replace(/</g,'&lt;') +'</a><div style="font-size:11px; color:#5f7582; word-break:break-all;">'+ String(h.url).replace(/</g,'&lt;').slice(0,90) +'</div></div>'; }).join('');
          els.grounding.style.display='block';
        } else if(gg && gg.note){ els.grounding.innerHTML = '<div class="gs-meta">Google grounding: '+ String(gg.note).replace(/</g,'&lt;') +'</div>'; els.grounding.style.display='block'; }
        else { els.grounding.innerHTML=''; els.grounding.style.display=\'none\'; }
      }
      if(els.lens){
        const lens = j.lens;
        const esc = function(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); };
        const isHttp = function(u){ u = String(u||'').trim().toLowerCase(); return u.startsWith('https://') || u.startsWith('http://'); };
        const hitCount = (lens && Array.isArray(lens.hits) && lens.hits.length) || 0;
        const handoff = ((lens && (lens.lensHandoff || lens.queryHint)) || '');
        if(!lens || (hitCount===0 && !lens.refinedVision && !(handoff && isHttp(handoff)))){
          els.lens.innerHTML = '<div class="gs-meta">Reverse image: no matches for this image. <a href="https://lens.google.com/upload" target="_blank" rel="noopener" style="color:#2fffd2;">Try Google Lens manually &#8599;</a></div>';
          els.lens.style.display='block';
        } else {
          let html = '';
          if(handoff && isHttp(handoff)){
            html += '<a class="gs-btn" href="'+esc(handoff)+'" target="_blank" rel="noopener" style="font-size:12px; padding:6px 12px; text-decoration:none; margin-bottom:10px; display:inline-flex;">Open full results in Google Lens &#8599;</a>';
          }
          if(lens.note) html += '<div class="gs-meta" style="color:#ffb142; margin-bottom:6px;">' + esc(lens.note) + '</div>';
          const rv = lens.refinedVision;
          if(rv){
            const hasLL = Number.isFinite(rv.lat) && Number.isFinite(rv.lon);
            html += '<div style="border:1px solid rgba(47,255,210,0.30); border-radius:10px; padding:10px 12px; background: linear-gradient(135deg, rgba(47,255,210,0.08), rgba(100,150,255,0.05)); margin-bottom:10px;">';
            html += '<div style="font-size:11px; letter-spacing:0.6px; text-transform:uppercase; color:#2fffd2; font-weight:700;">Match re-analyzed via ' + esc(rv.model||'vision') + '</div>';
            if(rv.place) html += '<div style="font-size:14px; color:#e0e0e0; font-weight:700; margin-top:4px;">' + esc(rv.place) + '</div>';
            if(hasLL) html += '<div class="gs-meta" style="margin-top:2px;">' + Number(rv.lat).toFixed(5) + ', ' + Number(rv.lon).toFixed(5) + ' &nbsp;' + pillFor(rv.confidence) + '</div>';
            else html += '<div class="gs-meta" style="margin-top:2px;">' + pillFor(rv.confidence) + (rv.city||rv.country ? ' -- ' + esc([rv.city, rv.state, rv.country].filter(Boolean).join(', ')) : '') + '</div>';
            if(rv.reasoning) html += '<div style="font-size:12.5px; color:#9baeb8; margin-top:6px; line-height:1.55;">' + esc(rv.reasoning).slice(0,620) + '</div>';
            if(hasLL) html += '<button class="gs-btn" data-lens-use style="margin-top:8px; font-size:12px; padding:6px 12px;" data-lat="'+rv.lat+'" data-lon="'+rv.lon+'" data-label="'+esc(rv.place||rv.city||'Lens hit')+'">Use Lens pin on map &#9673;</button>';
            const fromUrl = (lens.refinedFrom && (lens.refinedFrom.url||lens.refinedFrom.imageUrl)) || '';
            const fromTitle = (lens.refinedFrom && lens.refinedFrom.title) || 'top match';
            if(fromUrl && isHttp(fromUrl)) html += '<div class="gs-meta" style="margin-top:6px;">from: <a href="'+esc(fromUrl)+'" target="_blank" rel="noopener" style="color:#70a1ff; word-break:break-all;">' + esc(fromTitle).slice(0,90) + '</a></div>';
            html += '</div>';
          }
          const hits = Array.isArray(lens.hits) ? lens.hits.slice(0,10) : [];
          if(hits.length){
            html += '<div style="display:grid; grid-template-columns: repeat(auto-fill, minmax(210px, 1fr)); gap:8px;">';
            hits.forEach(function(h){
              const tit = esc((h.title||'Match').slice(0,110));
              // Click target: validated page URL only -- google-internal shells become display-only cards
              let href = String(h.url||'').trim();
              if(!isHttp(href) || /(^|\\\.)google\\\.[a-z.]+\\\/(search|url\\\?|imgres)/i.test(href)) href = String(h.imageUrl||'').trim();
              if(!isHttp(href)) href = '';
              const linkAttrs = href ? (' href="'+esc(href)+'" target="_blank" rel="noopener"') : '';
              // Thumb: server-fetched data URL first (cannot be blocked), then Bing-hosted turl (hotlink-safe)
              var rawSrc = String(h.thumbDataUrl || h.thumbUrl || h.imageUrl || '').trim();
              var src = rawSrc;
              if(src && /^https?:/i.test(src) && src.slice(0,7).toLowerCase()==='http://'){ src = 'https://' + src.slice(7); }
              var iu = String(h.imageUrl||'').trim(); var fbRaw = (iu && iu.toLowerCase().startsWith('http://')) ? ('https://' + iu.slice(7)) : iu; var fb = (iu && !src.startsWith('data:') && iu !== String(src).trim()) ? fbRaw : ''; var fbAttr = fb ? (' data-fallback="' + esc(fb) + '"') : '';
              let imgTag;
              if(src){
                imgTag = '<img src="'+esc(src)+'"' + fbAttr + ' alt="" referrerpolicy="no-referrer" style="width:100%; height:132px; object-fit:cover; border-radius:6px 6px 0 0; background:#050b10; display:block;" loading="lazy" onerror="if(this.dataset.fallback&&this.src!==this.dataset.fallback){this.src=this.dataset.fallback;return;}this.onerror=null;this.style.display=\\'none\\';var t=this.nextElementSibling;if(t&&t.classList.contains(\\'gs-fb\\'))t.style.display=\\'flex\\';" />' + '<div class="gs-fb" style="display:none; align-items:center; justify-content:center; height:132px; font-size:11px; color:rgba(255,255,255,0.52); background:#07121a; border-radius:6px 6px 0 0; text-align:center; padding:0 10px; overflow:hidden;">preview unavailable &#8212; <a href="' + esc(String(h.imageUrl||h.pageUrl||'#')) + '" target="_blank" rel="noopener" style="color:#2fffd2; margin-left:4px;">open</a></div>';
              } else {
                imgTag = '<div style="height:132px; background: rgba(255,255,255,0.04); border-radius:6px 6px 0 0; display:flex; align-items:center; justify-content:center; color:#5f7582; font-size:11px;">no preview' + (href ? ' -- <a'+linkAttrs+' style="color:#70a1ff; margin-left:4px;">open</a>' : '') + '</div>';
              }
              const wrapOpen = href ? '<a'+linkAttrs+' style="display:block; line-height:0;">' : '';
              const wrapClose = href ? '</a>' : '';
              const reanalyzeUrl = String(h.imageUrl || h.thumbUrl || '').trim();
              html += '<div style="border:1px solid rgba(255,255,255,0.08); border-radius:10px; overflow:hidden; background: rgba(0,0,0,0.22); display:flex; flex-direction:column;">' + wrapOpen + imgTag + wrapClose + '<div style="padding:8px 10px; flex:1; display:flex; flex-direction:column; gap:6px;">';
              html += '<div style="font-size:12px; color:#cbd8e0; font-weight:600; line-height:1.35;">' + tit + '</div>';
              if(href) html += '<a'+linkAttrs+' style="font-size:11px; color:#70a1ff; word-break:break-all;">' + esc(href.replace(/^https?:\\\/\\\//,'').slice(0,80)) + '</a>';
              if(reanalyzeUrl && isHttp(reanalyzeUrl)) html += '<button class="gs-btn secondary lens-reanalyze" data-img="'+esc(reanalyzeUrl)+'" style="font-size:11px; padding:5px 8px; margin-top:auto; cursor:pointer;">Re-analyze via vision &#8635;</button>';
              html += '</div></div>';
            });
            html += '</div>';
          }
          html += '<div class="gs-meta" style="margin-top:8px;">Matches via Bing Visual (server-side, keyless) -- hit <b>Re-analyze</b> to run any match back through the vision model. Machine reverse-image needs a public URL; uploads get the Lens hand-off above.</div>';
          els.lens.innerHTML = html;
          // wire re-analyze
          els.lens.querySelectorAll('.lens-reanalyze').forEach(function(btn){
            btn.addEventListener('click', async function(){
              const imgUrl = btn.getAttribute('data-img')||'';
              if(!imgUrl) return;
              const prev = btn.textContent;
              btn.textContent='Analyzing...'; btn.disabled=true;
              try{
                const inlineKey2 = (els.apiKey && els.apiKey.value.trim()) || getStoredKey() || undefined;
                const h2={ 'content-type':'application/json' }; if(inlineKey2) h2['x-api-key']=inlineKey2;
                const rr = await fetch(api('/api/geospy/lens'), { method:'POST', headers:h2, body: JSON.stringify({ imageBase64: b64, mime: mime, doRefine:true, model: selModel, context: (els.ctx&&els.ctx.value.trim())||undefined, guess: (els.guess&&els.guess.value.trim())||undefined, refineImageUrl: imgUrl, apiKey: inlineKey2 }) });
                const jj = await rr.json();
                if(!rr.ok) throw new Error(jj.error||('HTTP '+rr.status));
                const rv2 = jj.refinedVision;
                if(!rv2){ btn.textContent='No location from this hit'; setTimeout(function(){ btn.textContent=prev; btn.disabled=false; }, 2500); return; }
                const hasLL2 = Number.isFinite(rv2.lat) && Number.isFinite(rv2.lon);
                btn.textContent = (rv2.place||rv2.city||'Analyzed') + ' â ' + String(rv2.confidence||'').toUpperCase();
                const card = btn.closest('div');
                if(card){
                  const resEl = document.createElement('div');
                  resEl.style.cssText='margin-top:6px; padding:7px 8px; border-radius:7px; background: rgba(47,255,210,0.08); border:1px solid rgba(47,255,210,0.20); font-size:11.5px; color:#cbd8e0; line-height:1.45;';
                  const line1 = (rv2.place||[rv2.city,rv2.state,rv2.country].filter(Boolean).join(', ')||'No place') + (hasLL2 ? ' ('+Number(rv2.lat).toFixed(5)+', '+Number(rv2.lon).toFixed(5)+')' : '');
                  resEl.innerHTML = '<div style="font-weight:600; color:#e0e0e0;">'+esc(line1)+' &nbsp;'+pillFor(rv2.confidence)+'</div><div style="margin-top:4px; color:#9baeb8;">'+esc((rv2.reasoning||'').slice(0,340))+'</div>';
                  if(hasLL2){
                    const useBtn = document.createElement('button');
                    useBtn.className='gs-btn'; useBtn.style.cssText='font-size:11px; padding:4px 8px; margin-top:7px;'; useBtn.textContent='Use this pin';
                    useBtn.addEventListener('click', function(){ setMap(Number(rv2.lat), Number(rv2.lon), rv2.place||'Lens hit'); });
                    resEl.appendChild(useBtn);
                  }
                  card.appendChild(resEl);
                }
                if(hasLL2) setMap(Number(rv2.lat), Number(rv2.lon), rv2.place||'Lens hit');
              }catch(err){ btn.textContent='Failed: '+(err.message||String(err)).slice(0,56); setTimeout(function(){ btn.textContent=prev; btn.disabled=false; }, 2600); }
            });
          });
          els.lens.querySelectorAll('[data-lens-use]').forEach(function(b){
            b.addEventListener('click', function(){
              const la = Number(b.getAttribute('data-lat')), lo = Number(b.getAttribute('data-lon')), lb = b.getAttribute('data-label')||'Lens refinement';
              if(Number.isFinite(la) && Number.isFinite(lo)) setMap(la, lo, lb);
            });
          });
        }
        els.lens.style.display='block';
      }
      els.hooksNote.textContent = (j.hooks && j.hooks.trackingLinkHint) || '';

      // section badges + smart collapse: only open what actually has something to say
      setBadge(els.anaCount, clues.length + lms.length + locs.length);
      setBadge(els.forCount, (ex.hasGps ? 1 : 0) + intel.length);
      const lensHits = (j.lens && j.lens.hits && j.lens.hits.length) || 0;
      setBadge(els.xcCount, lensHits);
      if(els.dForensics) els.dForensics.open = !!ex.hasGps;
      if(els.dXcheck) els.dXcheck.open = !!(j.lens && (j.lens.refinedVision || lensHits > 0));

      if(hasCoord) setMap(lat, lon, (j.vision && j.vision.place) || (j.reverse && j.reverse.label) || '');

      try{ els.results.scrollIntoView({ behavior:'smooth', block:'start' }); }catch(e){}
    }catch(err){
      showError(err.message || String(err));
    }finally{
      els.analyze.disabled = false;
      els.analyze.textContent = 'LOCATE';
    }
  });
})();
</script>
`;

const aboutBuf = readFileSync(join(DOCS, 'about.html'));
const s = aboutBuf.toString('latin1');

const tOpen = once(s, '<title>');
const tClose = once(s, '</title>');
const h1 = once(s, 'id="pageTitle">About<');
const pageDiv = once(s, '<div class="page active" id="page-about">');
const pageDivEnd = pageDiv + '<div class="page active" id="page-about">'.length;
const mainClose = s.indexOf('</main>', pageDivEnd);
if (mainClose < 0) throw new Error('no </main> after page div');
const lastDivClose = s.lastIndexOf('</div>', mainClose);
if (lastDivClose <= pageDivEnd) throw new Error('content region empty');

const headStr =
  s.slice(0, tOpen) + '<title>T3MP3ST - Geospy Lab</title>' +
  s.slice(tClose + '</title>'.length, h1) + 'id="pageTitle">Geospy Lab<' +
  s.slice(h1 + 'id="pageTitle">About<'.length, pageDivEnd)
    .replace('<div class="page active" id="page-about">', '<div class="page active" id="page-geospy">');
const headBuf = Buffer.from(headStr, 'latin1');

const outBuf = Buffer.concat([
  headBuf,
  Buffer.from(GEOSPY_CONTENT, 'utf8'),
  aboutBuf.subarray(lastDivClose),
]);

// Patch the leaflet CSS/JS â geospy needs the map. about.html has no leaflet.
let outStr = outBuf.toString('latin1');
const fontsAnchor = 'href="https://fonts.googleapis.com';
const at = outStr.indexOf(fontsAnchor);
if (at < 0) throw new Error('fonts anchor missing');
const linkEnd = outStr.indexOf('>', at) + 1;
outStr = outStr.slice(0, linkEnd) +
  '\n    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">\n    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"><' + '/script>' +
  outStr.slice(linkEnd);
const finalBuf = Buffer.from(outStr, 'latin1');

writeFileSync(join(DOCS, 'geospy.html'), finalBuf);
console.log('geospy.html written:', finalBuf.length, 'bytes (from about.html', aboutBuf.length + ')');

// Add Geospy nav before GPS on every docs page that has the GPS link (or before About as fallback)
const NAV = Buffer.from(
  '<a class="nav-item" href="geospy.html" title="Geospy â image & video geolocation (social engineering lab)"><span class="icon">&#127758;</span> Geospy Lab</a>\n', 'utf8');

const candidates = ['<a class="nav-item" href="gps.html"', '<a class="nav-item" href="about.html"'];
const pages = readdirSync(DOCS).filter(f => f.endsWith('.html'));
for (const p of pages) {
  const buf = readFileSync(join(DOCS, p));
  const str = buf.toString('latin1');
  if (str.includes('href="geospy.html"')) { console.log(`  ${p}: already has geospy link, skipped`); continue; }
  let anchor = null;
  for (const c of candidates) {
    const idx = str.indexOf(c);
    if (idx >= 0) { anchor = c; break; }
  }
  if (!anchor) { console.log(`  ${p}: no GPS/About anchor, skipped`); continue; }
  const at2 = str.indexOf(anchor);
  const lineStart = str.lastIndexOf('\n', at2) + 1;
  const indent = str.slice(lineStart, at2);
  const out = Buffer.concat([ buf.subarray(0, lineStart), Buffer.from(indent, 'latin1'), NAV, buf.subarray(lineStart) ]);
  writeFileSync(join(DOCS, p), out);
  console.log(`  ${p}: Geospy nav inserted before ${anchor.slice(0,24)}...`);
}

// gate checks
const html = readFileSync(join(DOCS, 'geospy.html'), 'utf8');
const need = [
  '<link rel="icon"', 'href="favicon.svg"', '<link rel="apple-touch-icon"',
  'id="apiDot"', 'id="egressIpBadge"', 'refreshEgressIp', 'T3MP3ST_API', 'src="embed.js"',
  'id="page-geospy"', 'gsDrop', 'gsMap', 'leaflet', 'gsModelSelect', 'gsSatToggle', 'gsApiKey', 'gs3dToggle',
];
const missing = need.filter(n => !html.includes(n));
if (missing.length) throw new Error('geospy.html missing: ' + missing.join(', '));
if (html.includes('page-about')) throw new Error('page-about remnant');

// inline scripts must parse
const blocks = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m=>m[1]);
let fails=0;
blocks.forEach((b,i)=>{ try{ new vm.Script(b, {filename:`geospy.html#inline-${i}`}); }catch(e){ fails++; console.log(`PARSE FAIL inline #${i}: ${e.message.slice(0,200)}`); }});
console.log(`geospy.html: ${blocks.length} inline scripts, ${fails} parse failures, all ${need.length} gate markers present`);
if(fails) process.exit(1);

// byte preservation: invalid-utf8 count must equal about's for geospy heredoc is utf8-new-file
const fffdAbout = (readFileSync(join(DOCS,'about.html'),'utf8').match(/\uFFFD/g)||[]).length;
const fffdGeospy = (readFileSync(join(DOCS,'geospy.html'),'utf8').match(/\uFFFD/g)||[]).length;
console.log(`invalid-utf8 about/geospy: ${fffdAbout}/${fffdGeospy} (geospy may differ by few due to new utf8 content, but about-derived prefix preserved)`);
