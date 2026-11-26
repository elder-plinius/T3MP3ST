/* T3MP3ST shell bridge — loaded by every docs/*.html page.
 *
 * Standalone (page opened directly): sidebar nav clicks are routed into the
 * app shell (shell.html#page.html) so the persistent menu takes over.
 *
 * Embedded (page running inside shell.html's iframe): the page's own sidebar
 * is hidden — the shell owns the menu — and this bridge mirrors live sidebar
 * state (API dot, badges, connection status) plus the theme back to the shell
 * so the shell menu behaves exactly like the old per-page one.
 */
(function () {
    'use strict';
    if (/[?&]standalone\b/.test(location.search)) return;

    var embedded = false;
    try { embedded = window.self !== window.top; } catch (e) { embedded = true; }
    window.__t3mpEmbedded = embedded;

    /* ---------- operator settings → server settings DB ---------- */
    // Settings used to live ONLY in each browser's localStorage — a restart, a second
    // browser, or a cleared cache lost them. saveState() on every page now also pushes
    // the settings blob to the server's settings DB (debounced), and on boot this bridge
    // merges server-saved settings back into any browser that is missing them.
    var _settingsSyncTimer = null;
    function queueSettingsSync(settings) {
        if (!settings || typeof settings !== 'object') return;
        if (_settingsSyncTimer) clearTimeout(_settingsSyncTimer);
        _settingsSyncTimer = setTimeout(function () {
            try {
                fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ settings: settings, reason: 'ui.save' })
                }).catch(function () { /* server down — local storage still holds them */ });
            } catch (e) { /* noop */ }
        }, 600);
    }
    window.queueSettingsSync = queueSettingsSync;

    function restoreServerSettings() {
        try {
            fetch('/api/settings').then(function (r) { return r.ok ? r.json() : null; }).then(function (d) {
                var srv = d && d.settings;
                if (!srv) return;
                var blob = {};
                try { blob = JSON.parse(localStorage.getItem('t3mp3st') || '{}') || {}; } catch (e) { blob = {}; }
                blob.settings = blob.settings || {};
                var changed = 0;
                Object.keys(srv).forEach(function (k) {
                    var cur = blob.settings[k];
                    var v = srv[k];
                    if ((cur === undefined || cur === null || cur === '') && v !== undefined && v !== null && v !== '') {
                        blob.settings[k] = v;
                        changed++;
                    }
                });
                if (srv.proxyUrl && !localStorage.getItem('t3mp3st_proxy_url')) {
                    localStorage.setItem('t3mp3st_proxy_url', String(srv.proxyUrl));
                    changed++;
                }
                if (changed > 0) {
                    localStorage.setItem('t3mp3st', JSON.stringify(blob));
                    // The page's own pollers call saveState() and would write the PRE-merge
                    // in-memory state back over the restored blob. A single reload boots the
                    // page with the restored settings; the next pass finds nothing missing
                    // (changed=0) so this is self-terminating, never a loop.
                    setTimeout(function () { location.reload(); }, 50);
                    return;
                }
            }).catch(function () { /* server down */ });
        } catch (e) { /* noop */ }
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { setTimeout(restoreServerSettings, 1500); });
    else setTimeout(restoreServerSettings, 1500);


    /* ---------- nav routing (both modes) ---------- */
    document.addEventListener('click', function (ev) {
        if (ev.defaultPrevented || ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return;
        var t = ev.target;
        var a = t && t.closest ? t.closest('a[href$=".html"]') : null;
        if (!a || a.target || a.hasAttribute('download')) return;
        var href = a.getAttribute('href') || '';
        if (!/^[a-z-]+\.html$/i.test(href)) return;
        // The shell owns cross-page navigation now; keep the page's own
        // nav handlers from firing behind us (they toggle in-page sections).
        ev.preventDefault();
        ev.stopPropagation();
        if (embedded) parent.postMessage({ type: 't3mp3st:nav', href: href }, '*');
        else location.href = 'shell.html#' + href;
    }, true);

    if (!embedded) return; // everything below is embed-only

    /* ---------- embedded: hide this page's own chrome ---------- */
    document.documentElement.classList.add('t3mp-embedded');
    var css = document.createElement('style');
    css.id = 't3mpEmbedCss';
    css.textContent =
        '.t3mp-embedded .sidebar{display:none!important}' +
        '.t3mp-embedded .main-content{margin-left:0!important;width:100%!important}' +
        '.t3mp-embedded .mobile-toggle{display:none!important}';
    document.head.appendChild(css);

    /* ---------- embedded: mirror sidebar state + theme to the shell ---------- */
    // Leaf elements only — mirroring a container would wipe its children.
    var MIRROR_IDS = ['apiDot', 'apiText', 'pendingReceiptCount', 'activeOperatorCount',
        'ctfActiveCount', 'generalStatusBadge', 'connectionStatus', 'connectionText'];
    var queued = false;
    function postSnapshot() {
        queued = false;
        var els = [];
        for (var i = 0; i < MIRROR_IDS.length; i++) {
            var el = document.getElementById(MIRROR_IDS[i]);
            if (el) els.push({ id: MIRROR_IDS[i], cls: el.className, text: el.textContent, style: el.getAttribute('style') || '' });
        }
        try {
            parent.postMessage({
                type: 't3mp3st:state',
                page: location.pathname.split('/').pop(),
                theme: document.documentElement.getAttribute('data-theme') || '',
                title: document.title,
                els: els
            }, '*');
        } catch (e) { /* parent gone */ }
    }
    function queueSnapshot() {
        if (queued) return;
        queued = true;
        setTimeout(postSnapshot, 120);
    }
    function startMirror() {
        var sb = document.getElementById('sidebar');
        if (sb) {
            // The page scripts keep updating their (hidden) sidebar; the shell
            // replays every change onto its own visible copy by element id.
            new MutationObserver(queueSnapshot).observe(sb, { subtree: true, childList: true, attributes: true, characterData: true });
        }
        new MutationObserver(queueSnapshot).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
        queueSnapshot();
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', startMirror);
    else startMirror();

    /* ---------- shell → page commands ---------- */
    window.addEventListener('message', function (ev) {
        if (ev.source !== parent) return;
        var m = ev.data || {};
        if (m.type === 't3mp3st:theme' && window.t3mpTheme) {
            try { window.t3mpTheme.apply(m.id); } catch (e) { /* noop */ }
        }
    });
})();
