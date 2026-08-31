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
