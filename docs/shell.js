/* T3MP3ST app shell — one persistent sidebar + a framed content area.
 *
 * Pages load inside #pageFrame; navigation swaps the frame source instead of
 * reloading a full page, so the menu never re-renders and state like the API
 * dot / badges survives across pages. docs/embed.js (loaded by every page)
 * routes nav clicks here and mirrors live sidebar state back.
 */
(function () {
    'use strict';
    var THEME_KEY = 't3mp3st_theme';
    var PAGES = ['index.html', 'live-scan.html', 'receipts.html', 'operators.html', 'evidence.html',
        'obsidivm.html', 'ctf.html', 'arsenal.html', 'cves.html', 'dfir.html', 'terminal.html', 'configs.html',
        'general.html', 'self-improve.html', 'settings.html', 'about.html'];
    var TITLES = {
        'index.html': 'War Room', 'live-scan.html': 'Live Scan', 'receipts.html': 'Scope Receipts',
        'operators.html': 'Operatives', 'evidence.html': 'Evidence Vault', 'obsidivm.html': 'OBSIDIVM',
        'ctf.html': 'CTF Range', 'arsenal.html': 'Arsenal', 'cves.html': 'CVE Vault', 'dfir.html': 'DFIR Response',
        'terminal.html': 'Terminal', 'configs.html': 'Config Library', 'general.html': 'Op Admiral',
        'self-improve.html': 'Self-Improvement', 'settings.html': 'Settings', 'about.html': 'About'
    };

    var frame = document.getElementById('pageFrame');
    if (!frame) return;
    var sidebar = document.getElementById('sidebar');

    function currentPage() {
        var h = (location.hash || '').replace(/^#\/?/, '');
        try { h = decodeURIComponent(h); } catch (e) { /* keep raw */ }
        return PAGES.indexOf(h) > -1 ? h : PAGES[0];
    }

    function setActive(page) {
        var items = document.querySelectorAll('.nav-item[data-href]');
        for (var i = 0; i < items.length; i++) {
            items[i].classList.toggle('active', items[i].getAttribute('data-href') === page);
        }
    }

    function goTo(page) {
        if (location.hash === '#' + page) route();
        else location.hash = '#' + page;
    }

    function route() {
        var page = currentPage();
        setActive(page);
        document.title = 'T3MP3ST — ' + (TITLES[page] || page);
        if (frame.getAttribute('data-src') !== page) {
            frame.setAttribute('data-src', page);
            var bar = document.getElementById('shellLoading');
            if (bar) bar.classList.add('on');
            frame.src = page;
        }
    }
    window.addEventListener('hashchange', route);

    // Sidebar nav (the shell's own menu).
    if (sidebar) {
        sidebar.addEventListener('click', function (ev) {
            var a = ev.target && ev.target.closest ? ev.target.closest('a.nav-item[data-href]') : null;
            if (!a) return;
            ev.preventDefault();
            goTo(a.getAttribute('data-href'));
        });
    }

    /* ----- messages from the framed page ----- */
    function frameIsSameOrigin() {
        try { return !!(frame.contentDocument && frame.contentDocument.defaultView); }
        catch (e) { return false; }
    }
    window.addEventListener('message', function (ev) {
        if (ev.source !== frame.contentWindow || !frameIsSameOrigin()) return;
        var m = ev.data || {};
        if (m.type === 't3mp3st:nav' && typeof m.href === 'string') {
            var raw = m.href.split('/').pop();
            var parts = raw.split('#');
            var p = parts[0].split('?')[0];
            var hash = parts[1] || '';
            if (PAGES.indexOf(p) > -1) {
                goTo(p);
                var forwardMsg = function() {
                    try {
                        if (frame && frame.contentWindow) {
                            frame.contentWindow.postMessage({
                                type: 't3mp3st:focus_finding',
                                targetFinding: m.targetFinding,
                                hash: hash
                            }, '*');
                        }
                    } catch (e) {}
                };
                setTimeout(forwardMsg, 150);
                setTimeout(forwardMsg, 450);
            }
        } else if (m.type === 't3mp3st:state') {
            applyState(m);
        }
    });

    // Replay the framed page's sidebar changes onto the shell's visible copy.
    function applyState(m) {
        // Drop snapshots from a page that is being swapped out — its debounced
        // teardown mutations would otherwise clobber the new page's state/title.
        if (m.page && m.page !== currentPage()) return;
        var els = m.els || [];
        for (var i = 0; i < els.length; i++) {
            var e = els[i];
            var el = document.getElementById(e.id);
            if (!el) continue;
            // Prevent uninitialized "Checking..." from briefly downgrading verified "API + LLM Ready" during iframe load
            if (e.id === 'apiText' && e.text === 'Checking...' && el.classList.contains('llm-ready')) {
                continue;
            }
            if (e.id === 'apiDot' && e.cls === 'api-dot' && el.classList.contains('llm-ready')) {
                continue;
            }
            if (el.textContent !== e.text) el.textContent = e.text;
            if (el.className !== e.cls) el.className = e.cls;
            var st = e.style || '';
            if (el.getAttribute('style') !== st) {
                if (st) el.setAttribute('style', st);
                else el.removeAttribute('style');
            }
        }
        if (m.title) document.title = m.title.indexOf('T3MP3ST') === 0 ? m.title : 'T3MP3ST — ' + m.title;
        var t = (m.theme === undefined) ? null : (m.theme || 'storm');
        if (t !== null) {
            var cur = document.documentElement.getAttribute('data-theme') || 'storm';
            if (cur !== t) setTheme(t, { push: false });
        }
    }

    /* ----- theme switcher (same swatches the per-page sidebars had) ----- */
    var THEMES = [
        { id: 'storm', label: 'Storm', accent: '#2fffd2' },
        { id: 'ember', label: 'Ember', accent: '#ffab40' },
        { id: 'crimson', label: 'Crimson', accent: '#ff5470' },
        { id: 'void', label: 'Void', accent: '#b57bff' }
    ];
    function markSwatches(id) {
        var sw = document.querySelectorAll('.theme-swatch');
        for (var i = 0; i < sw.length; i++) sw[i].classList.toggle('active', sw[i].dataset.theme === id);
    }
    function setTheme(id, opts) {
        var t = THEMES.filter(function (x) { return x.id === id; })[0] || THEMES[0];
        if (t.id === 'storm') document.documentElement.removeAttribute('data-theme');
        else document.documentElement.setAttribute('data-theme', t.id);
        try { localStorage.setItem(THEME_KEY, t.id); } catch (e) { /* private mode */ }
        markSwatches(t.id);
        if (opts && opts.push) {
            try {
                if (frame.contentWindow) frame.contentWindow.postMessage({ type: 't3mp3st:theme', id: t.id }, '*');
            } catch (e) { /* frame not ready */ }
        }
    }
    function initTheme() {
        var host = document.getElementById('themeSwitcher');
        if (host && !host.dataset.built) {
            host.dataset.built = '1';
            THEMES.forEach(function (t) {
                var b = document.createElement('button');
                b.type = 'button';
                b.className = 'theme-swatch';
                b.dataset.theme = t.id;
                b.title = t.label + ' theme';
                b.setAttribute('aria-label', t.label + ' theme');
                b.style.background = t.accent;
                b.style.color = t.accent;
                b.addEventListener('click', function () { setTheme(t.id, { push: true }); });
                host.appendChild(b);
            });
        }
        var saved = 'storm';
        try { saved = localStorage.getItem(THEME_KEY) || 'storm'; } catch (e) { /* private mode */ }
        setTheme(saved, { push: false });
    }

    /* ----- shell sidebar controls backed by the framed page ----- */
    var btn = document.getElementById('apiReconnectBtn');
    if (btn) btn.addEventListener('click', function () {
        try {
            var w = frame.contentWindow;
            if (w && w.T3MP3ST_API && w.T3MP3ST_API.checkHealth) w.T3MP3ST_API.checkHealth();
        } catch (e) { /* frame not ready */ }
    });

    // Mobile: the shell sidebar slides off-canvas below 768px; a floating
    // toggle opens it (the pages' own toggles stay hidden while embedded).
    var mt = document.getElementById('shellMobileToggle');
    if (mt) mt.addEventListener('click', function () {
        if (sidebar) sidebar.classList.toggle('open');
    });
    document.addEventListener('click', function (ev) {
        if (!sidebar || !sidebar.classList.contains('open')) return;
        if (sidebar.contains(ev.target)) return;
        if (mt && (ev.target === mt || mt.contains(ev.target))) return;
        sidebar.classList.remove('open');
    });

    // Frame lifecycle: hide the loading bar, push the saved theme in (pages
    // apply it at their own init, this catches a theme changed mid-session).
    frame.addEventListener('load', function () {
        var bar = document.getElementById('shellLoading');
        if (bar) bar.classList.remove('on');
        try {
            var saved = 'storm';
            try { saved = localStorage.getItem(THEME_KEY) || 'storm'; } catch (e) { /* private mode */ }
            var w = frame.contentWindow;
            if (w && w.t3mpTheme) w.t3mpTheme.apply(saved);
        } catch (e) { /* frame not same-origin yet */ }
    });

    initTheme();
    route();
})();
