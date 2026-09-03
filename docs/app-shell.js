(function () {
  'use strict';

  var titles = {
    warroom: 'War Room', 'live-scan': 'Live Scan', receipts: 'Scope Receipts',
    operators: 'Operatives', evidence: 'Evidence Vault', 'cve-vault': 'CVE Vault',
    arsenal: 'Arsenal', terminal: 'Terminal', benchmarks: 'Benchmarks',
    configs: 'Config Library', 'ctf-range': 'CTF Range', general: 'Op Admiral',
    selfimprove: 'Self-Improvement', settings: 'Settings', about: 'About'
  };
  var initialized = false;

  function routeFromHash() {
    var match = /^#\/?([a-z0-9-]+)$/.exec(window.location.hash || '');
    return match && titles[match[1]] ? match[1] : null;
  }

  function writeHash(page, mode) {
    if (mode === 'none' || !window.history) return;
    var hash = '#/' + page;
    if (window.location.hash === hash) return;
    var method = mode === 'push' ? 'pushState' : 'replaceState';
    window.history[method](null, '', hash);
  }

  function runLifecycle(page) {
    var callbacks = {
      'live-scan': ['refreshLiveScanPage', 50], receipts: ['refreshReceiptsPage', 50],
      operators: ['loadOperativesRoster', 80], evidence: ['hydrateFindings', 60],
      selfimprove: ['renderSelfImprove', 60], settings: ['uacInit', 40],
      'ctf-range': ['initCtfRange', 0]
    };
    var callback = callbacks[page];
    if (callback && typeof window[callback[0]] === 'function') {
      window.setTimeout(window[callback[0]], callback[1]);
    }
  }

  function navigate(page, options) {
    if (!titles[page] || !document.getElementById('page-' + page)) return false;
    document.querySelectorAll('.nav-item').forEach(function (item) {
      item.classList.toggle('active', item.dataset.page === page);
      if (item.dataset.page === page) item.setAttribute('aria-current', 'page');
      else item.removeAttribute('aria-current');
    });
    document.querySelectorAll('.page').forEach(function (panel) {
      var active = panel.id === 'page-' + page;
      panel.classList.toggle('active', active);
      panel.hidden = !active;
    });
    var title = document.getElementById('pageTitle');
    var sidebar = document.getElementById('sidebar');
    if (title) title.textContent = titles[page];
    if (sidebar) sidebar.classList.remove('open');
    writeHash(page, options && options.history ? options.history : 'replace');
    runLifecycle(page);
    document.dispatchEvent(new CustomEvent('t3mp:navigate', { detail: { page: page } }));
    return true;
  }

  function readinessText(payload) {
    if (payload && payload.status === 'operational') {
      if (payload.llm && payload.llm.connected) return { state: 'ready', text: 'API and LLM ready (server verified)' };
      return { state: 'limited', text: 'API ready; LLM unavailable (server verified)' };
    }
    if (payload && payload.status === 'standalone') return { state: 'limited', text: 'Standalone mode; server readiness unavailable' };
    return { state: 'offline', text: 'API offline; LLM readiness unavailable' };
  }

  function updateReadiness(payload) {
    var status = readinessText(payload);
    document.querySelectorAll('[data-shell-readiness]').forEach(function (node) {
      node.textContent = status.text;
      node.dataset.state = status.state;
    });
    return status;
  }

  async function refreshReadiness() {
    var controller = new AbortController();
    var timeout = window.setTimeout(function () { controller.abort(); }, 5000);
    try {
      var response = await fetch('/api/health', { headers: { accept: 'application/json' }, signal: controller.signal });
      if (!response.ok) throw new Error('health request failed');
      return updateReadiness(await response.json());
    } catch (_) {
      return updateReadiness({ status: 'offline' });
    } finally {
      window.clearTimeout(timeout);
    }
  }

  function init() {
    if (initialized) return;
    initialized = true;
    document.querySelectorAll('.nav-item[data-page]').forEach(function (item) {
      item.setAttribute('role', 'link');
      item.tabIndex = 0;
      item.addEventListener('click', function () { navigate(item.dataset.page, { history: 'push' }); });
      item.addEventListener('keydown', function (event) {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        navigate(item.dataset.page, { history: 'push' });
      });
    });
    var active = document.querySelector('.nav-item.active[data-page]');
    var initial = routeFromHash() || (active && active.dataset.page) || 'warroom';
    navigate(initial, { history: 'none' });
    refreshReadiness();
    window.addEventListener('hashchange', function () {
      var page = routeFromHash();
      if (page) navigate(page, { history: 'none' });
    });
  }

  window.T3MP3STShell = { init: init, navigate: navigate, updateReadiness: updateReadiness, refreshReadiness: refreshReadiness, readinessText: readinessText, routeFromHash: routeFromHash };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
