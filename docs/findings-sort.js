/* T3MP3ST War Room — findings table: verified-first, then by severity.
   Rows carry data-verified (1 = tool-backed, 0 = model-asserted) and
   data-severity. Stable sort runs after every render (MutationObserver). */
(function () {
  'use strict';

  var SEV = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

  function sortRows() {
    var body = document.getElementById('findingsBody');
    if (!body) return;
    var rows = Array.prototype.slice.call(body.querySelectorAll('.finding-row'));
    if (rows.length < 2) return;
    var order = rows.map(function (r, i) {
      var v = r.getAttribute('data-verified') === '1' ? 1 : 0;
      var s = SEV[r.getAttribute('data-severity')] ?? 0;
      return { r: r, v: v, s: s, i: i };
    });
    order.sort(function (a, b) {
      if (a.v !== b.v) return b.v - a.v;
      if (a.s !== b.s) return b.s - a.s;
      return a.i - b.i;
    });
    var frag = document.createDocumentFragment();
    order.forEach(function (o) { frag.appendChild(o.r); });
    body.appendChild(frag);
  }

  var timer = null;
  function schedule() {
    if (timer) clearTimeout(timer);
    timer = setTimeout(function () { timer = null; sortRows(); }, 150);
  }

  function boot() {
    var body = document.getElementById('findingsBody');
    if (body) {
      sortRows();
      var mo = new MutationObserver(schedule);
      mo.observe(body, { childList: true, subtree: true });
    }
    // The app re-creates the table body on some renders — re-attach if detached.
    setInterval(function () {
      var b = document.getElementById('findingsBody');
      if (b && b.dataset && b.dataset.sorted !== '1') {
        b.dataset.sorted = '1';
        sortRows();
      }
    }, 4000);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
