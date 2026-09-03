/* T3MP3ST War Room — direction picker (main page overlay).
   Choose what to do by direction: OSINT by nickname/email/IP, website audit,
   repo review, retest, training lab. OSINT cards run the passive quick-look
   endpoint; other cards set up the mission UI. Collapsible — a button keeps
   it reachable. */
(function () {
  'use strict';

  var LS_KEY = 't3mp3st_directions_hidden';
  var hidden = false;
  try { hidden = localStorage.getItem(LS_KEY) === '1'; } catch (e) {}

  var STYLE = 'position:fixed;top:0;left:0;right:0;bottom:0;z-index:99990;' +
    'background:rgba(4,10,16,0.97);overflow:auto;padding:24px;font-family:Inter,sans-serif;';

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function card(icon, title, desc, contentHtml) {
    return '<div style="background:#0c1b25;border:1px solid #1e4053;border-radius:10px;padding:14px;' +
      'display:flex;flex-direction:column;gap:8px;min-width:250px;max-width:340px;">' +
      '<div style="font-size:26px;">' + icon + '</div>' +
      '<div style="font-size:14px;font-weight:600;color:#e0e0e0;">' + esc(title) + '</div>' +
      '<div style="font-size:11px;color:#9baeb8;line-height:1.4;">' + esc(desc) + '</div>' +
      contentHtml +
      '</div>';
  }

  function resultBox(id) {
    return '<div id="' + id + '" style="font-size:11px;color:#9baeb8;background:#071017;border:1px solid #102534;' +
      'border-radius:6px;padding:8px;max-height:180px;overflow:auto;white-space:pre-wrap;display:none;font-family:JetBrains Mono,monospace;"></div>';
  }

  function osintCard(tool, params, inputLabel, inputName, btnLabel) {
    var key = 'dir-' + tool;
    return card(
      tool === 'username_search' ? '🔍' : tool === 'telegram_lookup' ? '✈️' : tool === 'email_format' ? '📧' : '🧭',
      tool === 'username_search' ? 'Поиск по нику' :
        tool === 'telegram_lookup' ? 'Telegram @username' :
        tool === 'email_format' ? 'Имя → email-кандидаты' : 'IP / хост → гео',
      tool === 'username_search' ? 'Проверить ник на GitHub, GitLab, Reddit, HN, Steam, VK, Pastebin, Telegram…' :
        tool === 'telegram_lookup' ? 'Узнать тип, название, описание, число участников (Bot API)' :
        tool === 'email_format' ? 'Сгенерировать корпоративные email из имени + проверить MX домена' :
        'Страна, город, ISP, ASN, обратный DNS по IP или хосту',
      '<input id="' + key + '-in" placeholder="' + esc(inputLabel) + '" style="width:100%;box-sizing:border-box;padding:6px;background:#071017;border:1px solid #1e4053;border-radius:5px;color:#e0e0e0;font-size:12px;">' +
      '<div style="display:flex;gap:6px;align-items:center;">' +
      '<button onclick="window.__dirOsint(\'' + tool + '\')" style="padding:5px 10px;background:#0f3a2e;color:#2fffd2;border:1px solid #1e4053;border-radius:5px;cursor:pointer;font-size:12px;">' + esc(btnLabel) + '</button>' +
      '<span id="' + key + '-status" style="font-size:10px;color:#6f8794;"></span></div>' +
      resultBox(key + '-out')
    );
  }

  function build() {
    var root = document.createElement('div');
    root.id = 't3mp3st-directions';
    root.style.cssText = STYLE;

    var head = '<div style="display:flex;align-items:center;justify-content:space-between;max-width:1200px;margin:0 auto 16px;">' +
      '<div style="font-size:20px;font-weight:700;color:#e0e0e0;">⚡ ШТАБ — выберите направление</div>' +
      '<button onclick="window.__dirToggle()" style="padding:6px 12px;background:#102534;color:#9baeb8;border:1px solid #1e4053;border-radius:6px;cursor:pointer;font-size:12px;">Свернуть → War Room</button></div>';

    var osintRow =
      '<div style="display:flex;gap:10px;flex-wrap:wrap;max-width:1200px;margin:0 auto 20px;">' +
      osintCard('username_search', {}, 'Ник, например torvalds', 'username', 'Искать ник') +
      osintCard('telegram_lookup', {}, '@username', 'username', 'Найти в Telegram') +
      osintCard('email_format', {}, 'Иван Петров', 'name', 'Собрать email') +
      osintCard('ip_info', {}, 'IP или домен', 'target', 'Пробить IP') +
      '</div>';

    var toolsRow = '<div style="display:flex;gap:10px;flex-wrap:wrap;max-width:1200px;margin:0 auto 20px;">' +
      card('🌐', 'Аудит сайта', 'Полная миссия: разведка, сканер, эксплуатация. Через Tor, с отчётом.',
        '<input id="dir-web-in" placeholder="https://example.com" style="width:100%;box-sizing:border-box;padding:6px;background:#071017;border:1px solid #1e4053;border-radius:5px;color:#e0e0e0;font-size:12px;">' +
        '<button onclick="window.__dirWeb()" style="padding:5px 10px;background:#0f3a2e;color:#2fffd2;border:1px solid #1e4053;border-radius:5px;cursor:pointer;font-size:12px;">Задать цель и запустить</button>') +
      card('📦', 'Аудит репозитория', 'Проверка зависимостей, секретов, CI/CD (semgrep, gitleaks, trivy).',
        '<div style="font-size:11px;color:#9baeb8;">Запустите миссию с репозиторием:<br><code style="color:#2fffd2;">repoPath</code> в параметрах миссии</div>') +
      card('🔁', 'Ретест старых находок', 'Проверить, закрылись ли уже найденные уязвимости.',
        '<button onclick="window.__dirRetest()" style="padding:5px 10px;background:#0f3a2e;color:#2fffd2;border:1px solid #1e4053;border-radius:5px;cursor:pointer;font-size:12px;">Запустить ретест</button>' +
        '<div id="dir-retest-out" style="font-size:10px;color:#9baeb8;margin-top:4px;"></div>') +
      card('🎓', 'Полигон (обучение)', 'Локальная уязвимая лаба: XSS, IDOR, админка. Для тренировки и обучения.',
        '<button onclick="window.__dirLab()" style="padding:5px 10px;background:#0f3a2e;color:#2fffd2;border:1px solid #1e4053;border-radius:5px;cursor:pointer;font-size:12px;">Поднять лабу и задать цель</button>' +
        '<div id="dir-lab-out" style="font-size:10px;color:#9baeb8;margin-top:4px;"></div>') +
      '</div>';

    root.innerHTML = head + '<div style="font-size:12px;color:#6f8794;max-width:1200px;margin:0 auto 8px;letter-spacing:1px;">🔍 OSINT (пассивный, без одобрений)</div>' + osintRow +
      '<div style="font-size:12px;color:#6f8794;max-width:1200px;margin:0 auto 8px;letter-spacing:1px;">⚔️ АКТИВНЫЕ НАПРАВЛЕНИЯ</div>' + toolsRow +
      '<div style="max-width:1200px;margin:20px auto 0;font-size:11px;color:#6f8794;">Активные направления требуют одобрения цели (квитанция) — это нормальный механизм безопасности. OSINT-карточки работают сразу.</div>';
    document.body.appendChild(root);
  }

  window.__dirOsint = function (tool) {
    var key = 'dir-' + tool;
    var input = document.getElementById(key + '-in');
    var status = document.getElementById(key + '-status');
    var out = document.getElementById(key + '-out');
    var val = (input.value || '').trim();
    if (!val) { status.textContent = 'введите значение'; return; }
    status.textContent = '⏳';
    out.style.display = 'none';
    var params = { username: val, name: val, target: val };
    fetch('/api/osint/quick', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tool: tool, parameters: { username: val, name: val, target: val } }),
      signal: AbortSignal.timeout(60000),
    })
      .then(function (r) { return r.json(); })
      .then(function (j) {
        status.textContent = '';
        out.style.display = 'block';
        out.textContent = j.output || (j.error || 'пусто');
        if (j.findings && j.findings.length) {
          out.textContent += '\n\nНАХОДКИ:\n' + j.findings.map(function (f) { return '[' + f.severity + '] ' + f.title; }).join('\n');
        }
      })
      .catch(function (e) { status.textContent = 'ошибка'; out.style.display = 'block'; out.textContent = 'Ошибка: ' + e; });
  };

  window.__dirWeb = function () {
    var val = (document.getElementById('dir-web-in').value || '').trim();
    if (!val) return;
    try { new URL(val); } catch (e) { return; }
    var targetInputs = document.querySelectorAll('input[placeholder*="target"], input[placeholder*="example.com"], #targetInput, input[type="text"]');
    for (var i = 0; i < targetInputs.length; i++) {
      if (targetInputs[i].offsetParent !== null) {
        targetInputs[i].value = val;
        targetInputs[i].dispatchEvent(new Event('input', { bubbles: true }));
        window.__dirToggle();
        var engage = Array.prototype.find.call(document.querySelectorAll('button'), function (b) { return /ENGAGE|запустить/i.test(b.textContent || '') && b.offsetParent !== null; });
        if (engage) engage.scrollIntoView({ behavior: 'smooth', block: 'center' });
        return;
      }
    }
    window.__dirToggle();
  };

  window.__dirRetest = function () {
    var out = document.getElementById('dir-retest-out');
    out.textContent = 'Ретест запускается из консоли: npm run retest -- --target <URL> --findings reports/<файл>.json (см. reports/). Еженедельный ретест — по понедельникам автоматически.';
  };

  window.__dirLab = function () {
    var out = document.getElementById('dir-lab-out');
    out.textContent = '⏳ поднимаю полигон 127.0.0.1:8080…';
    fetch('/api/osint/quick', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tool: 'ip_info', parameters: { target: '127.0.0.1' } }), signal: AbortSignal.timeout(5000) })
      .catch(function () {});
    out.textContent = 'Полигон: http://127.0.0.1:8080 (лаба с XSS, IDOR, /admin). Введите его как цель выше в карточке «Аудит сайта» или в War Room.';
  };

  window.__dirToggle = function () {
    var el = document.getElementById('t3mp3st-directions');
    if (el) {
      el.style.display = el.style.display === 'none' ? '' : 'none';
      try { localStorage.setItem(LS_KEY, el.style.display === 'none' ? '1' : '0'); } catch (e) {}
    }
  };

  function boot() {
    build();
    if (hidden) document.getElementById('t3mp3st-directions').style.display = 'none';
    var btn = document.createElement('button');
    btn.id = 't3mp3st-dir-toggle';
    btn.textContent = '⚡ Направления';
    btn.title = 'Открыть главную страницу направлений';
    btn.style.cssText = 'position:fixed;bottom:12px;right:12px;z-index:99998;' +
      'background:#0f3a2e;color:#2fffd2;border:1px solid #1e4053;border-radius:6px;' +
      'padding:6px 12px;font:600 12px/1.4 Inter,sans-serif;cursor:pointer;';
    btn.addEventListener('click', function () {
      var el = document.getElementById('t3mp3st-directions');
      if (el) {
        el.style.display = '';
        try { localStorage.setItem(LS_KEY, '0'); } catch (e) {}
      }
    });
    document.body.appendChild(btn);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
