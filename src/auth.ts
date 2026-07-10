import { createHash, randomBytes, timingSafeEqual } from 'crypto';
import express from 'express';
import type { Express, Request, Response } from 'express';

// In-memory session store — cleared on restart (forces re-login after container restart)
const sessions = new Set<string>();

const USERNAME = 'admin';
let _password = '';

function parseCookies(header: string | undefined): Record<string, string> {
    if (!header) return {};
    const out: Record<string, string> = {};
    for (const part of header.split(';')) {
        const idx = part.indexOf('=');
        if (idx === -1) continue;
        out[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
    }
    return out;
}

function loginPage(error?: string): string {
    const errHtml = error
        ? `<div class="error">⚠ ${error}</div>`
        : '';
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>T3MP3ST — Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#080810;color:#ccd;font-family:'JetBrains Mono','Cascadia Code','Fira Code',monospace;min-height:100vh;display:flex;align-items:center;justify-content:center}
.box{width:100%;max-width:400px;padding:36px 32px;background:#0d0d1a;border:1px solid rgba(204,68,68,.3);border-radius:8px;box-shadow:0 0 48px rgba(204,68,68,.07)}
.logo{text-align:center;margin-bottom:28px}
.logo pre{font-size:8.5px;line-height:1.2;color:#cc4444;text-shadow:0 0 14px rgba(204,68,68,.5);display:inline-block;letter-spacing:.04em}
.sub{font-size:10px;color:#334;letter-spacing:.14em;text-transform:uppercase;margin-top:8px}
label{display:block;font-size:10px;color:#445;text-transform:uppercase;letter-spacing:.1em;margin-bottom:5px}
input{width:100%;padding:9px 12px;background:#0a0a16;border:1px solid #1a1a2a;border-radius:4px;color:#ccd;font-family:inherit;font-size:13px;margin-bottom:18px;outline:none;transition:border-color .15s}
input:focus{border-color:rgba(204,68,68,.5)}
button{width:100%;padding:11px;background:linear-gradient(135deg,#cc2222,#aa1111);border:none;border-radius:4px;color:#fff;font-family:inherit;font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;cursor:pointer;transition:opacity .15s}
button:hover{opacity:.85}
.error{margin-bottom:18px;padding:9px 12px;background:rgba(204,68,68,.1);border:1px solid rgba(204,68,68,.3);border-radius:4px;font-size:11px;color:#cc6666}
.hint{margin-top:18px;font-size:10px;color:#223;text-align:center;line-height:1.6}
</style>
</head>
<body>
<div class="box">
  <div class="logo">
    <pre>████████╗██████╗ ███╗   ███╗██████╗ ██████╗ ███████╗████████╗
╚══██╔══╝╚════██╗████╗ ████║██╔══██╗╚════██╗██╔════╝╚══██╔══╝
   ██║    █████╔╝██╔████╔██║██████╔╝ █████╔╝███████╗   ██║
   ██║    ╚═══██╗██║╚██╔╝██║██╔═══╝  ╚═══██╗╚════██║   ██║
   ██║   ██████╔╝██║ ╚═╝ ██║██║     ██████╔╝███████║   ██║
   ╚═╝   ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚═════╝ ╚══════╝   ╚═╝</pre>
    <div class="sub">Tactical Execution Multi-agent Platform</div>
  </div>
  ${errHtml}
  <form method="POST" action="/auth/login">
    <label for="u">Username</label>
    <input id="u" name="username" type="text" value="admin" autocomplete="username" spellcheck="false">
    <label for="p">Password</label>
    <input id="p" name="password" type="password" autocomplete="current-password">
    <button type="submit">⚡ Authenticate</button>
  </form>
  <div class="hint">password is printed in container logs on startup<br>run <code>make logs</code> or <code>docker compose logs</code></div>
</div>
</body>
</html>`;
}

export function initAuth(app: Express): void {
    _password = process.env.TEMPEST_PASSWORD?.trim() ||
        randomBytes(16).toString('hex'); // 32 hex chars

    const httpsPort = process.env.TEMPEST_HTTPS_PORT || '8443';
    const bar = '═'.repeat(54);

    console.log('');
    console.log(bar);
    console.log('  T3MP3ST — WEB ACCESS');
    console.log(`  URL:      https://localhost:${httpsPort}`);
    console.log('  Username: admin');
    console.log(`  Password: ${_password}`);
    console.log(bar);
    console.log('');

    // ── Login page ──────────────────────────────────────────────────────────
    app.get('/auth/login', (_req: Request, res: Response) => {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(loginPage());
    });

    // ── Login form submission ───────────────────────────────────────────────
    app.post(
        '/auth/login',
        express.urlencoded({ extended: false }),
        (req: Request, res: Response) => {
            const body = req.body as { username?: string; password?: string };
            const sha256 = (s: string): Buffer => createHash('sha256').update(s).digest();
            const pwdMatch = typeof body.password === 'string' &&
              timingSafeEqual(sha256(body.password), sha256(_password));
            if (body.username === USERNAME && pwdMatch) {
                const token = randomBytes(32).toString('hex');
                sessions.add(token);
                // Secure flag works through nginx HTTPS termination
                res.setHeader(
                    'Set-Cookie',
                    `t3mp3st_session=${token}; Path=/; HttpOnly; SameSite=Strict; Secure`
                );
                res.redirect(302, '/');
            } else {
                res.setHeader('Content-Type', 'text/html; charset=utf-8');
                res.status(401).send(loginPage('Invalid credentials — check container logs for the password.'));
            }
        }
    );

    // ── Session validation (internal Nginx auth_request sub-request) ────────
    app.get('/auth/validate', (req: Request, res: Response) => {
        const cookies = parseCookies(req.headers.cookie);
        if (cookies.t3mp3st_session && sessions.has(cookies.t3mp3st_session)) {
            res.sendStatus(200);
        } else {
            res.sendStatus(401);
        }
    });

    // ── Logout ──────────────────────────────────────────────────────────────
    app.post('/auth/logout', (req: Request, res: Response) => {
        const cookies = parseCookies(req.headers.cookie);
        if (cookies.t3mp3st_session) sessions.delete(cookies.t3mp3st_session);
        res.setHeader('Set-Cookie', 't3mp3st_session=; Path=/; HttpOnly; Max-Age=0');
        res.redirect(302, '/auth/login');
    });

    // GET logout — redirect to logout form/page (supports browser link clicks)
    app.get('/auth/logout', (_req: Request, res: Response) => {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(`<!DOCTYPE html><html><body style="background:#080810;color:#ccd;font-family:monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
<form method="POST" action="/auth/logout">
  <button type="submit" style="padding:10px 24px;background:#cc2222;border:none;border-radius:4px;color:#fff;font-family:monospace;font-size:13px;cursor:pointer">Log out</button>
</form></body></html>`);
    });
}
