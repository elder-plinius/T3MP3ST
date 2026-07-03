# T3MP3ST × OBSIDIVM — Learned Tactics (curated by ablation)

These tactics survived ablation pruning. Sorted by lifetime lift contribution.
Total alive: 4.  Last rebuild: 2026-05-27T10:38:19.797Z.

### dvwa/DVWA-012 — Brute Force (No Lockout)  [lift +0, conf 0.87, gen 001]

When testing DVWA on port 4280, immediately probe /login.php or /vulnerabilities/brute/ with 15+ rapid POST attempts using varying credentials (admin/pass1, admin/pass2, etc.). Confirm brute force viability by observing that no account lockout, CAPTCHA, or rate-limiting occurs after 10+ failed attempts. Evidence: HTTP 200 responses continue without delay/block, or success message appears on valid credential without prior lockout.

### juice/JUICE-012 — Robots.txt Disclosure  [lift +0, conf 0.92, gen 001]

For Juice Shop on port 4300: Always probe /robots.txt as first recon step in disclosure category. Parse for Disallow entries revealing hidden paths like /ftp, /support, /promotions. Confirm by requesting one revealed path—200/403 response proves disclosure. Log as 'Robots.txt Disclosure' with severity info. This is standard recon, not an attack vector.

### webgoat/GOAT-006 — Insecure Deserialization  [lift +0, conf 0.82, gen 001]

When testing WebGoat on port 4380, actively probe all endpoints accepting serialized objects (Java, XML, JSON with type hints) by injecting malicious payloads like ysoserial URLDNS gadgets or polymorphic type confusion attacks. Look for stack traces mentioning ObjectInputStream, readObject(), or deserialization libraries. Confirm with out-of-band DNS callbacks or time-based delays indicating code execution during object reconstruction.

### wordpress/WP-009 — Security Headers Missing  [lift +0, conf 0.92, gen 001]

For WordPress on port 4500: After banner/service confirmation, issue HEAD request to / and parse response headers. Flag WP-009 (Security Headers Missing) if ANY of X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, or Content-Security-Policy headers are absent. Log header inventory in evidence field. This is INFO severity, not exploitable, but documents hardening gaps.
