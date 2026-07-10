import { describe, it, expect } from 'vitest';
import { DANGEROUS_SINK_RE, OUTBOUND_REQUEST_RE } from '../recon/code-ingest.js';

describe('cross-language sinks', () => {
  it('matches new cross-language sinks', () => {
    for (const s of [
      'Runtime.getRuntime().exec(cmd)',
      'exec.Command("sh")',
      'child_process.exec(x)',
      'system(buf)',
      'popen(cmd)',
      'new ProcessBuilder(cmd)',
    ]) {
      expect(DANGEROUS_SINK_RE.test(s), s).toBe(true);
    }
  });

  it('regression: existing python sinks still match', () => {
    for (const s of ['os.system(x)', 'eval(y)', 'subprocess.run(z)', 'yaml.load(f)']) {
      expect(DANGEROUS_SINK_RE.test(s), s).toBe(true);
    }
  });

  it('no false positive on benign / System.out / filesystem identifiers', () => {
    for (const s of ['const total = sum(a, b)', 'System.out.println("debug")', 'fileSystem.readFile(x)']) {
      expect(DANGEROUS_SINK_RE.test(s), s).toBe(false);
    }
  });

  it('outbound covers go net/http and js fetch/axios', () => {
    for (const s of ['http.Get(u)', 'http.Post(u, b)', 'fetch(u)', 'axios.get(u)']) {
      expect(OUTBOUND_REQUEST_RE.test(s), s).toBe(true);
    }
  });

  it('recall: idiomatic outbound/exec forms missed by the first-pass patterns', () => {
    // Go http.NewRequest+client.Do, Go client.Get, Node http(s).request, axios(config),
    // C exec-family, and receiver-qualified fetch — all real attack-surface idioms.
    for (const s of [
      'req, _ := http.NewRequest("GET", u, nil)',
      'resp, _ := client.Do(req)',
      'exec.CommandContext(ctx, cmd)',
      'execve(path, argv, envp)',
      'execvp(cmd, args)',
      'https.request(options, cb)',
      'axios({ url: u })',
      'return window.fetch(url)', // qualified fetch must still match (JS SSRF idiom)
      'this.fetch(userUrl)',
    ]) {
      expect(DANGEROUS_SINK_RE.test(s), s).toBe(true);
    }
    for (const s of ['client.Get(u)', 'client.Do(req)', 'http.request(u, cb)', 'axios({url:u})', 'window.fetch(u)']) {
      expect(OUTBOUND_REQUEST_RE.test(s), s).toBe(true);
    }
  });

  it('precision: bare-call sinks and generic .Get/.Do methods on unrelated receivers are not flagged', () => {
    // `.system(`/`.popen(` on an unrelated object must not be flagged as the
    // C/OS bare call. (os.system / os.popen keep matching via their own patterns.)
    expect(DANGEROUS_SINK_RE.test('solarSystem.system(planets)'), 'receiver .system(').toBe(false);
    expect(DANGEROUS_SINK_RE.test('os.system(cmd)'), 'os.system still').toBe(true);
    // Generic keyed-store methods must NOT be mistaken for outbound HTTP — the
    // .Get/.Post/.Do alternatives are receiver-qualified to `client`.
    for (const s of ['return db.Get(id)', 'cache.Get(userID)', 'queue.Do(task)', 'session.Post(data)', 'config.get(key)']) {
      expect(OUTBOUND_REQUEST_RE.test(s), s).toBe(false);
      expect(DANGEROUS_SINK_RE.test(s), s).toBe(false);
    }
  });
});
