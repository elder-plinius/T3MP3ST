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
});
