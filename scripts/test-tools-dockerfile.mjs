#!/usr/bin/env node
/**
 * Regression guard for the tools image's non-root runtime contract.
 *
 * Python packages install console scripts in /usr/local/bin (including httpx).
 * Go tools must therefore be built in a staging directory before installation,
 * otherwise `go install` refuses to overwrite the existing Python script.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const dockerfile = fs.readFileSync(path.join(here, '..', 'tools', 'Dockerfile'), 'utf8');
const smokeScript = fs.readFileSync(path.join(here, 'check-tools-image.sh'), 'utf8');

let passed = 0;
let failed = 0;

function check(label, condition) {
  if (condition) {
    passed += 1;
    console.log(`  ok   ${label}`);
  } else {
    failed += 1;
    console.error(`  FAIL ${label}`);
  }
}

check(
  'Go binaries are not built directly into /usr/local/bin',
  !/export\s+GOBIN=\/usr\/local\/bin/.test(dockerfile),
);
check(
  'Go binaries use a staging directory',
  /export\s+GOBIN=\/tmp\/projectdiscovery-bin/.test(dockerfile),
);
check(
  'staged Go binaries are installed into /usr/local/bin',
  /install\s+-m\s+0755\s+"\$GOBIN"\/\*\s+\/usr\/local\/bin\//.test(dockerfile),
);
check(
  'Go staging directory is removed',
  /rm\s+-rf\s+"\$GOBIN"/.test(dockerfile),
);
check(
  'operator user reuses the existing Kali operator group',
  /useradd\s+--gid\s+operator\s+--create-home\s+--shell\s+\/bin\/bash\s+operator/.test(dockerfile),
);
check('image runtime user is operator', /^USER operator$/m.test(dockerfile));
check('image runtime workdir is /work', /^WORKDIR \/work$/m.test(dockerfile));
check(
  'tools smoke avoids a login shell whose logout hook can mask success',
  /docker run .* "\$IMAGE" bash -c '/.test(smokeScript) &&
    !/docker run .* "\$IMAGE" bash -lc '/.test(smokeScript),
);

console.log(`\n${failed === 0 ? 'PASS' : 'FAIL'}: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
