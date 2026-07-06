#!/usr/bin/env node
/**
 * Cross-platform entry for `npm run update`.
 * Windows  -> scripts/update.ps1
 * Linux/macOS/WSL -> scripts/update.sh
 */
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { platform } from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const args = process.argv.slice(2);

function commandExists(name) {
  if (platform() === 'win32') {
    const result = spawnSync('where', [name], { shell: true, stdio: 'pipe' });
    return result.status === 0;
  }
  const result = spawnSync('command', ['-v', name], { shell: true, stdio: 'pipe' });
  return result.status === 0;
}

function gitInstallHelp() {
  const os = platform();
  if (os === 'win32') {
    return [
      '[x] Git is required but was not found on PATH.',
      '',
      'Install Git for Windows:',
      '  https://git-scm.com/download/win',
      '',
      'During setup, choose "Git from the command line and also from 3rd-party software".',
      'Then reopen your terminal and run:  npm run update',
    ].join('\n');
  }
  if (os === 'darwin') {
    return [
      '[x] Git is required but was not found on PATH.',
      '',
      'Install options:',
      '  brew install git',
      '  xcode-select --install',
      '',
      'Then run:  npm run update',
    ].join('\n');
  }
  return [
    '[x] Git is required but was not found on PATH.',
    '',
    'Install with your package manager, for example:',
    '  sudo apt install git        # Debian/Ubuntu',
    '  sudo dnf install git        # Fedora',
    '  sudo pacman -S git          # Arch',
    '',
    'More: https://git-scm.com/download/linux',
    '',
    'Then run:  npm run update',
  ].join('\n');
}

function npmInstallHelp() {
  return [
    '[x] npm is required but was not found on PATH.',
    '',
    'Install Node.js (includes npm): https://nodejs.org/',
    'Then run:  npm run update',
  ].join('\n');
}

function mapArgsForPowerShell(argv) {
  return argv.flatMap((arg) => {
    switch (arg) {
      case '--dry-run':
        return ['-DryRun'];
      case '--hard':
        return ['-Hard'];
      case '--force':
        return ['-Force'];
      case '--keep-backup':
        return ['-KeepBackup'];
      default:
        return [arg];
    }
  });
}

if (!existsSync(join(root, 'package.json'))) {
  console.error(`[x] Not a T3MP3ST repo (package.json missing): ${root}`);
  process.exit(1);
}

if (!commandExists('git')) {
  console.error(gitInstallHelp());
  process.exit(1);
}

if (!commandExists('npm')) {
  console.error(npmInstallHelp());
  process.exit(1);
}

const os = platform();
const platformLabel = { win32: 'Windows', darwin: 'macOS', linux: 'Linux' }[os] ?? os;
const scriptName = os === 'win32' ? 'update.ps1' : 'update.sh';
console.log('\x1b[90m-- Launcher ----------------------------------------\x1b[0m');
console.log(`  \x1b[36mPlatform\x1b[0m   ${platformLabel}`);
console.log(`  \x1b[36mDriver\x1b[0m     scripts/${scriptName}`);
console.log(`  \x1b[36mCommand\x1b[0m    npm run update`);
console.log('');

let result;

if (os === 'win32') {
  const ps1 = join(__dirname, 'update.ps1');
  if (!existsSync(ps1)) {
    console.error(`[x] Missing updater script: ${ps1}`);
    process.exit(1);
  }
  result = spawnSync(
    'powershell',
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ps1, ...mapArgsForPowerShell(args)],
    { cwd: root, stdio: 'inherit' },
  );
} else {
  const sh = join(__dirname, 'update.sh');
  if (!existsSync(sh)) {
    console.error(`[x] Missing updater script: ${sh}`);
    process.exit(1);
  }
  result = spawnSync('bash', [sh, ...args], { cwd: root, stdio: 'inherit' });
}

if (result.error) {
  console.error(`[x] Failed to start updater: ${result.error.message}`);
  process.exit(1);
}

process.exit(result.status ?? 1);
