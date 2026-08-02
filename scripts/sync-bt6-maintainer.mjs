#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { basename, dirname, join, relative, resolve } from 'node:path';

const projectRoot = resolve(import.meta.dirname, '..');
const lockPath = join(projectRoot, '.aiwg', 'bt6-maintainer.lock.json');
const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
const checkOnly = process.argv.includes('--check');

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    cwd: projectRoot,
    encoding: 'utf8',
    stdio: options.capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
  });
}

function capture(command, args) {
  return run(command, args, { capture: true });
}

function filesUnder(root, current = root) {
  const files = [];
  for (const entry of readdirSync(current, { withFileTypes: true })) {
    const path = join(current, entry.name);
    if (entry.isDirectory()) files.push(...filesUnder(root, path));
    if (entry.isFile()) files.push(relative(root, path));
  }
  return files.sort();
}

function digest(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function compareTrees(expectedRoot, actualRoot) {
  const expectedFiles = filesUnder(expectedRoot);
  const actualFiles = existsSync(actualRoot) ? filesUnder(actualRoot) : [];
  const missing = expectedFiles.filter((path) => !actualFiles.includes(path));
  const extra = actualFiles.filter((path) => !expectedFiles.includes(path));
  const changed = expectedFiles.filter(
    (path) => actualFiles.includes(path) && digest(join(expectedRoot, path)) !== digest(join(actualRoot, path)),
  );
  return { equal: missing.length === 0 && extra.length === 0 && changed.length === 0, missing, extra, changed };
}

function assertContained(parent, child, label) {
  const parentPath = resolve(parent);
  const childPath = resolve(child);
  if (childPath !== parentPath && !childPath.startsWith(`${parentPath}/`)) {
    throw new Error(`${label} escapes ${parentPath}: ${childPath}`);
  }
}

const installRef = `${lock.source}@${lock.ref}`;
run('aiwg', ['install', installRef, '--refresh']);

const info = capture('aiwg', ['packages', 'info', lock.registryKey]);
const plainInfo = info.replace(/\x1b\[[0-9;]*m/g, '');
const cacheMatch = plainInfo.match(/^\s*Cache:\s*(.+)$/m);
if (!cacheMatch) throw new Error(`Unable to resolve AIWG package cache for ${lock.registryKey}`);

const cacheRoot = resolve(cacheMatch[1].trim());
const cachedCommit = capture('git', ['-C', cacheRoot, 'rev-parse', 'HEAD']).trim();
const cachedTree = capture('git', ['-C', cacheRoot, 'rev-parse', `HEAD:${lock.sourceWrapperPath}`]).trim();
if (cachedCommit !== lock.commit) {
  throw new Error(`Pinned commit mismatch: expected ${lock.commit}, received ${cachedCommit}`);
}
if (cachedTree !== lock.wrapperTree) {
  throw new Error(`Pinned wrapper tree mismatch: expected ${lock.wrapperTree}, received ${cachedTree}`);
}

const sourceWrapper = join(cacheRoot, lock.sourceWrapperPath);
assertContained(cacheRoot, sourceWrapper, 'source wrapper');
const targetWrapper = join(projectRoot, lock.wrapperPath);
assertContained(join(projectRoot, '.aiwg', 'plugins'), targetWrapper, 'target wrapper');

const manifest = JSON.parse(readFileSync(join(sourceWrapper, 'manifest.json'), 'utf8'));
if (manifest.id !== lock.package || manifest.type !== 'plugin' || manifest.version !== lock.version) {
  throw new Error(`Wrapper identity mismatch for ${lock.package}@${lock.version}`);
}

const before = compareTrees(sourceWrapper, targetWrapper);
if (checkOnly) {
  if (!before.equal) {
    throw new Error(`Vendored wrapper differs: ${JSON.stringify(before)}`);
  }
  console.log(`bt6-maintainer ${lock.version} matches ${lock.commit} (${lock.wrapperTree})`);
  process.exit(0);
}

const pluginsRoot = dirname(targetWrapper);
const stage = mkdtempSync(join(pluginsRoot, '.bt6-maintainer-stage-'));
const stagedWrapper = join(stage, basename(targetWrapper));
cpSync(sourceWrapper, stagedWrapper, { recursive: true, errorOnExist: true });

const backupRoot = join(projectRoot, '.aiwg', 'working', 'bt6-maintainer-sync-backup');
rmSync(backupRoot, { recursive: true, force: true });
if (existsSync(targetWrapper)) {
  cpSync(targetWrapper, backupRoot, { recursive: true });
  rmSync(targetWrapper, { recursive: true, force: true });
}

try {
  renameSync(stagedWrapper, targetWrapper);
  rmSync(stage, { recursive: true, force: true });
  run('aiwg', ['use', lock.package]);
  run('aiwg', ['use', lock.package, '--provider', 'codex']);
  run('aiwg', ['index', 'build']);
  run('aiwg', ['doctor', '--project-local']);
  const after = compareTrees(sourceWrapper, targetWrapper);
  if (!after.equal) throw new Error(`Post-deploy wrapper differs: ${JSON.stringify(after)}`);
  rmSync(backupRoot, { recursive: true, force: true });
  console.log(`Synchronized ${lock.package} ${lock.version} from ${lock.commit}`);
} catch (error) {
  rmSync(targetWrapper, { recursive: true, force: true });
  if (existsSync(backupRoot) && statSync(backupRoot).isDirectory()) {
    renameSync(backupRoot, targetWrapper);
  }
  throw error;
}
