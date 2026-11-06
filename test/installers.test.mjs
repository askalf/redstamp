import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const root = path.resolve(import.meta.dirname ?? path.dirname(new URL(import.meta.url).pathname), '..');
const SH = path.join(root, 'install', 'redstamp.sh');
const PS1 = path.join(root, 'install', 'redstamp.ps1');

const hasCmd = (cmd, args) => spawnSync(cmd, args, { stdio: 'ignore' }).status === 0;
const isWin = process.platform === 'win32';
const hasSh = !isWin && hasCmd('sh', ['-c', 'exit 0']);
const hasPwsh = !isWin && hasCmd('pwsh', ['-NoProfile', '-Command', 'exit 0']);

// Fake gh and npm on PATH. gh writes the release assets into --dir and
// verifies with the given exit code; npm logs its argv and fails install
// with the given exit code.
function stubs({ verifyExit = 0, npmExit = 0 } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redstamp-installer-'));
  const log = path.join(dir, 'npm.log');
  fs.writeFileSync(path.join(dir, 'gh'), `#!/bin/sh
if [ "$1 $2" = "release download" ]; then
  while [ $# -gt 0 ]; do
    if [ "$1" = "--dir" ]; then d="$2"; fi
    shift
  done
  : > "$d/redstamp.tgz"; : > "$d/redstamp.tgz.sigstore.json"
  exit 0
fi
if [ "$1 $2" = "attestation verify" ]; then exit ${verifyExit}; fi
exit 2
`, { mode: 0o755 });
  fs.writeFileSync(path.join(dir, 'npm'), `#!/bin/sh
echo "$*" >> "${log}"
if [ "$1" = "install" ]; then exit ${npmExit}; fi
exit 0
`, { mode: 0o755 });
  const env = { ...process.env, PATH: `${dir}${path.delimiter}${process.env.PATH}` };
  const npmCalls = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n') : []);
  return { dir, env, npmCalls };
}

const runSh = (env) => spawnSync('sh', [SH], { env, encoding: 'utf8' });
const runPs1 = (env) => spawnSync('pwsh', ['-NoProfile', '-NonInteractive', '-File', PS1], { env, encoding: 'utf8' });

test('redstamp.sh: failed verification never runs npm', { skip: !hasSh }, () => {
  const s = stubs({ verifyExit: 1 });
  const r = runSh(s.env);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /verification failed/);
  assert.deepEqual(s.npmCalls(), []);
});

test('redstamp.sh: installs the verified local tarball', { skip: !hasSh }, () => {
  const s = stubs();
  const r = runSh(s.env);
  assert.equal(r.status, 0, r.stderr);
  const install = s.npmCalls().find((l) => l.startsWith('install'));
  assert.match(install, /^install -g \/.*redstamp\.tgz$/);
  assert.doesNotMatch(install, /https?:/);
});

test('redstamp.sh: npm install failure exits nonzero without success', { skip: !hasSh }, () => {
  const s = stubs({ npmExit: 1 });
  const r = runSh(s.env);
  assert.notEqual(r.status, 0);
  assert.doesNotMatch(r.stdout, /done - try/);
});

test('redstamp.ps1: failed verification never runs npm', { skip: !hasPwsh }, () => {
  const s = stubs({ verifyExit: 1 });
  const r = runPs1(s.env);
  assert.notEqual(r.status, 0);
  assert.deepEqual(s.npmCalls(), []);
});

test('redstamp.ps1: npm install failure exits before npm ls and success', { skip: !hasPwsh }, () => {
  const s = stubs({ npmExit: 1 });
  const r = runPs1(s.env);
  assert.notEqual(r.status, 0);
  assert.doesNotMatch(r.stdout, /done - try/);
  assert.ok(!s.npmCalls().some((l) => l.startsWith('ls')));
});

const codeLines = (file) => fs.readFileSync(file, 'utf8').split('\n').filter((l) => !l.trimStart().startsWith('#'));

test('redstamp.ps1: every native command is followed by a $LASTEXITCODE check', () => {
  const code = codeLines(PS1);
  for (const cmd of [/^\s*gh release download\b/, /^\s*gh attestation verify\b/, /^\s*npm install\b/]) {
    const i = code.findIndex((l) => cmd.test(l));
    assert.ok(i >= 0, `missing ${cmd}`);
    assert.match(code[i + 1], /\$LASTEXITCODE -ne 0.*throw/, `no exit check after ${code[i].trim()}`);
  }
  const install = code.findIndex((l) => /^\s*npm install\b/.test(l));
  const ls = code.findIndex((l) => /^\s*npm ls\b/.test(l));
  const exit = code.findIndex((l, i) => i > install && /^\s*exit 1\b/.test(l));
  assert.ok(install < exit && exit < ls, 'a failed install must exit before npm ls');
});

test('installers never hand a remote URL to npm', () => {
  for (const file of [SH, PS1]) {
    for (const line of codeLines(file)) {
      if (/\bnpm (install|i)\b/.test(line)) assert.doesNotMatch(line, /https?:|\$url\b/i, `${file}: ${line}`);
    }
  }
});

test('documented one-line installers fetch from master', () => {
  const doc = fs.readFileSync(path.join(root, 'docs', 'install.md'), 'utf8');
  const urls = doc.match(/https:\/\/raw\.githubusercontent\.com\/askalf\/redstamp\/[^\s"]+/g) ?? [];
  assert.equal(urls.length, 2);
  for (const u of urls) assert.match(u, /\/redstamp\/master\/install\/redstamp\.(sh|ps1)$/);
});
