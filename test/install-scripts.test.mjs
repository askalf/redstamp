import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// The one-line installers promise that nothing reaches npm unless the release's provenance check
// passes. These run the real scripts with curl, gh and npm stubbed, so that promise is what is
// tested, and no network or global install is touched.
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const works = (cmd, args) => spawnSync(cmd, args, { stdio: 'ignore' }).status === 0;
const SH = works('sh', ['-c', 'exit 0']);
const PS = ['pwsh', 'powershell'].find((cmd) => works(cmd, ['-NoProfile', '-Command', 'exit 0']));

// A path sh can put on PATH: PATH splits on ":", so a Windows drive prefix has to go.
const shPath = (p) => p.replace(/^([A-Za-z]):/, (_, d) => `/${d.toLowerCase()}`).replace(/\\/g, '/');

function runSh({ tools = ['curl', 'gh', 'npm'], curl = 0, gh = 0, npm = 0 } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redstamp-install-'));
  const log = path.join(dir, 'calls.log');
  const stub = (name, body) => fs.writeFileSync(path.join(dir, name), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  const record = (name, code) => stub(name, `echo "${name} $*" >> "${shPath(log)}"\nexit ${code}`);
  if (tools.includes('curl')) record('curl', curl);
  if (tools.includes('gh')) record('gh', gh);
  if (tools.includes('npm')) stub('npm', `echo "npm $*" >> "${shPath(log)}"\n[ "$1" = install ] && exit ${npm}\nexit 0`);
  stub('mktemp', `echo "${shPath(dir)}"`);
  stub('rm', 'exit 0');
  const script = shPath(path.join(ROOT, 'install', 'redstamp.sh'));
  const res = spawnSync('sh', ['-c', 'PATH="$STUB_PATH"; . "$STUB_SCRIPT"'], { encoding: 'utf8', env: { ...process.env, STUB_PATH: shPath(dir), STUB_SCRIPT: script } });
  const calls = fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '';
  fs.rmSync(dir, { recursive: true, force: true });
  return { status: res.status, calls, out: res.stdout + res.stderr };
}

test('sh: the checked local tarball is what npm installs', { skip: !SH }, () => {
  const r = runSh();
  assert.equal(r.status, 0, r.out);
  assert.match(r.calls, /gh attestation verify \S*redstamp\.tgz --repo askalf\/redstamp --bundle \S*redstamp\.tgz\.sigstore\.json/);
  assert.match(r.calls, /npm install -g \S*redstamp\.tgz\n/);
  assert.doesNotMatch(r.calls, /npm install -g http/);
  assert.ok(r.calls.indexOf('gh attestation') < r.calls.indexOf('npm install'), 'the check comes first');
  assert.match(r.out, /done - try/);
});

test('sh: a failed provenance check never reaches npm', { skip: !SH }, () => {
  const r = runSh({ gh: 1 });
  assert.notEqual(r.status, 0);
  assert.doesNotMatch(r.calls, /npm install/);
  assert.doesNotMatch(r.out, /done - try/);
});

test('sh: a failed download never reaches the check or npm', { skip: !SH }, () => {
  const r = runSh({ curl: 22 });
  assert.notEqual(r.status, 0);
  assert.doesNotMatch(r.calls, /gh attestation|npm install/);
});

test('sh: without gh it refuses rather than installing unchecked', { skip: !SH }, () => {
  const r = runSh({ tools: ['curl', 'npm'] });
  assert.equal(r.status, 1);
  assert.match(r.out, /gh not found/);
  assert.doesNotMatch(r.calls, /npm install/);
});

test('sh: a failed npm install does not report success', { skip: !SH }, () => {
  const r = runSh({ npm: 1 });
  assert.notEqual(r.status, 0);
  assert.doesNotMatch(r.out, /done - try/);
});

function runPs({ gh = 0, npm = 0, web = true } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redstamp-install-ps-'));
  const harness = path.join(dir, 'harness.ps1');
  const script = path.join(ROOT, 'install', 'redstamp.ps1');
  fs.writeFileSync(harness, `
function global:Invoke-WebRequest { param($Uri, $OutFile, [switch]$UseBasicParsing) ${web ? "Set-Content -Path $OutFile -Value 'x'" : "throw 'download failed'"} }
function global:gh { Write-Output "CALL gh $args"; $global:LASTEXITCODE = ${gh} }
function global:npm { Write-Output "CALL npm $args"; if ($args[0] -eq 'install') { $global:LASTEXITCODE = ${npm} } else { $global:LASTEXITCODE = 0 } }
. '${script.replace(/'/g, "''")}'
`);
  const res = spawnSync(PS, ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', harness], { encoding: 'utf8' });
  fs.rmSync(dir, { recursive: true, force: true });
  return { status: res.status, out: res.stdout + res.stderr };
}

test('ps1: the checked local tarball is what npm installs', { skip: !PS }, () => {
  const r = runPs();
  assert.equal(r.status, 0, r.out);
  assert.match(r.out, /CALL gh attestation verify \S*redstamp\.tgz --repo askalf\/redstamp --bundle \S*redstamp\.tgz\.sigstore\.json/);
  assert.match(r.out, /CALL npm install -g \S*redstamp\.tgz/);
  assert.doesNotMatch(r.out, /CALL npm install -g http/);
  assert.match(r.out, /done - try/);
});

test('ps1: a failed provenance check never reaches npm', { skip: !PS }, () => {
  const r = runPs({ gh: 1 });
  assert.notEqual(r.status, 0);
  assert.doesNotMatch(r.out, /CALL npm install/);
  assert.doesNotMatch(r.out, /done - try/);
});

test('ps1: a failed npm install stops before the listing and reports no success', { skip: !PS }, () => {
  const r = runPs({ npm: 1 });
  assert.notEqual(r.status, 0);
  assert.doesNotMatch(r.out, /CALL npm ls/);
  assert.doesNotMatch(r.out, /done - try/);
});

test('ps1: a failed download never reaches the check or npm', { skip: !PS }, () => {
  const r = runPs({ web: false });
  assert.notEqual(r.status, 0);
  assert.doesNotMatch(r.out, /CALL gh|CALL npm/);
});

// gh release download needs a signed-in gh, and gh attestation verify with a bundle does not, so
// the download stays on plain HTTPS: an installer that needed a login would fail for anyone
// who has gh but has not signed in.
test('neither installer downloads through gh', () => {
  for (const name of ['redstamp.sh', 'redstamp.ps1']) {
    const code = fs.readFileSync(path.join(ROOT, 'install', name), 'utf8').split('\n').filter((l) => !l.trim().startsWith('#'));
    assert.ok(!code.some((l) => /gh release download/.test(l)), name);
  }
});

test('neither installer hands a remote URL to npm', () => {
  for (const name of ['redstamp.sh', 'redstamp.ps1']) {
    const code = fs.readFileSync(path.join(ROOT, 'install', name), 'utf8').split('\n').filter((l) => !l.trim().startsWith('#'));
    for (const line of code) {
      if (/\bnpm (install|i)\b/.test(line)) assert.doesNotMatch(line, /https?:|\$BASE|\$base/, `${name}: ${line}`);
    }
  }
});

test('the documented one-liners fetch from master, the branch these scripts land on', () => {
  const doc = fs.readFileSync(path.join(ROOT, 'docs', 'install.md'), 'utf8');
  const urls = doc.match(/https:\/\/raw\.githubusercontent\.com\/askalf\/redstamp\/[^\s"]+/g) ?? [];
  assert.equal(urls.length, 2);
  for (const u of urls) assert.match(u, /\/redstamp\/master\/install\/redstamp\.(sh|ps1)$/);
});
