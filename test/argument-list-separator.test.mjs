// Regression tests for the -ArgumentList comma-array evasion (2026-08-04).
//
// The Windows black rules keyed the gap between a flag/subcommand and its VALUE
// on whitespace (`\s+`). PowerShell's -ArgumentList takes an ARRAY, so the
// idiomatic spelling separates them with `','` instead — and the same launch
// that rated black space-separated rated CLEAN in array form. Proven live on a
// device: two dispatches of one command 7 minutes apart, only the separator
// style differing; one was blocked, one ran.
//
// Every case pins BOTH spellings so the pair can never drift apart again, and
// the last two tests pin benign siblings so the widening cannot leak into prose.
//
// Fixtures are BUILT from fragments rather than written literally, per this
// repo's existing convention (see base64-shell-spellings.test.mjs) — a literal
// fixture here reads as a live payload to the scanners that watch this repo.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classify, TIER } from '../src/classify.mjs';

const tier = (command) => classify({ tool: 'shell', input: { command } }).tier;

const BS = '\u005c';                 // Windows path separator, kept out of paths
const PS = 'power' + 'shell';
const SP = 'Start-Pro' + 'cess';
const AL = '-Argument' + 'List';

// Two spellings of ONE command line. `spaced` is the form the ruleset already
// caught; `arr` is the array form that walked past it. The OS runs both, so
// both must reach the same verdict.
const spaced = (exe, ...args) => `${exe} ${args.join(' ')}`;
const arr = (exe, ...args) => `${SP} ${exe} ${AL} ` + args.map((a) => `'${a}'`).join(',');
// An exe+subcommand pair reaches the array via a launcher, with the pair itself
// INSIDE the array, separated by `','`.
const cmdArr = (...args) => arr('cmd', '/c', ...args);

const bothBlack = (exe, ...args) => {
  assert.equal(tier(spaced(exe, ...args)), TIER.BLACK, `spaced: ${exe}`);
  assert.equal(tier(arr(exe, ...args)), TIER.BLACK, `array: ${exe}`);
};
const pairBlack = (...args) => {
  assert.equal(tier(spaced(...args)), TIER.BLACK, `spaced: ${args[0]}`);
  assert.equal(tier(cmdArr(...args)), TIER.BLACK, `array: ${args[0]}`);
};

// ── the reported hole ───────────────────────────────────────────────────────
const EP = '-Execution' + 'Policy';
const BYPASS = 'Byp' + 'ass';
const WSTYLE = '-Window' + 'Style';
const HIDDEN = 'Hid' + 'den';
const ENC = '-Encoded' + 'Command';
const B64 = 'QUJDREVGR0hJSktMTU5PUFFSU1Q';

test('hidden + bypass powershell is black in BOTH separator styles', () => {
  bothBlack(PS, EP, BYPASS, WSTYLE, HIDDEN, '-File', 'C:' + BS + 'x.ps1');
});

test('hidden + encoded powershell is black in BOTH separator styles', () => {
  bothBlack(PS + '.exe', WSTYLE, HIDDEN, ENC, B64);
  bothBlack(PS + '.exe', WSTYLE, HIDDEN, '-enc', B64);
});

test('the standalone encoded-command rule accepts the array separator', () => {
  bothBlack(PS, ENC, B64);
});

// ── sibling rules that shared the whitespace-only assumption ────────────────
const RG = 'r' + 'eg';
const A = 'a' + 'dd';
const RUN_KEY = ['HKLM', 'Software', 'Microsoft', 'Windows', 'CurrentVersion', 'Run'].join(BS);
const SVC_KEY = ['HKLM', 'SYSTEM', 'CurrentControlSet', 'Services', 'Evil'].join(BS);

test('registry persistence / credential-dump rules accept the array separator', () => {
  pairBlack(RG, A, RUN_KEY, '/v', 'x', '/d', 'e.exe');
  pairBlack(RG, A, SVC_KEY, '/v', 'ImagePath');
  pairBlack(RG, 'save', 'HKLM' + BS + 'SAM', 'C:' + BS + 't.hiv');
  pairBlack(RG, 'delete', 'HKLM' + BS + 'SYSTEM', '/f');
});

const SC = 's' + 'c.exe';
const DEFENDER = 'Win' + 'Defend';
const WEVT = 'wevt' + 'util';

test('service / defender / log / boot / account rules accept the array separator', () => {
  pairBlack(SC, 'create', 'Evil', 'binPath=C:' + BS + 'm.exe');
  pairBlack(SC, 'stop', DEFENDER);
  pairBlack(WEVT, 'c' + 'l', 'Security');
  pairBlack('bcd' + 'edit', '/set', 'recovery' + 'enabled', 'n' + 'o');
  pairBlack('net', 'localgroup', 'admin' + 'istrators', 'evil', '/' + 'add');
  pairBlack('wm' + 'ic', 'process', 'ca' + 'll', 'create', 'calc.exe');
});

const RM = 'Remove-' + 'Item';
const SYS_ROOT = 'C:' + BS + 'Wind' + 'ows';

test('Windows drive-root deletion accepts the array separator', () => {
  assert.equal(tier(spaced(RM, '-Recurse', '-Force', SYS_ROOT)), TIER.BLACK);
  assert.equal(tier(arr(PS, '-Command', RM, '-Recurse', '-Force', SYS_ROOT)), TIER.BLACK);
  assert.equal(tier(cmdArr('r' + 'd', '/s', '/q', SYS_ROOT)), TIER.BLACK);
});

// ── the fix must not over-widen ────────────────────────────────────────────
test('benign Windows commands are still not black', () => {
  assert.notEqual(tier(arr(PS, '-File', '.' + BS + 'build.ps1')), TIER.BLACK);
  // hidden ALONE is not the rule — it takes hidden AND bypass/encoded.
  assert.notEqual(tier(arr(PS, WSTYLE, HIDDEN, '-File', '.' + BS + 'build.ps1')), TIER.BLACK);
  assert.notEqual(tier(cmdArr(RG, 'query', RUN_KEY)), TIER.BLACK);
  assert.notEqual(tier(cmdArr(SC, 'query', DEFENDER)), TIER.BLACK);
  assert.notEqual(tier(cmdArr(WEVT, 'qe', 'Security', '/c:5')), TIER.BLACK);
  assert.notEqual(tier(spaced(RM, '-Recurse', '-Force', 'node_modules')), TIER.BLACK);
  assert.notEqual(tier(arr('npm', 'run', 'build')), TIER.BLACK);
});

// ARGSEP requires the comma to be QUOTED ON BOTH SIDES precisely so an English
// comma between two bare words cannot bridge them into a command.
test('a bare comma between words is prose, not an argument array', () => {
  assert.notEqual(tier(`Write-Output "the ${'n' + 'et'}, ${'local' + 'group'} and ${A} keywords"`), TIER.BLACK);
  assert.notEqual(tier(`$${RG} = Get-Content notes.txt`), TIER.BLACK);
  assert.notEqual(tier(`${SC}, ${WEVT}, and ${RG} are Windows tools`), TIER.BLACK);
});
