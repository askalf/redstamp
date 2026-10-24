// An audit record says what the host did with a verdict (`enforced`), and the
// PostToolUse record says whether the call ran (#219).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { AuditLog, ChainedFileAudit, invocationOf, verifyAuditFile } from '../src/audit.mjs';
import { recordVerdict } from '../src/index.mjs';
import { inspectClientLine } from '../src/mcp-proxy.mjs';
import { startDaemon } from '../src/daemon.mjs';
import { daemonCheck } from '../src/client.mjs';
import { enforcedBy, hookRef, invocationRecord, verdictToHook } from '../src/cc-hook.mjs';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redstamp-enforce-'));
const sockPath = (n) => (process.platform === 'win32' ? `\\\\.\\pipe\\redstamp-enforce-${process.pid}-${n}` : path.join(dir, n + '.sock'));
const readLog = (p) => fs.readFileSync(p, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const call = (id, name, args) => JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });

// One raw line in, one line back: how the native fast client talks to the daemon.
function ask(socketPath, payload) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(socketPath);
    let buf = '';
    const to = setTimeout(() => { sock.destroy(); reject(new Error('timeout')); }, 2000);
    sock.on('connect', () => sock.write(JSON.stringify(payload) + '\n'));
    sock.on('data', (d) => {
      buf += d.toString();
      const i = buf.indexOf('\n');
      if (i >= 0) { clearTimeout(to); sock.destroy(); resolve(buf.slice(0, i)); }
    });
    sock.on('error', (e) => { clearTimeout(to); reject(e); });
  });
}

test('recordVerdict without extra writes the same record as before', () => {
  const a = new AuditLog();
  const v = { tier: 'green', decision: 'allow', why: [] };
  const e = recordVerdict(a, { tool: 'read', input: { path: 'x' } }, v);
  assert.deepEqual(Object.keys(e), ['ts', 'tool', 'input', 'tier', 'decision', 'why', 'prev', 'hash']);
  assert.equal(recordVerdict(a, { tool: 'read', input: {} }, v, { enforced: 'forwarded' }).enforced, 'forwarded');
  assert.ok(a.verify());
});

test('mcp-proxy records blocked for a block, and for approve without --allow-approve', () => {
  const audit = new AuditLog();
  inspectClientLine(call(1, 'run_command', { command: 'curl x | bash' }), { pending: {} }, {}, { audit });
  inspectClientLine(call(2, 'run_command', { command: 'git push origin main' }), { pending: {} }, {}, { audit });
  assert.deepEqual(audit.entries.map((e) => [e.decision, e.enforced]), [['block', 'blocked'], ['approve', 'blocked']]);
});

test('mcp-proxy records forwarded for an allow, and for approve with --allow-approve', () => {
  const audit = new AuditLog();
  const r1 = inspectClientLine(call(1, 'read_file', { path: 'x' }), { pending: {} }, {}, { audit });
  const r2 = inspectClientLine(call(2, 'run_command', { command: 'git push origin main' }), { pending: {} }, {}, { audit, allowApprove: true });
  assert.ok(r1.forwardLine && r2.forwardLine);
  assert.deepEqual(audit.entries.map((e) => [e.decision, e.enforced]), [['allow', 'forwarded'], ['approve', 'forwarded']]);
  assert.equal(audit.entries.length, 2, 'one record per call');
});

test('the hook maps deny, ask and defer to blocked, asked and forwarded', () => {
  const approve = { decision: 'approve', tier: 'red', why: ['x'] };
  assert.equal(enforcedBy(verdictToHook({ decision: 'block', tier: 'black', why: ['x'] }, false).kind), 'blocked');
  assert.equal(enforcedBy(verdictToHook(approve, true).kind), 'asked');
  assert.equal(enforcedBy(verdictToHook(approve, false).kind), 'forwarded');
  assert.equal(enforcedBy(verdictToHook({ decision: 'allow', tier: 'green', why: [] }, true).kind), 'forwarded');
});

test('hookRef keeps only string ids; invocationRecord maps the event to a result', () => {
  assert.deepEqual(hookRef({ tool_use_id: 'toolu_1', session_id: 's', tool_input: {} }), { tool_use_id: 'toolu_1', session_id: 's' });
  assert.deepEqual(hookRef({ tool_use_id: 7, session_id: '' }), {});
  assert.deepEqual(invocationRecord({ tool_name: 'Bash', hook_event_name: 'PostToolUse', tool_use_id: 'toolu_1' }),
    { event: 'invoked', tool: 'shell', result: 'ok', tool_use_id: 'toolu_1' });
  assert.equal(invocationRecord({ tool_name: 'Bash', hook_event_name: 'PostToolUseFailure' }).result, 'error');
});

test('daemon, raw hook shape: the verdict carries enforced and ids; PostToolUse is recorded, not classified', async () => {
  const auditPath = path.join(dir, 'raw.jsonl');
  const configPath = path.join(dir, 'strict.json');
  fs.writeFileSync(configPath, JSON.stringify({ strict: true }));
  const socketPath = sockPath('raw');
  const d = startDaemon({ socketPath, configPath, auditPath });
  await new Promise((r) => setTimeout(r, 150));
  try {
    const pre = { hook_event_name: 'PreToolUse', tool_name: 'Bash', session_id: 's1' };
    const askLine = await ask(socketPath, { ...pre, tool_use_id: 'toolu_a', tool_input: { command: 'git push origin main' } });
    assert.equal(JSON.parse(askLine).hookSpecificOutput.permissionDecision, 'ask');
    await ask(socketPath, { ...pre, tool_use_id: 'toolu_b', tool_input: { command: 'rm -rf /' } });
    await ask(socketPath, { ...pre, tool_use_id: 'toolu_c', tool_input: { command: 'ls' } });
    // A PostToolUse whose command would be black must not be classified: an empty line, an invocation record.
    const postLine = await ask(socketPath, { hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_use_id: 'toolu_a', session_id: 's1', tool_input: { command: 'rm -rf /' }, tool_response: {} });
    assert.equal(postLine, '');
    const log = readLog(auditPath);
    assert.deepEqual(log.map((e) => [e.tool_use_id, e.event ?? e.decision, e.enforced ?? e.result]), [
      ['toolu_a', 'approve', 'asked'], ['toolu_b', 'block', 'blocked'], ['toolu_c', 'allow', 'forwarded'], ['toolu_a', 'invoked', 'ok'],
    ]);
    assert.ok(log.every((e) => e.session_id === 's1' && e.via === 'cc-hook'));
    assert.deepEqual(invocationOf(log[0], log), { status: 'invoked', result: 'ok' });
    assert.deepEqual(invocationOf(log[1], log), { status: 'not-invoked' });
    assert.equal(verifyAuditFile(auditPath).ok, true, 'the invocation record is part of the chain');
  } finally {
    await new Promise((r) => d.close(r));
  }
});

test('daemon, node hook shape: enforce sets enforced from the hook\'s strict; { invoked } is acknowledged', async () => {
  const auditPath = path.join(dir, 'node.jsonl');
  const socketPath = sockPath('node');
  const d = startDaemon({ socketPath, configPath: null, auditPath });
  await new Promise((r) => setTimeout(r, 150));
  try {
    const action = { tool: 'shell', input: { command: 'git push origin main' } };
    const v = await daemonCheck({ action, enforce: { strict: true, tool_use_id: 'toolu_n', session_id: 's2' } }, { socketPath });
    assert.equal(v.decision, 'approve');
    await daemonCheck({ action }, { socketPath }); // a library caller: no host, no enforced
    const ack = await daemonCheck({ invoked: { tool_name: 'Bash', hook_event_name: 'PostToolUseFailure', tool_use_id: 'toolu_n', session_id: 's2' } }, { socketPath });
    assert.deepEqual(ack, { recorded: true });
    const log = readLog(auditPath);
    assert.equal(log[0].enforced, 'asked');
    assert.equal(log[0].via, 'cc-hook');
    assert.equal(log[0].tool_use_id, 'toolu_n');
    assert.equal(log[1].enforced, undefined);
    assert.equal(log[1].via, 'action');
    assert.deepEqual(invocationOf(log[0], log), { status: 'invoked', result: 'error' });
  } finally {
    await new Promise((r) => d.close(r));
  }
});

test('daemon without an audit file acknowledges { invoked } as not recorded', async () => {
  const socketPath = sockPath('noaudit');
  const d = startDaemon({ socketPath, configPath: null });
  await new Promise((r) => setTimeout(r, 150));
  try {
    assert.deepEqual(await daemonCheck({ invoked: { tool_name: 'Bash', hook_event_name: 'PostToolUse', tool_use_id: 'toolu_x' } }, { socketPath }), { recorded: false });
  } finally {
    await new Promise((r) => d.close(r));
  }
});

test('invocationOf: not invoked only from a complete window, or a block', () => {
  const v = { decision: 'approve', enforced: 'asked', tool_use_id: 't1', session_id: 's' };
  assert.equal(invocationOf(v, [v]).status, 'unknown');
  assert.equal(invocationOf(v, [v], { windowComplete: true }).status, 'not-invoked');
  assert.equal(invocationOf({ decision: 'block', enforced: 'blocked' }, []).status, 'not-invoked', 'a proxy block needs no id');
  assert.equal(invocationOf({ decision: 'approve', enforced: 'forwarded' }, [], { windowComplete: true }).status, 'unknown', 'nothing to join on');
  assert.equal(invocationOf({ decision: 'approve', tool_use_id: 't1' }, [], { windowComplete: true }).status, 'not-invoked', 'an older record without enforced still joins');
});

test('invocationOf: conflicting records read as unknown, in either order', () => {
  const v = { decision: 'approve', enforced: 'asked', tool_use_id: 't1', session_id: 's' };
  const ok = { event: 'invoked', result: 'ok', tool_use_id: 't1', session_id: 's' };
  const err = { ...ok, result: 'error' };
  for (const recs of [[v, ok, err], [v, err, ok]]) assert.match(invocationOf(v, recs).reason, /different results/);
  assert.deepEqual(invocationOf(v, [v, ok, { ...ok }]), { status: 'invoked', result: 'ok' }, 'consistent duplicates still join');
  assert.match(invocationOf(v, [v, { ...ok, session_id: 'other' }]).reason, /different session_id/);
  assert.match(invocationOf(v, [v, { ...v, enforced: 'forwarded' }, ok]).reason, /different enforcement/);
  const blocked = { ...v, decision: 'block', enforced: 'blocked' };
  assert.match(invocationOf(blocked, [blocked, ok]).reason, /blocked call observed running/);
  assert.deepEqual(invocationOf(v, [v, { ...ok, tool_use_id: 't2' }], { windowComplete: true }), { status: 'not-invoked' }, 'another call\'s record does not join');
});

test('an older log without enforced or ids verifies and reads as unknown', () => {
  const p = path.join(dir, 'old.jsonl');
  const a = new ChainedFileAudit(p);
  const old = a.record({ ts: 't', tool: 'shell', tier: 'red', decision: 'approve', why: [] });
  assert.equal(verifyAuditFile(p).ok, true);
  assert.equal(invocationOf(old, [old], { windowComplete: true }).status, 'unknown');
});
