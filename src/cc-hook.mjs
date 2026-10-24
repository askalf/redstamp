#!/usr/bin/env node
// warden as a Claude Code PreToolUse hook.
// Fast path: ask the warden daemon (shared classifier + audit). Fallback: run an
// in-process check if the daemon isn't running. Fail-open: any error -> defer,
// so a warden bug never bricks your tooling.
//
// Posture: black -> deny; approve-tier -> ask only in strict mode; else defer.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadPolicy } from './policy.mjs';
import { daemonCheck } from './client.mjs';

/** Map a Claude Code tool_name + tool_input to a warden action. */
export function ccToAction(toolName, ti = {}) {
  const t = (toolName || '').toLowerCase();
  if (t === 'bash' || t === 'powershell' || t === 'shell') return { tool: 'shell', input: { command: ti.command || ti.cmd || '' } };
  if (t === 'write') return { tool: 'write', input: { path: ti.file_path || ti.path || '', content: ti.file_text || ti.content || '' } };
  if (t === 'edit' || t === 'multiedit') return { tool: 'edit', input: { path: ti.file_path || ti.path || '' } };
  if (t === 'notebookedit') return { tool: 'edit', input: { path: ti.notebook_path || ti.file_path || '' } };
  if (t === 'read') return { tool: 'read', input: { path: ti.file_path || ti.path || '' } };
  if (t === 'webfetch' || t === 'fetch') return { tool: 'fetch', input: { url: ti.url || '', method: 'GET' } };
  if (t === 'websearch') return { tool: 'read', input: { query: ti.query || '' } };
  if (t === 'grep') return { tool: 'grep', input: { pattern: ti.pattern || '' } };
  if (t === 'glob' || t === 'ls') return { tool: 'list', input: { pattern: ti.pattern || '' } };
  return { tool: t || 'unknown', input: ti };
}

/** Map a warden verdict to a Claude Code hook decision. */
export function verdictToHook(verdict, strict) {
  if (verdict.decision === 'block') return { kind: 'deny', reason: `⛔ warden blocked (${verdict.tier}): ${verdict.why.join('; ')}` };
  if (verdict.decision === 'approve' && strict) return { kind: 'ask', reason: `warden flagged (${verdict.tier}): ${verdict.why.join('; ')}` };
  return { kind: 'defer' };
}

/** What the hook did with a verdict, as the audit records it: deny -> blocked, ask -> asked, defer -> forwarded (to Claude Code's own permission rules). */
export const enforcedBy = (kind) => (kind === 'deny' ? 'blocked' : kind === 'ask' ? 'asked' : 'forwarded');

/** The ids that join a PreToolUse verdict to the PostToolUse record of the same call. Only string ids are kept. */
export function hookRef(p = {}) {
  const ref = {};
  if (typeof p.tool_use_id === 'string' && p.tool_use_id) ref.tool_use_id = p.tool_use_id;
  if (typeof p.session_id === 'string' && p.session_id) ref.session_id = p.session_id;
  return ref;
}

/** Hook events that mean the tool ran: PostToolUse after a success, PostToolUseFailure after an error. */
export const INVOKED_EVENTS = new Set(['PostToolUse', 'PostToolUseFailure']);

/** The audit record for a PostToolUse payload: the call ran, observed rather than inferred. */
export function invocationRecord(p = {}) {
  return { event: 'invoked', tool: ccToAction(p.tool_name, {}).tool, result: p.hook_event_name === 'PostToolUseFailure' ? 'error' : 'ok', ...hookRef(p) };
}

const out =(permissionDecision, reason) =>
  process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision, permissionDecisionReason: reason } }));

function readStdin() {
  return new Promise((res) => {
    let d = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (d += c));
    process.stdin.on('end', () => res(d));
    setTimeout(() => res(d), 2500);
  });
}

async function main() {
  const HOME = process.env.USERPROFILE || process.env.HOME || os.homedir();
  const CFG = process.env.WARDEN_CONFIG || path.join(HOME, '.warden', 'config.json');
  const AUDIT = process.env.WARDEN_AUDIT || path.join(HOME, '.warden', 'audit.jsonl');
  let payload;
  try { payload = JSON.parse((await readStdin()) || '{}'); } catch { process.exit(0); } // fail-open
  const append = (rec) => {
    try { fs.mkdirSync(path.dirname(AUDIT), { recursive: true }); fs.appendFileSync(AUDIT, JSON.stringify({ ts: new Date().toISOString(), ...rec }) + '\n'); } catch {}
  };
  try {
    // Registered for PostToolUse too: record that the call ran, joined to its
    // verdict by tool_use_id. The daemon writes it to the same chained log as the
    // verdict; with no daemon it goes beside the fallback verdicts. Nothing to say
    // to Claude Code, so nothing on stdout.
    if (INVOKED_EVENTS.has(payload.hook_event_name)) {
      const rec = invocationRecord(payload);
      // Only the ids go to the daemon: tool_response can be larger than its frame cap.
      const { tool_name, hook_event_name, tool_use_id, session_id } = payload;
      if (rec.tool_use_id && !(await daemonCheck({ invoked: { tool_name, hook_event_name, tool_use_id, session_id } }, { timeoutMs: 1500 }))) append(rec);
      process.exit(0);
    }
    const policy = loadPolicy(CFG);
    const strict = policy.strict || !!process.env.WARDEN_STRICT;
    const action = ccToAction(payload.tool_name, payload.tool_input || {});
    // Long read timeout: a daemon with the judge tier may think for seconds on a
    // gray command. Connect still fails fast (daemon down -> in-process fallback).
    const readMs = Number(process.env.WARDEN_READ_MS) || 15000;
    // `enforce` tells the daemon what this hook will do with the verdict (strict
    // decides ask vs defer), so its audit record carries `enforced` and the ids.
    const enforce = { strict, ...hookRef(payload) };
    let v = await daemonCheck({ action, skillText: '', enforce }, { timeoutMs: readMs }); // fast path (daemon also audits)
    const auditedByDaemon = !!v;
    if (!v) { const { check } = await import('./index.mjs'); v = check(action, policy, {}); } // fallback
    const d = verdictToHook(v, strict);
    if (!auditedByDaemon) append({ tool: payload.tool_name, tier: v.tier, decision: v.decision, why: v.why, enforced: enforcedBy(d.kind), ...hookRef(payload) });
    if (d.kind === 'deny') out('deny', d.reason);
    else if (d.kind === 'ask') out('ask', d.reason);
    process.exit(0);
  } catch (e) {
    process.stderr.write('warden-hook error (fail-open): ' + (e && e.message || e) + '\n');
    process.exit(0); // fail-open
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
