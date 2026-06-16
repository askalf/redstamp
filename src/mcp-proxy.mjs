// MCP stdio proxy — sits transparently between an MCP client and a downstream
// MCP server. Firewalls every `tools/call`, strips poisoned tools out of
// `tools/list` responses, and neutralizes prompt-injection in tool RESULTS.
// JSON-RPC over newline-delimited stdio.
import { spawn } from 'node:child_process';
import { check } from './index.mjs';
import { mapMcpToAction, scanMcpTools, scanToolResult } from './mcp.mjs';

const MAX_LINE = 1 << 20; // 1 MiB — a single JSON-RPC frame shouldn't exceed this

const toolError = (id, text) =>
  JSON.stringify({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text }], isError: true } });

/**
 * A bounded newline framer. Buffers stream chunks and yields complete lines;
 * if the trailing (un-terminated) buffer ever exceeds maxLen it is dropped and
 * `overflow` is reported — so a hostile peer can't exhaust memory by never
 * sending a newline. Pure + synchronous → unit-testable without a stream.
 */
export function makeFramer(maxLen = MAX_LINE) {
  let buf = '';
  return function push(chunk) {
    buf += chunk;
    const lines = [];
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) { lines.push(buf.slice(0, nl)); buf = buf.slice(nl + 1); }
    let overflow = false;
    if (buf.length > maxLen) { buf = ''; overflow = true; } // partial frame too big → drop
    return { lines, overflow };
  };
}

/** client → server. Returns { forwardLine } to pass on, or { replyLine } to short-circuit a block. */
export function inspectClientLine(line, state, policy, opts = {}) {
  let msg;
  try { msg = JSON.parse(line); } catch { return { forwardLine: line }; }
  if (msg && msg.method && msg.id != null) state.pending[msg.id] = msg.method;
  if (msg && msg.method === 'tools/call') {
    const name = msg.params?.name;
    const args = msg.params?.arguments || {};
    const action = mapMcpToAction(name, args, opts.nameMap || {});
    const v = check(action, policy, { audit: opts.audit });
    const blocked = v.decision === 'block' || (v.decision === 'approve' && !opts.allowApprove);
    if (blocked) {
      opts.onWarn?.(`blocked ${name} (${v.tier}): ${v.why.join('; ')}`);
      const hint = v.decision === 'approve' ? ' — add an allow rule to warden.config.json to permit it.' : '';
      return { replyLine: toolError(msg.id, `⛔ warden blocked this call (${v.tier}): ${v.why.join('; ')}${hint}`) };
    }
    if (v.decision === 'approve') opts.onWarn?.(`allowed (approve-tier, --allow-approve) ${name}`);
    return { forwardLine: line };
  }
  return { forwardLine: line };
}

/** server → client. Returns { forwardLine }, possibly rewritten to strip poisoned
 *  tools from a tools/list or to neutralize an injected tools/call result. */
export function inspectServerLine(line, state, opts = {}) {
  let msg;
  try { msg = JSON.parse(line); } catch { return { forwardLine: line }; }
  const method = msg && msg.id != null ? state.pending[msg.id] : undefined;
  if (method === 'tools/list' && msg.result?.tools) {
    delete state.pending[msg.id];
    const findings = scanMcpTools(msg.result.tools);
    if (findings.length) {
      for (const f of findings) opts.onWarn?.(`poisoned tool from server: ${f.tool} (${f.flags.join(', ')})`);
      if (opts.strip !== false) {
        const bad = new Set(findings.map((f) => f.tool));
        msg.result.tools = msg.result.tools.filter((t) => !bad.has(t.name));
        return { forwardLine: JSON.stringify(msg) };
      }
    }
  } else if (method === 'tools/call' && msg.result != null) {
    delete state.pending[msg.id];
    const hits = scanToolResult(msg.result);
    if (hits.length) {
      opts.onWarn?.(`injection in tool result (call #${msg.id}): ${hits.join(', ')}`);
      if (opts.scanResults !== false) {
        msg.result = { content: [{ type: 'text', text: `⛔ warden neutralized this tool result — prompt-injection detected in the returned content (${hits.join('; ')}).` }], isError: true };
        return { forwardLine: JSON.stringify(msg) };
      }
    }
  } else if (method && msg.id != null) {
    delete state.pending[msg.id];
  }
  return { forwardLine: line };
}

/** Spawn the downstream server and wire the two firewalled streams together. */
export function runProxy({ command, args = [], policy = {}, audit = null, auditPath = null, allowApprove = false, strip = true, scanResults = true, nameMap = {}, maxLine = MAX_LINE }) {
  const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'inherit'] });
  const state = { pending: {} };
  const opts = { allowApprove, strip, scanResults, nameMap, audit, onWarn: (m) => process.stderr.write('[warden] ' + m + '\n') };

  const fromClient = makeFramer(maxLine);
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => {
    const { lines, overflow } = fromClient(chunk);
    if (overflow) opts.onWarn?.(`dropped an oversized client frame (> ${maxLine}B)`);
    for (const line of lines) {
      if (!line.trim()) continue;
      const r = inspectClientLine(line, state, policy, opts);
      if (r.replyLine) process.stdout.write(r.replyLine + '\n');
      if (r.forwardLine) child.stdin.write(r.forwardLine + '\n');
    }
  });

  const fromServer = makeFramer(maxLine);
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    const { lines, overflow } = fromServer(chunk);
    if (overflow) opts.onWarn?.(`dropped an oversized server frame (> ${maxLine}B)`);
    for (const line of lines) {
      if (!line.trim()) continue;
      process.stdout.write(inspectServerLine(line, state, opts).forwardLine + '\n');
    }
  });

  process.stdin.on('end', () => { try { child.stdin.end(); } catch {} });
  child.on('exit', (code) => { if (audit && auditPath) try { audit.flush(auditPath); } catch {} process.exit(code ?? 0); });
}
