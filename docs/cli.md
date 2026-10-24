# CLI, Claude Code hook and environment

## CLI

```bash
redstamp check '{"tool":"shell","input":{"command":"rm -rf /"}}'   # firewall one action (--policy <file> to override)
redstamp scan-mcp ./mcp-tools.json                                  # scan an MCP manifest for poisoning
redstamp init                                                       # scan project -> starter redstamp.config.json
redstamp init --global                                              # ...or write the user-wide policy at ~/.warden/config.json
redstamp audit --blocks                                             # what redstamp has stopped (also --tier black, --tail N)
redstamp verify                                                     # verify the tamper-evident audit chain (exit 2 on tamper — CI-usable)
redstamp verify --audit <file>                                      # ...verify a specific audit file
redstamp-hook                                                       # the Claude Code PreToolUse hook (reads a hook payload on stdin)
redstamp-serve                                                      # run the daemon (shared classifier + audit, policy hot-reload)
```

Every command is also available under its legacy `warden*` name (`warden`, `warden-hook`, `warden-mcp`, `warden-serve`) — redstamp was **formerly `warden`**; the repo redirects and env vars keep the `WARDEN_` prefix for compatibility.

## Wiring the Claude Code hook

`redstamp-hook` is the binary you point Claude Code at. Add it as a `PreToolUse` hook in `~/.claude/settings.json`, and as a `PostToolUse` and a `PostToolUseFailure` hook with the same matcher if you want the audit to show which calls ran (Claude Code sends a failed call only to `PostToolUseFailure`, so without it a call that ran and failed leaves no record):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|WebFetch",
        "hooks": [{ "type": "command", "command": "redstamp-hook", "timeout": 15 }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|WebFetch",
        "hooks": [{ "type": "command", "command": "redstamp-hook", "timeout": 5 }]
      }
    ],
    "PostToolUseFailure": [
      {
        "matcher": "Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|WebFetch",
        "hooks": [{ "type": "command", "command": "redstamp-hook", "timeout": 5 }]
      }
    ]
  }
}
```

### What the audit records

Each verdict a host acts on records what the host did with it, in `enforced`:

| `enforced` | written by | meaning |
|---|---|---|
| `blocked` | `redstamp-mcp`, `redstamp-hook` | the call was refused: a block, an approve-tier call in the proxy without `--allow-approve`, or a hook deny |
| `asked` | `redstamp-hook` | strict mode asked the user; the answer never reaches redstamp |
| `forwarded` | `redstamp-mcp`, `redstamp-hook` | the call was passed on; after a hook defer, Claude Code's own permission rules still apply |

Hook records also carry Claude Code's `tool_use_id` and `session_id`. With both post hooks registered, a call that ran adds `{ "event": "invoked", "result": "ok" }` (`"error"` for `PostToolUseFailure`) with the same `tool_use_id`, so whether an asked call ran is observed, not inferred. `invocationOf(verdict, records, { windowComplete })` from `@askalf/redstamp/audit` joins them: it reports `not-invoked` only for a blocked call or when you vouch the records cover the whole window, and `unknown` when records for the same call conflict. Records written before this field, and records from library calls with no host, have no `enforced` and read as before.

A `block` verdict denies the call with the reason; with `strict: true` in your policy (or `WARDEN_STRICT=1`), red-tier calls additionally prompt instead of passing silently. The hook is **fail-open by construction** — a malformed payload or an internal error exits 0 rather than wedging your tooling.

## Environment variables

All keep the `WARDEN_` prefix for compatibility (see the rename note above).

| var | what it does |
|---|---|
| `WARDEN_CONFIG` | override the policy file path |
| `WARDEN_AUDIT` | override the audit-log path (`redstamp audit` / `verify` read it) |
| `WARDEN_STRICT` | `1` → prompt on red-tier calls instead of deferring |
| `WARDEN_READ_MS` | hook stdin read timeout |
| `WARDEN_SOCKET` / `WARDEN_INFO` | daemon socket path / discovery file |
| `WARDEN_TOKEN` | daemon capability token (normally minted for you into the `0600` discovery file) |
| `WARDEN_NO_TAINT` | disable cross-call taint tracking in the daemon |
| `WARDEN_JUDGE_ENDPOINT` / `WARDEN_JUDGE_KEY` / `WARDEN_JUDGE_MODEL` | judge tier endpoint, key, model (key falls back to `ANTHROPIC_API_KEY`) |
| `WARDEN_FALLBACK_HOOK` / `WARDEN_NODE` | native fast hook: path to the Node fallback, and the node binary to run it with |

> **Windows / Git Bash:** MSYS rewrites Unix-looking path arguments before `redstamp` (a native node process) sees them, so a bare `scan-mcp /srv/tools.json` or `--policy /etc/redstamp.config.json` can arrive mangled and miss the file. A quoted JSON action (`redstamp check '{…}'`) is one arg starting with `{`, so it's safe — only path args are affected. Prefix with `MSYS_NO_PATHCONV=1` and use drive-letter paths (`C:/…`), or run from PowerShell/cmd.
