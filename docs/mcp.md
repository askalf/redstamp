# redstamp and MCP

## MCP middleware

Firewall an MCP server's tool-calls, and scan its advertised tools for poisoning:

```js
import { guardHandler, scanMcpTools } from '@askalf/redstamp/mcp';

// 1) supply-chain: catch malicious instructions hidden in tool descriptions
const findings = scanMcpTools(server.tools); // [{ tool, flags, severity, hits }]
// severity: 'critical' = injection/exfil *instructions*; 'advisory' = a bare
// sensitive-path / secret-env *mention* — so prose that documents credential
// handling doesn't read as poison when you scan long-form skill text.
// hits: [{ flag, match, start, end }] — the exact matched span behind each flag.

// 2) wrap the tools/call handler — every call is firewalled before it runs
server.setHandler(guardHandler(realHandler, policy, {
  onApprove: async (action, verdict) => askHuman(action, verdict), // fail-closed by default
}));
```

## MCP stdio proxy (drop-in)

Wrap **any** MCP server with the firewall — no code changes to client or server:

```bash
redstamp-mcp --policy redstamp.config.json -- npx -y @modelcontextprotocol/server-filesystem /workspace
```

Point your MCP client (Claude Code, Claude Desktop, …) at `redstamp-mcp` instead of the server directly:

- every `tools/call` is firewalled before it reaches the server;
- **poisoned tools are stripped from `tools/list`** before the client ever sees them;
- **prompt-injection in returned content is neutralized** across every server→client channel that carries it — `tools/call` results, `resources/read` bodies, and `prompts/get` templates — before it reaches the model;
- **cross-call taint is tracked** for the life of the connection, so a split-exfil (secret staged on one call, shipped on a later one — each benign in isolation) is caught as a sequence;
- blocks come back as normal tool errors the model can read.

Flags: `--allow-approve` (downgrade approval-tier to allow) · `--no-strip` (warn instead of strip) · `--no-scan-results` · `--no-taint` · `--audit <file>` (hash-chained log).
