import type { Action, AuditSink, Judge, Policy, Verdict } from './types.mjs';

/** An MCP `tools/call` request, either the full JSON-RPC shape or just `{ name, arguments }`. */
export interface McpCallRequest {
  params?: { name?: string; arguments?: Record<string, unknown> };
  name?: string;
  arguments?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface McpGuardOptions {
  /** Map specific MCP tool names to redstamp tools, e.g. `{ run_query: 'read' }`. */
  nameMap?: Record<string, string>;
  skillText?: string;
  audit?: AuditSink | null;
  judge?: Judge | null;
}

export interface McpGuardResult {
  verdict: Verdict;
  action: Action;
}

/** Map an MCP tool name and arguments to a redstamp action. */
export declare function mapMcpToAction(name: unknown, args?: Record<string, unknown>, nameMap?: Record<string, string>): Action;

/** Firewall one MCP `tools/call` request. */
export declare function guardMcpCall(req: McpCallRequest, policy?: Policy, opts?: McpGuardOptions): McpGuardResult;

/** `guardMcpCall` plus the optional escalate-only judge. */
export declare function guardMcpCallAsync(req: McpCallRequest, policy?: Policy, opts?: McpGuardOptions): Promise<McpGuardResult>;

/** Scan a tool result for indirect prompt injection. Returns the flags found; empty means clean. */
export declare function scanToolResult(result: unknown): string[];

export interface McpErrorResult {
  isError: true;
  content: Array<{ type: 'text'; text: string }>;
}

export interface GuardHandlerOptions extends McpGuardOptions {
  /** Resolve truthy to allow a red-tier call. Defaults to deny (fail-closed). */
  onApprove?: (action: Action, verdict: Verdict) => boolean | Promise<boolean>;
  /** Neutralize results that carry prompt injection. Default true. */
  scanResults?: boolean;
}

/** Wrap an MCP `tools/call` handler so every call is firewalled and every result scanned. */
export declare function guardHandler<Req extends McpCallRequest, Res>(
  handler: (req: Req) => Res | Promise<Res>,
  policy?: Policy,
  opts?: GuardHandlerOptions,
): (req: Req) => Promise<Res | McpErrorResult>;

/** The exact text `scanMcpTools` scans for a tool. Hit offsets index into this string. */
export declare function scanTextOf(tool: unknown): string;

/** Blank a tool's name value to same-length spaces so intent patterns can't match inside it. */
export declare function blankNameValue(text: string, tool: unknown): string;

export interface ToolFindingHit {
  flag: string;
  match: string;
  start: number;
  end: number;
}

export interface ToolFinding {
  tool: string | undefined;
  flags: string[];
  severity: 'critical' | 'advisory';
  hits: ToolFindingHit[];
}

/** Scan an MCP server's advertised tools for poisoning. Returns one finding per suspicious tool. */
export declare function scanMcpTools(tools?: unknown[]): ToolFinding[];
