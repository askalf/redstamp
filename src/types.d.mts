// Shared type definitions for redstamp's public API. Hand-written to mirror the
// runtime shapes in the .mjs sources; `test/types.test.mjs` keeps the export
// lists in sync.

/** Risk tier, lowest to highest. */
export type Tier = 'green' | 'yellow' | 'red' | 'black';

/** What the caller should do: run it, ask a human, or refuse. */
export type Decision = 'allow' | 'approve' | 'block';

/** A tool call in redstamp's normalized shape. `tool` is matched case-insensitively. */
export interface Action {
  tool: string;
  input?: Record<string, unknown>;
}

/** Allow/deny rules use Claude-Code-style `tool(glob)` syntax, e.g. `shell(npm run test:*)`. */
export interface Policy {
  allow?: string[];
  deny?: string[];
  /** Hosts (and their subdomains) a network tool may reach without a gate. */
  egressAllow?: string[];
  /** Write-path confinement; `null` or absent means unconfined. */
  writeRoots?: string[] | null;
  [key: string]: unknown;
}

/** A policy after `normalizePolicy`: every list is an array. */
export interface NormalizedPolicy extends Policy {
  allow: string[];
  deny: string[];
  egressAllow: string[];
  writeRoots: string[] | null;
}

export interface Verdict {
  tool: string | undefined;
  tier: Tier;
  decision: Decision;
  /** Human-readable reasons, in the order they fired. */
  why: string[];
  /** External hosts this call reaches, after the egress allowlist. */
  externalHosts: string[];
  /** True when the verdict is gray-zone and an optional judge may be consulted. */
  gray: boolean;
  /** Set by TaintSession when a cross-call flow raised the verdict. */
  crossCall?: boolean;
}

export interface Classification {
  tier: Tier;
  why: string[];
}

/** A judge's answer. Can only raise the tier; `null` means no opinion. */
export interface JudgeResult {
  tier: Tier;
  reason?: string;
}

export type Judge = (action: Action, verdict: Verdict) => Promise<JudgeResult | null | undefined>;

/** Anything with a `record()` method can receive verdicts: AuditLog, ChainedFileAudit, or your own sink. */
export interface AuditSink {
  record(rec: Record<string, unknown>): unknown;
}

export interface AuditEntry extends Record<string, unknown> {
  prev: string;
  hash: string;
}
