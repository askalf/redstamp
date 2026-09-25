import type { Action, AuditSink, Judge, Policy, Verdict } from './types.mjs';

/** Thrown by `guardExecutor` when a call is blocked, or held for approval and not granted. */
export declare class WardenBlocked extends Error {
  constructor(action: Action, verdict: Verdict, held?: boolean);
  name: 'WardenBlocked';
  action: Action;
  verdict: Verdict;
  tier: Verdict['tier'];
  heldForApproval: boolean;
}

export interface GuardExecutorOptions<Args extends unknown[], R> {
  /** Turn the executor's arguments into an action. Defaults to treating the first argument as the action. */
  toAction?: (...args: Args) => Action;
  policy?: Policy;
  audit?: AuditSink | null;
  judge?: Judge | null;
  /** Resolve truthy to allow a red-tier call. Without it, red calls throw (fail-closed). */
  onApprove?: ((action: Action, verdict: Verdict) => boolean | Promise<boolean>) | null;
  /** Return a value instead of throwing when a call is refused. */
  onBlock?: ((action: Action, verdict: Verdict) => R) | null;
}

/** Wrap an executor so every call is firewalled first. */
export declare function guardExecutor<Args extends unknown[], R>(
  execFn: (...args: Args) => R | Promise<R>,
  opts?: GuardExecutorOptions<Args, R>,
): (...args: Args) => Promise<R>;

/** Firewall an Anthropic-SDK `tool_use` block (`{ name, input }`). Returns the verdict. */
export declare function guardToolUse(
  toolUse: { name: string; input?: Record<string, unknown> },
  policy?: Policy,
  opts?: { nameMap?: Record<string, string>; audit?: AuditSink | null },
): Verdict;
