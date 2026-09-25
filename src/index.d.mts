import type { Action, AuditSink, Classification, Judge, NormalizedPolicy, Policy, Verdict } from './types.mjs';
import { AuditLog } from './audit.mjs';

export type * from './types.mjs';
export { AuditLog };

export declare const TIER: { readonly GREEN: 'green'; readonly YELLOW: 'yellow'; readonly RED: 'red'; readonly BLACK: 'black' };

/** Classify an action's risk tier from its tool and input alone (no policy). */
export declare function classify(action: Action): Classification;

/** Load a policy file. Never throws: a missing or malformed file yields the default policy. */
export declare function loadPolicy(path: string): NormalizedPolicy;

/** Does `rule` (e.g. `shell(npm run test:*)`, `write(src/*)`) match this action? */
export declare function matchRule(rule: string, action: Action): boolean;

/** Resolve the project config path: an explicit path, else `redstamp.config.json`, else a legacy `warden.config.json`. */
export declare function resolveConfig(explicit?: string | null, dir?: string): string;

/** Deterministic verdict for an action. No I/O, no LLM: pure and offline. */
export declare function decide(action: Action, policy?: Policy, skillText?: string): Verdict;

/** Append a verdict to an audit sink. A null sink is a no-op. */
export declare function recordVerdict(audit: AuditSink | null | undefined, action: Action, v: Verdict): unknown;

export interface CheckOptions {
  audit?: AuditSink | null;
  /** Skill or tool-description text to scan for poisoning alongside the call. */
  skillText?: string;
}

/** Synchronous deterministic check, optionally recorded to an audit sink. */
export declare function check(action: Action, policy?: Policy, opts?: CheckOptions): Verdict;

export interface CheckAsyncOptions extends CheckOptions {
  judge?: Judge | null;
}

/** Like `check`, but consults an optional judge for gray-zone verdicts. The judge can only escalate. */
export declare function checkAsync(action: Action, policy?: Policy, opts?: CheckAsyncOptions): Promise<Verdict>;

/** Apply a judge to a verdict in place (escalate-only). Returns the same verdict object. */
export declare function applyJudge(action: Action, v: Verdict, judge: Judge | null | undefined): Promise<Verdict>;

