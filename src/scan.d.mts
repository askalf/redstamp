import type { Action } from './types.mjs';

export interface PatternRule {
  re: RegExp;
  why: string;
}

export declare const SECRET_RE: PatternRule[];
export declare const SECRET_ENV_RE: RegExp;
export declare const SENSITIVE_PATH_RE: RegExp;
export declare const METADATA_RE: RegExp;
export declare const PERSISTENCE_PATH_RE: RegExp;
export declare const PIPE_TO_SHELL: string;
export declare const B64_TO_SHELL_RE: RegExp;
export declare const EXFIL_INTENT_RE: RegExp;
export declare const INJECTION_RE: PatternRule[];
export declare const SENSITIVE_PATH_EXFIL_RE: RegExp;
export declare const URL_RE: RegExp;
export declare const OBFUSCATION_RE: PatternRule[];

/** JSON.stringify that survives cycles, BigInt and Symbols. Never throws. */
export declare function safeStringify(v: unknown): string;

/** String coercion that never throws. Arrays join with commas. */
export declare function asStr(v: unknown): string;

/** The host in one spelling: trailing dot dropped, numeric IPv4 forms dotted. */
export declare function canonicalHost(host: string): string;

/** Is this host outside loopback, private ranges and the allowlist? */
export declare function isExternal(host: string | null | undefined, allow?: string[]): boolean;

export declare function ipScope(host: string | null | undefined): 'linklocal' | 'loopback' | 'private' | null;

export interface SecretScan {
  flags: string[];
  hosts: string[];
  hasSecret: boolean;
}

export declare function scanSecrets(action: Action, text?: string): SecretScan;

export interface MatchSpan {
  match: string;
  start: number;
  end: number;
}

export declare function matchOf(re: RegExp, text?: string): MatchSpan | null;
export declare function injectionHitsDetailed(text?: string): Array<MatchSpan & { flag: string }>;
export declare function injectionHits(text?: string): string[];
export declare function scanInjection(action: Action, skillText?: string): string[];
export declare function obfuscationHits(text?: string): string[];
