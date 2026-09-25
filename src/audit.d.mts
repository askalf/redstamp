import type { AuditEntry, AuditSink } from './types.mjs';

/** The `prev` hash of the first entry in every chain: 64 zeros. */
export declare const GENESIS: string;

/** SHA-256 of `prev + JSON.stringify(rec)`, hex-encoded. */
export declare function hashOf(prev: string, rec: Record<string, unknown>): string;

/** In-memory, hash-chained audit log. */
export declare class AuditLog implements AuditSink {
  constructor();
  entries: AuditEntry[];
  prev: string;
  record(rec: Record<string, unknown>): AuditEntry;
  /** True iff no entry has been altered, inserted or removed. */
  verify(): boolean;
  /** Append all entries to a JSONL file. */
  flush(path: string): void;
}

/** The last chained hash in an audit file, or GENESIS if there is none. */
export declare function lastHashOf(path: string): string;

export interface ChainState {
  head: string;
  count: number;
}

export declare function writeCheckpoint(path: string, state: ChainState): void;
export declare function readCheckpoint(path: string): ChainState | null;
export declare function chainStateOf(path: string): ChainState;

/** Streaming audit: each record is chained and appended to disk immediately. */
export declare class ChainedFileAudit implements AuditSink {
  constructor(path: string, opts?: { checkpoint?: boolean });
  path: string;
  checkpoint: boolean;
  count: number;
  readonly head: string;
  record(rec: Record<string, unknown>): AuditEntry;
}

export type VerifyResult =
  | { ok: true; entries: number; unchained?: number }
  | { ok: false; at: number; reason?: 'truncated' | 'rollback' };

/** Verify a JSONL audit file's chain, and its checkpoint when one exists. */
export declare function verifyAuditFile(path: string, expected?: ChainState | null): VerifyResult;
