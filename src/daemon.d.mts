import type { Server, AddressInfo } from 'node:net';
import type { Judge } from './types.mjs';

export interface DaemonOptions {
  socketPath?: string;
  /** Policy file, hot-reloaded on change. */
  configPath?: string | null;
  /** Hash-chained JSONL audit file, checkpointed against truncation. */
  auditPath?: string | null;
  judge?: Judge | null;
  /** Also listen on loopback TCP for the native fast hook. */
  tcp?: boolean;
  tcpPort?: number;
  infoFile?: string;
  onLog?: (msg: string) => void;
  /** Track cross-call taint per connection. Default true. */
  taint?: boolean;
}

export interface DaemonHandle {
  server: Server;
  tcp: Server | null;
  address(): AddressInfo | string | null;
  close(cb?: () => void): void;
}

/** Start the shared classifier daemon. */
export declare function startDaemon(opts?: DaemonOptions): DaemonHandle;
