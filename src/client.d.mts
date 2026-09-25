import type { Action, Verdict } from './types.mjs';

/** The daemon's socket path: `$WARDEN_SOCKET`, else a named pipe on Windows or a temp-dir socket elsewhere. */
export declare function wardenSocket(): string;

/** The 0600 discovery file the daemon writes: `$WARDEN_INFO`, else `~/.warden/daemon.json`. */
export declare function wardenInfoFile(): string;

/** The daemon's capability token from the discovery file, if readable. */
export declare function wardenToken(): string | undefined;

export interface DaemonPayload {
  action?: Action;
  skillText?: string;
  token?: string;
  [key: string]: unknown;
}

/** Ask a running daemon for a verdict. Resolves null on any failure so the caller can fall back to an in-process check. */
export declare function daemonCheck(
  payload: DaemonPayload,
  opts?: { socketPath?: string; timeoutMs?: number },
): Promise<Verdict | Record<string, unknown> | null>;
