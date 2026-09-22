# Daemon and native fast hook

## Daemon (optional)

`redstamp-serve` runs a long-lived process that loads the classifier + policy once, streams a hash-chained audit straight to disk, hot-reloads policy on change, and can host the judge tier. It's reachable only with a **capability token** published into a `0600` file — so only your user can talk to it, closing local-process abuse of the judge tier and audit. The Claude Code hook tries the daemon first and **falls back to in-process** if it isn't running (or can't authenticate), so screening always happens — fail-safe, never fail-open.

## Native fast hook

A node hook pays node's startup + module-load on every tool call (~78 ms here). [`native/warden-fast`](../native/README.md) is a tiny compiled client (Go, zero deps, single static binary) that pipes the hook's stdin to the daemon over loopback and prints the verdict back — **4.3× faster, ~60 ms saved per call**, with all logic still in the daemon. Build it, run `redstamp-serve`, point your PreToolUse hook at the binary. If the daemon is unreachable it falls back to the in-process Node hook — slower, but it still screens.
