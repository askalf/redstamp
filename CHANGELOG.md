# Changelog

## [Unreleased]

## [0.7.0] - 2026-07-27

### Security — evasion-hardening pass (adversarial red-team)
A verdict-only white-box sweep (nothing executed) targeting structural seams found
nine command-class bypasses (below) plus four parser/tokenizer differentials
(further down); all fixed, with the benign sibling of each pinned so the fix did
not over-widen. Bench: 286 samples, 97% recall / **100% precision (0/80 FP)**;
ReDoS worst-case 1.9ms.

**Parser/tokenizer differentials — the classifier and the shell disagreeing about
the same bytes (each was invisible: green, not even gray-routed):**
- **A `#` comment runs to end-of-LINE, not end-of-script.** The quoted-data
  neutralizer discarded everything after the first `#`, so a destructive command
  on a *later* line was scrubbed before the rules saw it. It now skips only to the
  newline.
- **Command substitution inside a "prose" flag executes.** `$(…)`/backticks in a
  double-quoted `--body`/`-m` arg run before the arg is passed, but the neutralizer
  blanked them as inert data. Double-quoted args containing `$(`/backtick now stay
  visible; single-quoted stays inert, and a benign `-m "$(date)"` stays clean.
- **Backslash-escaped keywords/targets.** `r\m -rf /` and `rm -rf \/` run as
  `rm -rf /`; the unix rules now also match a backslash-de-escaped copy, while the
  original is still matched so Windows path separators are untouched.
- **Quoted / paren-terminated root target.** `rm -rf "/"`, `rm -rf '/'`,
  `$(rm -rf /)` and `bash -c $'rm -rf /'` only gated before; the root anchor now
  treats a quoted or separator-terminated root the same as a bare one (black).

**Command-class bypasses:**
- **Tool-spoof path never reached the obfuscation judge.** `classify()` runs the
  shell ruleset for a non-shell tool that carries a `command` field (the poisoned-
  server path), but the gray "→ judge" router only fired for `SHELL` tools — so an
  obfuscated command smuggled through a spoofed `read`/`get` tool
  (`X=rm;$X -rf /`, `eval "$UNSAFE"`) got neither a deterministic block nor a judge
  look, defeating the exact defense the tool-spoof classification was paired with.
  The router now fires whenever the shell ruleset ran. It adds only gray-routing,
  never a block — no false-positive surface.
- **Raw block-device destruction beyond `>` / `dd of=`.** `wipefs`, `blkdiscard`
  and `sgdisk --zap-all` of a `/dev/` device are now black, siblings of the
  existing redirect/`dd` rules. Fixed an NVMe-naming blind spot in the process:
  the device charclass (`[a-z]*\d*`) could not match `nvme0n1` (digit-then-letter),
  which also affected the pre-existing redirect-to-device rule — both broadened to
  `[a-z0-9]*`.
- **Privilege escalation.** `chmod +s`/`u+s` (setuid/setgid bit) and `setcap
  cap_setuid`/`sys_admin`/… now gate (red). Symbolic `+s` only, so `chmod +x` and
  numeric modes like `755` stay clean.
- **Kernel-module load/unload.** `insmod`/`rmmod` gate (red) — ring-0 code, a
  rootkit vector; `modprobe` is intentionally excluded as the common legitimate
  path.
- **Bulk copy of a sensitive source to remote storage.** `rclone copy` and
  `aws s3 sync|cp|mv` gate (red) when the source is a known credential/secret path
  or a whole-home tree; a deploy sync of build output
  (`aws s3 sync ./dist s3://…`, or a specific `/home/app/dist` subdir) stays clean.

### Added
- **`guardMcpCallAsync` — the MCP surface can finally reach the LLM judge.**
  `guardMcpCall` is synchronous, and `guardHandler`, though async, called it — so
  no MCP consumer could consult the judge at all, whatever it passed in `opts`.
  A judge handed to `guardHandler` was silently ignored: configured and inert.

  Stitching the two existing entry points together from outside does **not**
  close it. `checkAsync` derives `gray` from its own `decide()` pass, which does
  not include the MCP shell-spoof leaf scan — so a call that is gray *only*
  because a payload is buried under an arbitrary argument key never reaches the
  judge. Measured rather than assumed: across six name/payload pairs where a
  red-tier command hides under an innocuous key on a benignly-named tool
  (`list_items`, `read_file`, `get_status`, …), **6 of 6** were gray via the leaf
  scan and not gray to `checkAsync`. That is precisely the obfuscated-payload
  case the judge exists for, and it was unreachable.

  `guardMcpCallAsync` runs the judge against the **leaf-scanned** verdict.
  `guardHandler` now takes the async path whenever a judge is supplied, and the
  sync path otherwise so judge-less callers are unchanged. Omitting `opts.judge`
  gives behaviour and verdicts identical to `guardMcpCall`.

### Changed
- **The escalate-only judge merge now lives in one place: `applyJudge`.**
  Extracted from `checkAsync` and shared with `guardMcpCallAsync`. A second copy
  is the dangerous kind of duplication here — a drifted one could let a judge
  *lower* a verdict, the one thing it must never do. The invariants (consulted
  only when gray and not already blocked, escalate-only, judge errors keep the
  deterministic verdict) are now pinned by direct tests as well as through both
  callers. `checkAsync` behaviour is unchanged; full suite 266/266.
- **The MCP audit record is written after the judge, not before.** `guardMcpCall`
  recorded inside the classification path, so an escalation applied afterwards
  would have left the audit log disagreeing with the decision actually enforced.
  The deterministic core is split out and both entry points record once, at the
  end — exactly one entry per call, carrying the final verdict.

### Fixed
- **`obfuscated payload to shell` recognised one spelling out of twelve** (#88).
  Both halves of the pattern were too narrow: the decode flag matched only `-d`
  (so `--decode`, `-di` and `-d -i` evaded it) and the shell name matched only
  `sh`/`bash` (so `zsh`, `dash`, `/bin/sh` and `env bash` evaded it) — **7 of 12
  real spellings walked past**. This reached the runtime, not just the poison
  scan: `injectionHits` backs `scanToolResult`, so `guardHandler` forwarded a
  long-form dropper in a tool result to the agent verbatim while neutralising the
  short form. Same class as #41/#45. The live shell firewall was never affected —
  `decide()` returned `black` for every spelling.

  The sibling `decodes then pipes to a shell` obfuscation smell had the identical
  shell-name gap and is fixed with it; both now share `PIPE_TO_SHELL` so they
  cannot drift apart again.

  Detection **widening** is the risk direction that creates false positives, so
  it was measured rather than reasoned about: re-scanning the full official
  plugin directory (**272 plugins / 1850 skills**) before and after produced a
  **zero delta** — no skill changed verdict or flags. `bench/redos.mjs` worst
  case 0.47 ms across 144 patterns; every gap in the new pattern is bounded and
  every character class excludes its own delimiter.

## [0.6.0] - 2026-07-21

### Added
- **Detectors expose the matched span (`hits[]`) for evidence surfacing.** `matchOf()`
  and `injectionHitsDetailed()` return `{ flag, match, start, end }`, and
  `scanMcpTools` attaches a parallel `hits: [{ flag, match }]` to each finding — same
  order and conditions as `flags` — so a finding can be checked against the exact
  source bytes that produced it. Strictly additive: `flags`/`why` output is
  byte-for-byte unchanged.

### Fixed
- **Windows/PowerShell/cmd destructive deletes are now classified.** The shell ruleset
  blacked Unix `rm -rf /`, but its Windows equivalents fell through to the read-only
  `green` default — `Remove-Item -Recurse -Force C:/` (forward slash is valid on
  Windows), `$env:USERPROFILE` targets, the `ri`/`rmdir`/`rd`/`del` aliases with
  truncated `-r`/`-fo` flags, cmd's `rd /s /q` and `del /f /s /q C:\*`, a
  `Get-ChildItem -Recurse` piped into a force-delete, and `reg delete` of a machine
  hive (SYSTEM/SOFTWARE/SAM/SECURITY). All now black, **scoped to a system/drive root**
  so ordinary project cleanup (`Remove-Item -Recurse -Force node_modules`,
  `rd /s /q .\build`) stays benign. Forced shutdown/reboot (`Stop-Computer`,
  `Restart-Computer`, `shutdown /s|/r`) gates as red. Adds a `destructive-win` bench
  family so the gap can't silently reopen.
- **A `Program`-prefixed path is no longer mistaken for a system root.** Both the new
  and the pre-existing Windows drive-root matchers accepted a bare `Program`, so
  `C:\Programming\myrepo\build` and `C:\Programs\tool` matched the system-root branch
  and hard-blocked. Now anchored to `Program Files` (including `(x86)`).
- **Prose flag values are treated as data, not live commands.** A `gh pr create
  --body "…"`, `gh issue --description`, or `gh release --notes` whose text merely
  *documents* a dangerous command was matched as though the command were live.
  `neutralizeQuotedData` now blanks those quoted values exactly as it already did for
  `-m`/`--message`/`--grep`. Deliberately **not** extended to curl's
  `-d`/`--data`/`-F`/`-T`/`--post-file`, which carry the exfil payload the black rules
  must keep seeing; a real command chained after the flag (`… --body x; rm -rf /`)
  still blocks.

### Security
- **The native `warden-fast` hook client no longer fails OPEN against a token-gated
  daemon.** The daemon gates its loopback listener with a per-start capability token
  (published into the `0600` discovery file) and answers an *unauthenticated*
  hook-shaped request with an empty line — which the client relayed as "allow". Since
  a `tcp` daemon always mints that token, `warden-fast` was silently allowing every
  tool call whenever it talked to a real daemon (the in-process node hook was
  unaffected). `warden-fast` now reads the token from the same discovery file it
  already reads the port from and injects it into the forwarded payload; if the
  payload isn't parseable JSON it declines the fast path and falls back to the
  in-process node hook, so it fails **safe**, never open. A tokenless daemon keeps the
  zero-parse byte-pipe path. `native/smoke.mjs` now asserts the token gate is active
  (an unauthenticated request gets an empty line) before checking that the client
  authenticates past it — so a regression can't pass silently.

## [0.5.1] - 2026-07-16

### Security
- **Audit tail-truncation is now detectable.** A hash chain proves no past record
  was edited or deleted from the *middle*, but a valid *prefix* still verifies — so
  deleting the most-recent entries (the ones recording an attacker's own action)
  went unnoticed, and a restart re-seeded from the truncated tail. `ChainedFileAudit`
  can now anchor the chain head in a `0600` `<audit>.chk` checkpoint (`{ checkpoint: true }`,
  which the streaming daemon enables), and `verifyAuditFile(path, { head, count })`
  flags a log that no longer ends where the checkpoint says (`truncated`/`rollback`,
  surfaced by `redstamp verify`). A same-directory attacker who rewrites both is still
  out of reach of a same-fs sidecar; retain the checkpoint on separate-trust storage
  for full protection. SECURITY.md's tamper-evidence scope updated to match.
- **Write-root confinement no longer bypassable by `..` traversal or a shared-prefix
  sibling.** The `writeRoots` gate compared paths with a raw `startsWith`, so
  `src/../../etc/x` (traverses out) and a `data` root admitting `database/…` (shared
  string prefix) both slipped the review gate. Paths are now normalized (`.`/`..`
  collapsed) and matched on a separator boundary.
- **Daemon capability token compared in constant time.** The `!==` check returned
  early on the first differing byte — a timing oracle a local process on the loopback
  listener could walk. Now a fixed-length SHA-256 digest comparison via
  `crypto.timingSafeEqual` (constant-time and length-independent).

## [0.5.0] - 2026-07-11

### Changed
- **`redstamp init` now writes `redstamp.config.json`** (was `warden.config.json`),
  and `redstamp check` / `redstamp-mcp` default to it — completing the config-file
  half of the warden→redstamp rename (the docs already advertised
  `redstamp.config.json`, but the code still defaulted to `warden.config.json`, so
  a user following the README got a gate that loaded no policy). **Fully
  back-compatible:** with no `--policy`, an existing `warden.config.json` is still
  read transparently, so a project set up before the rename keeps working — only a
  fresh `init` writes the branded name. Help text updated and the example is now
  `redstamp.config.example.json`. The `~/.warden/` **global** config, the audit
  log, and the `WARDEN_*` env vars are intentionally unchanged.

## 0.4.1

- **Renamed: `@askalf/warden` → `@askalf/redstamp`** (npm-publishable name; the old name collides with an existing unscoped package and is create-blocked by the registry). GitHub repo becomes `askalf/redstamp` (old URLs redirect). Legacy `warden`/`warden-mcp`/`warden-hook`/`warden-serve` bin aliases retained alongside the new `redstamp*` bins. `WARDEN_*` env vars unchanged.

All notable changes to **@askalf/redstamp** (formerly `@askalf/warden`) are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [0.4.0] - 2026-07-09

### Added
- **Cross-call taint tracking — `TaintSession`** (`@askalf/warden/taint`, #34).
  `check()` classifies one call in isolation, which an attacker evades by
  splitting an exfil across calls: read a secret into a temp file (call 1 — a
  sensitive *read*), then ship that file out (call 2 — *benign*, no visible
  secret). `TaintSession` remembers the session: secret **sources** (reads of
  `~/.ssh`, `.env`, `.aws/credentials`, …), **propagation** (the file a secret
  is written to — and any copy — becomes tainted), and external **sinks**,
  escalating to black the moment tainted data leaves the machine.
  `checkSequence(actions, policy)` runs a whole stream through one session.
  Deterministic and offline; like the judge it can only **raise** risk, never
  lower a verdict — wrapping a stream is always at least as safe as per-call
  `check()`. Precision-scoped: config-read → **allowlisted** host is not
  flagged. The stateless core is untouched (byte-identical `decide()`).
- **External MITRE ATT&CK arena corpus** (#36) — the default arena corpus is
  warden-authored, so warden topping it proves capability, not neutrality.
  `arena/external-corpus.json` adds 68 samples across 32 MITRE ATT&CK
  techniques, command forms drawn from the public GTFOBins / LOLBAS /
  HackTricks knowledge bases, with benign uses of the *same* tools so precision
  is a genuine test. `node arena/run.mjs --corpus <file>` / `npm run
  arena:external`; results in `arena/EXTERNAL-CORPUS-RESULTS.md` (warden: 100%
  recall, 100% precision after the #33 coverage work — the corpus originally
  cross-flagged the same two gaps #33 closed). Honest caveat documented:
  externally taxonomized but still assembled in-repo; true neutrality needs an
  outside-contributed corpus, and the protocol makes that a drop-in.
- **Six measured classifier coverage gaps closed** (#33), each mechanism-scoped
  and checked against the benign set: recursive `chmod` of the root/system tree
  (any mode — `000` locks root out, not just `777`); staged
  download→make-executable chained with `;` as well as `&&`; `rundll32
  javascript:` protocol exec (LOLBin) → black; gnupg keyring
  (`.gnupg/secring.gpg`) in `SENSITIVE_PATH_RE`; `/etc/shadow` reads gated
  (distinct from world-readable `/etc/passwd`, which stays allow); `vssadmin
  create shadow` gated (dual-use NTDS-theft prep — the ransomware
  delete-shadows variant stays black). Corpus +11 → 245 samples; recall
  96% → **97%**, precision held at **100%**.

### Changed
- Default judge model freshened to `claude-sonnet-5` (#35).
- README: quick-start notes that **npm v12 blocks git dependencies by
  default** — until warden is on npm, `npm i github:askalf/warden` needs
  `--allow-git` on npm ≥ 12.

### Fixed
- **Judge tier fail-safe + raise-only proof** (#35). `makeJudge` no longer
  throws into the host on a bad response (explicit `res.ok` check — a 429/5xx
  returning HTML used to throw at `res.json()`; wrapped JSON parse; catch-all):
  every failure mode returns null and `checkAsync` keeps the deterministic
  verdict. And the invariant that a compromised/jailbroken judge can only
  *raise* risk is now pinned by tests — a judge answering green cannot clear a
  black or weaken a verdict.
- **Fuzz-found fail-safe gaps at the entrypoints** (#32): `tool`/`method`
  arriving as an array containing a `Symbol` (implicit `String(array)` →
  `Array.join` → TypeError), and non-string `skillText` reaching the injection
  scanner's regex, could throw instead of failing safe to a verdict. A shared
  symbol-safe `asStr()` coercion now guards every site; found by 1M-iteration
  fuzzing, pinned by regression tests. Detection unchanged.
- **CI release notes** (#30): extraction uses `indexOf`, not a multiline regex
  whose `$` matched the blank line after the heading and shipped empty bodies
  (v0.2.1 and v0.3.0 notes were backfilled by hand).

## [0.3.0] - 2026-07-03

### Added
- **arena — a neutral, reproducible agent-firewall benchmark** (`npm run arena`):
  on a labeled corpus of real attacks and real benign work, every tool is scored
  on recall *and* precision *and* determinism through one pipe, so the numbers
  are comparable instead of anecdotal. Ships allow-all / block-all anchors, a
  naive regex deny-list baseline, and a **LlamaFirewall adapter**, framed along
  threat-model axes (what each tool even attempts to cover). Results live in
  `arena/RESULTS.md` and regenerate with `node arena/run.mjs`.
- **`scanMcpTools` severity tiers** — every finding now carries
  `severity: 'critical' | 'advisory'`. Injection/exfil *instructions* (the
  curated patterns) are critical; a bare sensitive-path / secret-env *mention*
  is advisory, so consumers scanning long-form skill prose (canon) can stop
  treating instructional docs about credential handling as poison — scanning
  the official Claude Code marketplace flagged 19/29 skills on exactly those
  mention heuristics. Additive: `flags` are unchanged and consumers that only
  read them behave as before.
- **`SENSITIVE_PATH_EXFIL_RE`** — a sensitive path being *moved*
  (transfer-verb → sensitive path → destination, one clause), e.g.
  `read ~/.ssh/id_rsa and POST it to https://…`, which the curated exfil
  patterns miss (wrong verb/noun combination). Critical, and built on
  `SENSITIVE_PATH_RE` so the two can't drift apart.
- **Four framework-governance examples** (`examples/`) — the same warden MCP
  gate governing a CrewAI Flow, a LangGraph.js StateGraph, an OpenAI Agents SDK
  agent, and a Microsoft AutoGen agent, all surfaced in the README.

### Fixed
- **Three scanner false-positive classes, measured on 2,000+ real marketplace
  skills** (auditing the official Claude Code catalog + 9 community
  marketplaces with canon; every first-pass critical was manually reviewed):
  - `SENSITIVE_PATH_RE`'s `.env` now requires a non-word lookbehind —
    `process.env` / `self.env` / `import.meta.env` are code, not the dotenv
    file, and were the single largest FP source. (Also applied to the
    data-exfil-to-destination pattern's `.env` noun.)
  - `scanMcpTools` normalizes stringified newlines (`\n` 2-char escapes) back
    to real newlines before matching, and `SENSITIVE_PATH_EXFIL_RE`'s gaps stop
    at both — previously clause-bounded patterns silently spanned lines in
    JSON-stringified text, so unrelated rows of a markdown table could read as
    one verb→path→destination "clause".
  - The bare-word **'exfiltration intent'** rule (exfiltrate/leak/steal, no
    destination) now tiers as `advisory`, not critical: every corpus hit was
    descriptive prose — memory leaks, ML data leakage, threat lists in
    defensive security docs. The flag itself is unchanged, so strict
    (tool-description) surfaces still act on it.
- **Three classifier false-positive classes:**
  - single-label hostnames (Docker service names like `db` or `redis`) are
    treated as internal, so container-to-container traffic no longer reads as
    an exfil destination;
  - the `curl | interpreter` RCE rule fires only on an *external* target —
    piping from localhost/internal services no longer flags;
  - the DNS-exfil rule is anchored to command position, so prose that merely
    mentions `host`/`dig` no longer flags.
- **Docs matched to shipped behavior** — the native hook (`warden-fast`) is
  fail-safe, not fail-open (daemon unreachable → it execs the in-process Node
  hook, which still screens), and the daemon command is `warden-serve`, not
  `warden serve`.
- **Audit verifier — interspersed unprotected records no longer read as tampering.**
  `verifyAuditFile()` skipped only *leading* pre-chain lines; the first line
  lacking a `prev`/`hash` mid-file was treated as a chain break, so any file that
  a second, non-chained writer had appended to (e.g. an in-process hook fallback
  logging raw tool calls into the shared `~/.warden/audit.jsonl`) reported
  `ok:false` even when the hash chain was fully intact — and an attacker could
  defeat verification outright by appending one junk line. Now any line without a
  string `prev`+`hash` is treated as unprotected history: skipped and tallied as
  `unchained`, while the chained records are verified continuously. Tamper
  detection is unchanged — editing a chained record breaks its hash, deleting one
  breaks the next record's link, and stripping a record's `prev`/`hash` to
  disguise an edit breaks the following record's link. Pinned by three regression
  tests (interspersed foreign record, junk-tail append, strip-to-disguise).

## [0.2.1] - 2026-06-27

### Fixed
- **Secret scanner — GitHub App / Actions tokens.** `scanSecrets` recognized
  `ghp_` / `gho_` / `github_pat_` but missed the GitHub App token family:
  `ghs_` (server-to-server — the `GITHUB_TOKEN` minted into **every** GitHub
  Actions run and the output of `actions/create-github-app-token`), `ghu_`
  (user-to-server), and `ghr_` (refresh). An agent exfiltrating a `ghs_` token
  to an external host therefore slipped the secret-exfil gate. This is the
  credential class stolen in the tj-actions/changed-files supply-chain attack
  (CVE-2025-30066). Now matched (`gh[sur]_[A-Za-z0-9]{30,}`) and blocked on
  egress; pinned by a regression test.

## [0.2.0] - 2026-06-15

First public release — own your agent security.

### Added
- **Deterministic risk classification** — `check()` / `decide()` sort any agent
  action into one of four tiers (green / yellow / red / black) from a fixed,
  offline rule set. No model call in the hot path, so the verdict is the same
  every run.
- **Policy** — `loadPolicy()` reads `~/.warden/config.json`; allow / approve /
  block decisions are policy-driven and overridable per tier.
- **Threat coverage** — secret-exfiltration and prompt-injection detection,
  catastrophic-filesystem and credential-theft patterns, with ReDoS-hardened
  matchers (bounded quantifiers; benchmarked under `npm run bench:redos`).
- **Tamper-evident audit** (`@askalf/warden/audit`) — every decision is
  hash-chained to disk; `verifyAuditFile()` detects any edit or deletion of a
  past entry.
- **MCP middleware** (`@askalf/warden/mcp`, `warden-mcp`) — wrap an MCP server
  to firewall tool calls, strip poisoned tools from `tools/list`, and neutralize
  prompt-injection returned in tool *results* (indirect injection). Tool/arg
  mapping is exfil-aware: a URL-bearing call is risk-checked as a fetch even when
  the tool is named like a reader, so SSRF / cloud-metadata access can't be
  hidden behind a benign name. The stdio proxy bounds its line buffer against a
  hostile peer (`npm run bench:mcp` red-teams all of this).
- **Claude Code hook** (`warden-hook`) — drop-in pre-tool-use guard.
- **Daemon + native fast client** (`warden-serve`, `@askalf/warden/client`) —
  a local decision server with a low-latency client for hot paths.
- **Optional LLM judge tier** (`@askalf/warden/judge`) — escalates only genuine
  gray-zone actions; the deterministic core decides everything else.
- **Fail-safe contract** — every entrypoint returns a verdict, never throws into
  the host: a null/non-object action, a non-string `tool`/`method`, a circular
  input, or a Symbol buried in a command/path/url array all classify safely
  instead of raising. The scanned text is bounded (64KB) so a giant input field
  can't turn a call into a heavy scan. Fuzzed at 2M malformed inputs with zero
  throws / zero invalid verdicts (`npm run bench:max`), worst-case regex timing
  under 50ms at 300KB, ~60k verdicts/sec (p99 ~60µs).

[0.2.0]: https://github.com/askalf/warden/releases/tag/v0.2.0
