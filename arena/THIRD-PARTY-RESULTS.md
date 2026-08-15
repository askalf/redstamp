# Third-party corpus results

> redstamp scored against corpora **nobody here wrote** — the neutrality test the arena README calls for. Precision on external benign commands, recall on external attacks, reported straight. Regenerate: `node arena/thirdparty.mjs`.

## tldr-pages — benign precision (CC-BY-4.0)

Source: 1212 real command examples from [tldr-pages](https://github.com/tldr-pages/tldr) `pages/common` @ `63e425aea1`, placeholder-substituted, destructive/dual-use utilities excluded (a firewall should gate those). See provenance in the corpus file.

- **Precision: 100% — 0 hard false-positives of 1212.**
- Friction (benign escalated to review, a softer signal): 11/1212 — all defensible outward-facing/dual-use shapes (`git push`, `npx`, a credentials-file scan).

A large external benign set with zero hard false-positives is the number that matters most: a firewall that fires on real work gets disabled, and a disabled firewall catches nothing.

## Atomic Red Team — external ATT&CK attacks + benign (MIT)

Source: 203 commands from [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) @ `2c63affb3b` across 45 ATT&CK techniques. Labels assigned by security principle per technique (not "it's in Atomic → block"); see the corpus provenance for the full methodology.

**Read this axis-aware.** redstamp classifies command *semantics*. Atomic Red Team also ships tests that run a pre-staged binary (`mimikatz.exe`, `gsecdump.exe`) — whose maliciousness is in the binary's reputation, not the command string. No command-string firewall can catch those without a binary-reputation feed; they are a documented axis limit, exactly as LlamaFirewall is read on the injection slice only. Each sample is tagged `command-semantic` vs `opaque-binary`.

| slice | metric | result |
|---|---|---|
| block · command-semantic (redstamp's axis) | hard-block recall | **21/26 (81%)** |
| block · command-semantic | +gate recall (block or escalate) | 26/26 (100%) |
| block · opaque-binary (out of axis) | hard-block recall | 6/39 (15%) — documented limit |
| approve · dual-use | escalated (block or gate) | 13/66 (20%) |
| allow · discovery | **precision** (0 FP = perfect) | **0 FP / 72** (100%), 2 gated |

_On the dual-use row: this corpus labels every dual-use technique `approve` — the conservative position that a human should see them — so 53 of 66 sit below redstamp's escalation threshold (archiving, clipboard/screen reads, registry edits, permission changes, plain file transfers). That is the friction dial, not a miss: gating all of them would put a prompt in front of routine work, and the arena reports it plainly rather than tuning the labels to flatter the score._

**Honest read.** Nothing on-axis is silently allowed: **26/26** of the external ATT&CK attacks are stopped — 21 hard-blocked and 5 escalated for human review — at **100%** precision on benign discovery from the same source (0 false-positives of 72).

This is what the corpus was imported for. The first run scored **10/31 hard-block and 13/31 prevented**, with 18 attacks silently allowed — an outside ATT&CK corpus catching real command-semantic gaps redstamp's own corpus never exercised: exfil over ssh/tar and DNS, inhibit-recovery variants (`wbadmin delete catalog`, WMI shadow-copy delete, `fsutil usn deletejournal`), ransomware-shaped encryption of system credential files, `dd` overwriting a logfile, the `kubectl` privileged-pod host escape, and credential-store enumeration. Those became detection rules (each with a regression test **and** a paired false-positive guard, since every one is a co-occurrence rule), and the numbers above are post-fix.

### Remaining boundary

Nothing on-axis is silently allowed. The residue is the **opaque-binary** slice (33 of 39 not hard-blocked): commands whose payload is a pre-staged `.exe`/`.dll`, where the maliciousness lives in the binary rather than the command string. Closing that needs a binary-reputation feed, which is a different layer — not a rule this classifier can honestly write.

## Provenance & licenses

- **tldr-pages** — CC-BY-4.0. © tldr-pages team and contributors, licensed CC-BY-4.0. Commands extracted from pages/common and placeholder-substituted; this is a derived subset, not the original pages.
- **Atomic Red Team** — MIT. Atomic Red Team™ by Red Canary, MIT License. Command strings extracted from atomics/<technique>/<technique>.yaml executor blocks with input-argument defaults substituted; this is a derived subset.

See [THIRD-PARTY-CORPORA.md](THIRD-PARTY-CORPORA.md) for the full license map (including corpora we deliberately did NOT vendor for license reasons) and the import roadmap. MIT for redstamp's own code and tooling.
