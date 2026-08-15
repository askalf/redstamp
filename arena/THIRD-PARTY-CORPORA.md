# Third-party corpora — provenance, licenses, and roadmap

The arena's default corpus (`corpus.json`) is redstamp-authored, so redstamp
topping it "proves capability, not neutrality" (the arena README says so). This
directory adds corpora **nobody here wrote**, so the numbers can't be graded
homework. Each is fetched from its upstream source by a committed builder and
vendored as a normalized `arena/*.json` with full attribution.

Scored by `node arena/thirdparty.mjs` → [THIRD-PARTY-RESULTS.md](THIRD-PARTY-RESULTS.md).

## Vendored corpora (live)

| corpus | source | license | role | builder |
|---|---|---|---|---|
| `thirdparty-tldr.json` | [tldr-pages](https://github.com/tldr-pages/tldr) `pages/common` | **CC-BY-4.0** | benign **precision** — real developer commands | `arena/build-thirdparty-tldr.mjs` |
| `thirdparty-atomic.json` | [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | **MIT** | external **ATT&CK attacks** + benign discovery | `arena/build-thirdparty-atomic.mjs` |

### Attribution (required by license — do not remove)

- **tldr-pages** — © tldr-pages team and contributors, licensed **CC-BY-4.0**.
  Commands were extracted from `pages/common/*.md` and their `{{placeholder}}`
  tokens substituted; this is a derived, normalized subset, not the original
  pages. License: <https://creativecommons.org/licenses/by/4.0/>.
- **Atomic Red Team™** by Red Canary, **MIT License**. Command strings were
  extracted from `atomics/<technique>/<technique>.yaml` executor blocks with
  input-argument defaults substituted; a derived subset.

The combined corpus set is therefore a **mix of licenses** — redstamp's own code
and tooling are MIT, tldr content is CC-BY-4.0, Atomic content is MIT. This file
is the attribution manifest; keep it in sync with any new import.

## Methodology notes that keep this honest

- **Labels by security principle, not by source.** Atomic Red Team spans every
  ATT&CK tactic including Discovery (`whoami`, `systeminfo`). Labeling every
  atomic `block` would manufacture fake misses. Each technique is mapped to what
  a correct firewall *should* do — block (execution/impact/exfil/persistence/
  credential/evasion/C2), approve (dual-use), or allow (discovery) — in
  `build-thirdparty-atomic.mjs`. The `allow` (discovery) set is a genuine
  precision test drawn from the same source as the attacks.
- **Axis-aware reading.** redstamp classifies command *semantics*. Atomic tests
  that run a pre-staged binary (`mimikatz.exe`) are tagged `opaque-binary` and
  read as a documented axis limit, not a miss — the same way the arena reads
  LlamaFirewall on the injection slice only.
- **Benign sets are filtered, not padded.** tldr's destructive/dual-use
  utilities (`dd`, `mkfs`, `rm`, `curl`, `ssh`…) are excluded because a correct
  firewall should gate those; and Atomic commands in allow/approve techniques
  that are actually RCE download-cradles are dropped. Both exclusions are logged
  in the corpus provenance so nothing is quietly cherry-picked.

## What this surfaced (the point of an external corpus)

The Atomic Red Team import found **redstamp missing real, on-axis command-
semantic attacks** its own corpus never exercised — see the gap list in
[THIRD-PARTY-RESULTS.md](THIRD-PARTY-RESULTS.md). Themes: exfil over ssh/tar and
DNS, inhibit-recovery variants (`fsutil usn deletejournal`, `wbadmin delete
catalog`, WMI shadow-copy delete), ransomware-shaped encryption of system files,
`dd` overwrite of a logfile, `kubectl` privileged-pod escape, credential-store
enumeration. These are concrete detection work; closing them raises real-world
recall and a future Atomic Red Team score. Meanwhile precision held (0 hard
false-positives on 1,212 tldr commands and 71 Atomic discovery commands).

## Roadmap — next imports (researched, license-verified)

| corpus | license | axis fit | status |
|---|---|---|---|
| **AgentHarm** (UK AISI / Gray Swan) | MIT + safety-use clause | agent **tool-calls**, harmful+benign splits | queued — carries a use-restriction clause; record it in NOTICE |
| **AgentDojo** (ETH Zürich) | MIT | tool-call + injection tasks | queued — cleanest MIT tool-call complement |
| **InjecAgent** | MIT | indirect injection in tool results | queued — injection slice |
| **CyberSecEval** interpreter/PI (Meta PurpleLlama) | MIT (per repo README component table) | prompts-to-generate-code — mostly OFF a tool-call firewall's axis | low priority for this axis |

### Deliberately NOT vendored (license-incompatible with MIT)

- **NL2Bash** (`TellinaTool/nl2bash`) — **GPL-3.0**. Would have been an ideal
  ~9k benign-command precision set, but GPL copyleft is incompatible with keeping
  this corpus MIT-clean. tldr-pages (CC-BY) is used for the benign axis instead.
- **GTFOBins**, **LOLBAS** — both **GPL-3.0**. Not vendored for the same reason;
  their techniques are already represented in the MIT external ATT&CK corpus.

## Big-name competitor rows (separate track — operator-gated)

Actually running **Meta LlamaFirewall** (needs a gated Meta HF model) and
**Lakera Guard** (paid key) in the arena is the literal "on par with major
products" comparison. Those need operator credentials/budget and are tracked
outside this file; the adapters/roadmap live in `arena/adapters.json`.
