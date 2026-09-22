# Why deterministic

Autonomous agents are a machine for turning your bank balance — and your blast radius — into tool calls. OpenClaw became 2026's first big AI security disaster: a one-click RCE ([CVE-2026-25253](https://nvd.nist.gov/vuln/detail/CVE-2026-25253), CVSS 8.8 — a `gatewayUrl` query parameter auto-opened a WebSocket and leaked the auth token), a poisoned skills marketplace (the **ClawHavoc** campaign: 341 malicious skills, mostly credential stealers), and [135,000+ instances exposed across 82 countries](https://securityscorecard.com/) with no auth. **redstamp is the layer built to stop that class of failure.**

redstamp isn't an AI — it's a firewall that *guards* AIs. That's deliberate:

- A **probabilistic** (LLM-based) guard can be prompt-injected by the very content it's screening, never answers the same way twice, and can't be regression-tested.
- A **deterministic** guard is reproducible, auditable, and testable: same call, same verdict, offline, in microseconds.

There *is* an optional [LLM judge](taint-and-judge.md#optional-llm-judge) for gray-zone calls — the only probabilistic part — and it is structurally constrained: it can **raise** risk, never clear a block.

Every stage is deterministic and offline except the judge path — which is opt-in, consulted only for calls that *smell* evasive, and structurally unable to lower a verdict. With no judge configured, gray-smelling calls keep their deterministic verdict (no false blocks); with one, they get deobfuscated and blocked.

## How the scoreboard is measured

Behind the arena: **the full test suite, all passing in CI**, three adversarial batteries (`bench/edgecases.mjs`, `bench/stress.mjs`, `bench/stress2.mjs`), a seeded fuzzer, and a ReDoS guard (`bench/redos.mjs` — every pattern × adversarial inputs at a 16 KB cap, all inside a hard latency budget). Obfuscated payloads — `X=rm; $X`, `${IFS}` padding, brace expansion, hex/base64-encoded commands — are **resolved deterministically**, not guessed at. Run it yourself: `npm run bench`, `npm run arena`.

```bash
npm run demo    # feeds it OpenClaw-class attacks + benign ops
npm test        # node --test
npm run bench   # the 298-sample corpus, per-family scores
npm run arena   # score redstamp against the rival adapters
```
