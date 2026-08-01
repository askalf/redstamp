# Arena results

Corpus: **291 samples** · 25 families · 165 malicious / 44 risky / 82 benign.

Scored 7 firewall(s) through the same stdin/stdout pipe (see [protocol.md](protocol.md)). Regenerate: `node arena/run.mjs`.

| firewall | offline | deterministic | recall (block) | recall (+gate) | precision | under-gate | median µs |
|---|---|---|---|---|---|---|---|
| warden | yes | yes | 100.0% | 100.0% | **100%** | 1/44 | 84 |
| regex deny-list (baseline) | yes | yes | 17.6% | 17.6% | 96.3% | 44/44 | 1 |
| allow-all (null) | yes | yes | 0.0% | 0.0% | **100%** | 44/44 | 0 |
| block-all (paranoid) | yes | yes | 100.0% | 100.0% | 0.0% | 0/44 | 0 |
| Pipelock (scan API) | yes | yes | 6.1% | 6.1% | 96.3% | 38/44 | 0 |
| AEGIS (pre-execution check) | yes | yes | 4.2% | 53.9% | **100%** | 29/44 | 1000 |
| mcp-firewall (inbound pipeline) | yes | yes | 8.5% | 100.0% | 96.3% | 0/44 | 49 |

- **recall (block)** — malicious actions hard-blocked. **recall (+gate)** — blocked *or* escalated to a human.
- **precision** — benign actions NOT blocked (100% = zero false positives). **under-gate** — risky actions silently allowed.
- **deterministic** — identical verdicts across two scoring passes (`*` = not re-run this pass; declared value shown).
- **median µs** — self-reported decision latency; comparable only among offline, same-host tools (a cloud tool includes network RTT).

_The `allow-all` and `block-all` rows are sanity anchors: allow-all pins 0% recall, block-all pins 100% recall at 0% precision — which is why recall is meaningless without precision beside it._
