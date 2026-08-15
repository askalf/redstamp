#!/usr/bin/env python3
# Arena adapter: LLM Guard (github.com/protectai/llm-guard, MIT) — the guardrail
# toolkit from Protect AI (now part of Palo Alto Networks). See ../protocol.md.
#
# THREAT-MODEL NOTE — read this before reading its numbers. LLM Guard is an
# LLM-I/O guardrail, not a tool-call firewall. Its input scanners screen the
# TEXT going to a model: prompt-injection phrasing, secrets, banned topics,
# toxicity. This corpus is agent TOOL-CALL ACTIONS (shell/exec/fetch/write), so
# LLM Guard is EXPECTED to flag the injection family and to ALLOW shell
# semantics like `rm -rf /` — screening that is simply not what it does. That is
# a cross-layer map, not a loss: the two are complementary layers, and the
# per-family breakdown in results.json shows exactly where each one lives.
# Reporting its low shell recall as a "win" for redstamp would be the strawman
# the arena README exists to prevent.
#
# Scanners: the two documented INPUT scanners that need no operator-written
# configuration, so this is an out-of-box posture like every other row —
#   PromptInjection : its flagship; a DeBERTa classifier for injection text.
#                     Default model `protectai/deberta-v3-base-prompt-injection-v2`
#                     is PUBLIC (only the -small variant is gated), so this
#                     adapter needs NO token and NO paid key.
#   Secrets         : detect-secrets under the hood — pure regex/entropy, no model.
# Deliberately NOT enabled: `Code`/`BanCode` would flag essentially every sample
# (the corpus IS commands), manufacturing a precision collapse that says nothing
# about security; and BanSubstrings/Regex/BanTopics require operator-written
# rules, which no other row gets either.
#
# BINARY tool: LLM Guard returns valid/invalid per scanner — there is no
# human-in-the-loop tier — so `gated` is always false. protocol.md scores binary
# tools fairly rather than penalising them for lacking an escalate tier.
#
# If the package or its model is unavailable, this prints a diagnostic to stderr
# and exits 0 with NO stdout, so the runner marks the adapter "unavailable" and
# skips it — never a fake 0% row.
import json
import os
import sys
import time


def unavailable(msg: str) -> None:
    print(f"[llm-guard adapter] unavailable: {msg}", file=sys.stderr)
    sys.exit(0)  # no stdout => runner marks this adapter unavailable and skips it


try:
    from llm_guard import scan_prompt
    from llm_guard.input_scanners import PromptInjection, Secrets
    from llm_guard.input_scanners.prompt_injection import MatchType
except Exception as e:  # noqa: BLE001 - any import failure means "not installed"
    unavailable(f"import failed ({e}); `pip install llm-guard`")

# Model load happens here (downloads the public HF model on first run). Any
# failure — offline runner, HF outage — must mark the row unavailable rather
# than silently scoring every sample "allow".
try:
    scanners = [
        PromptInjection(threshold=0.92, match_type=MatchType.FULL),
        Secrets(),
    ]
except Exception as e:  # noqa: BLE001
    unavailable(f"scanner init failed ({e})")


def text_for(sample: dict) -> str:
    # Same input choice as the LlamaFirewall adapter, so the two LLM-I/O
    # guardrails see identical text: the untrusted skill text when the sample
    # carries one (the injection family), else the command the agent wants to run.
    text = sample.get("skill") or sample.get("command")
    if not text:
        text = json.dumps((sample.get("action") or {}).get("input") or {})
    return str(text)


def main() -> None:
    out = sys.stdout
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            sample = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        sid = sample.get("id")
        try:
            t0 = time.perf_counter()
            _sanitized, results_valid, _scores = scan_prompt(scanners, text_for(sample))
            ms = (time.perf_counter() - t0) * 1000.0
            # results_valid maps scanner name -> is_valid. Any scanner reporting
            # invalid means LLM Guard would reject this input.
            blocked = any(not ok for ok in results_valid.values())
            tripped = [name for name, ok in results_valid.items() if not ok]
            out.write(json.dumps({
                "id": sid,
                "blocked": blocked,
                "gated": False,  # binary tool: no human-in-the-loop tier
                "tier": (",".join(tripped) if tripped else "valid"),
                "ms": round(ms, 3),
            }) + "\n")
        except Exception as e:  # noqa: BLE001
            # A guardrail that errors is not a guardrail that allowed.
            out.write(json.dumps({"id": sid, "blocked": False, "error": str(e)}) + "\n")
        out.flush()


main()
