#!/usr/bin/env bash
# Restart the AEGIS gateway on a FRESH database before scoring a corpus.
#
# Why this exists — and why it is a fairness measure, not a thumb on the scale.
# AEGIS gates POST /api/v1/check behind a Stripe plan quota, and its free plan
# is `monthly_checks: 1_000` with `allow_overage: false`
# (packages/gateway-mcp/src/services/billing.ts). The arena scores every adapter
# TWICE per corpus (the determinism check), so one full board run issues several
# thousand checks — far past that cap. Once exceeded, the gateway answers 429 to
# everything for the rest of the run.
#
# Left unhandled that produced two false results, both of which we nearly
# published:
#   * verdicts differed between the two scoring passes, so the determinism
#     column accused AEGIS of declaring a determinism it did not have; and
#   * on a large corpus even the adapter's startup probe was throttled, so the
#     row silently disappeared as "unavailable".
# Neither is a security property. A commercial quota is not a detection limit,
# and scoring a tool through its paywall measures the paywall.
#
# The quota counter lives in the gateway's SQLite DB, so recreating the
# container gives the next corpus a clean allowance. Corpora that fit inside
# 1,000 checks (samples x 2 passes) are therefore scored on their merits. A
# corpus that does NOT fit cannot be scored on the free plan at all, and we
# decline to buy a paid plan to benchmark someone else's tool — that case is
# excluded explicitly in the workflow's assertion rather than reported as a
# failing row.
set -euo pipefail

docker rm -f aegis >/dev/null 2>&1 || true
docker run -d --name aegis -p 8080:8080 \
  -e DB_PATH=/data/agentguard.db \
  -e RATE_LIMIT_MAX=100000000 \
  -e RATE_LIMIT_WINDOW=1000 \
  aegis-gateway:pinned >/dev/null

for _ in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/health || true)
  if [ "$code" = "200" ]; then
    echo "AEGIS restarted with a fresh quota"
    exit 0
  fi
  sleep 1
done

echo "AEGIS did not come back up after restart; container log:" >&2
docker logs aegis >&2 || true
exit 1
