#!/bin/bash
# Pre-submission check for the TAP-A2A repository.
#
# Verifies that nothing secret is tracked, that the files the marker
# needs are present, and that the working tree is clean. Run from the
# repo root before the final push.

FAIL=0
ok()   { echo "  OK    $1"; }
bad()  { echo "  FAIL  $1"; FAIL=1; }
warn() { echo "  WARN  $1"; }

echo "=============================================="
echo "TAP-A2A pre-submission check"
echo "=============================================="

echo ""
echo "[1/5] Secrets"
# The local wallet must never be tracked, in the current tree or in history.
if git ls-files | grep -qE '(^|/)\.env$'; then
    bad ".env is TRACKED — it holds API keys. Untrack it and ROTATE the key:"
    bad "      git rm --cached .env  &&  revoke the key at the provider"
else
    ok "no .env tracked"
fi

if git log --all --full-history --name-only --pretty=format: 2>/dev/null \
     | grep -qE '(^|/)\.env$'; then
    bad ".env appears in git HISTORY — ROTATE the API key immediately."
else
    ok "no .env in history"
fi

if git ls-files | grep -qE '(^|/)id\.json$'; then
    bad "id.json is tracked — remove it: git rm --cached <path>"
else
    ok "no id.json tracked"
fi

if git log --all --full-history --name-only --pretty=format: 2>/dev/null \
     | grep -qE '(^|/)id\.json$'; then
    warn "id.json appears in git HISTORY. On a localnet-only wallet this is"
    warn "low risk, but rotate the key and mention it if asked."
else
    ok "no id.json in history"
fi

TRACKED_KEYS=$(git ls-files | grep -E '_keypair\.json$' | grep -v 'tap_a2a-keypair.json')
if [ -n "$TRACKED_KEYS" ]; then
    warn "agent keypairs are tracked:"
    echo "$TRACKED_KEYS" | sed 's/^/          /'
    warn "these are disposable localnet test keys, but prefer not to ship them"
else
    ok "no agent keypairs tracked"
fi

echo ""
echo "[2/5] Bulk artefacts"
for d in target/deploy/tap_a2a.so test-ledger node_modules venv; do
    if git ls-files | grep -q "^$d"; then
        bad "$d is tracked — add to .gitignore and: git rm -r --cached $d"
    else
        ok "$d not tracked"
    fi
done

echo ""
echo "[3/5] Files the marker needs"
for f in README.md requirements.txt .gitignore \
         programs/tap_a2a/src/lib.rs Anchor.toml \
         tap_a2a_common.py tap_a2a_client.py \
         scenario_runner.py full_gateway_benchmark.py \
         agentic_orchestrator.py generate_graphs.py \
         deploy_and_test.sh run_all_evaluations.sh \
         tap_a2a.spthy verify_tap_a2a.py; do
    if [ -f "$f" ]; then ok "$f"; else bad "$f MISSING"; fi
done

echo ""
echo "[4/5] Committed results"
if [ -d dissertation_results ]; then
    COUNT=$(git ls-files dissertation_results | wc -l | tr -d ' ')
    if [ "$COUNT" -gt 0 ]; then
        ok "dissertation_results/ has $COUNT tracked file(s)"
    else
        bad "dissertation_results/ exists but nothing is tracked — the marker"
        bad "      would see no evidence without running the suite"
    fi
else
    bad "dissertation_results/ missing"
fi

for f in figure_6_1_latency_by_stage.png figure_6_2_cu_bar_chart.png; do
    if git ls-files | grep -q "$f"; then ok "$f tracked"; else warn "$f not tracked"; fi
done

echo ""
echo "[5/5] Working tree"
if [ -z "$(git status --porcelain)" ]; then
    ok "clean"
else
    warn "uncommitted changes:"
    git status --porcelain | sed 's/^/          /'
fi

echo ""
echo "=============================================="
if [ $FAIL -eq 0 ]; then
    echo "No blocking problems found."
else
    echo "BLOCKING PROBLEMS FOUND — fix the FAIL lines above."
fi
echo "=============================================="
exit $FAIL
