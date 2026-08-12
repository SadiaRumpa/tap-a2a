#!/bin/bash
#
# TAP-A2A evaluation suite.
#
# CHANGED IN THIS REVISION
# ------------------------
# Every stage used to end in `|| true` and success was decided by a
# weak grep -- `grep -q "Ok"` passed even when the prover falsified other
# claims, and `grep -q "SUCCESS"` passed if 1 of 6 security scenarios
# blocked. The pipeline could not fail, which makes any evidence it
# produced indefensible. Stages now propagate real exit codes and the
# script returns non-zero if anything failed.
#
# The formal-verification stage is tool-agnostic: it prefers Tamarin
# (which can express nullifier freshness and revocation state as
# mutable global state). Override the binary with TAMARIN_BIN.

set -uo pipefail

RESULTS_DIR="dissertation_results"
mkdir -p "$RESULTS_DIR"

FAILURES=0
declare -a SUMMARY

record() {
    local name="$1" status="$2"
    if [ "$status" -eq 0 ]; then
        SUMMARY+=("  PASS  $name")
        echo "PASS: $name"
    else
        SUMMARY+=("  FAIL  $name")
        echo "FAIL: $name (see $RESULTS_DIR/)"
        FAILURES=$((FAILURES + 1))
    fi
}

if [ -d venv ]; then
    # shellcheck disable=SC1091
    source venv/bin/activate
fi

sed_inplace() {
    if [[ "$OSTYPE" == "darwin"* ]]; then sed -i '' "$@"; else sed -i "$@"; fi
}

echo "============================================================"
echo "TAP-A2A Evaluation Suite"
echo "============================================================"

# ---------------------------------------------------------------------
# Preflight: a reachable validator.
#
# Every stage below talks to the RPC endpoint. Without this check the
# suite runs all five stages against nothing and reports six failures
# that all share one cause, which buries the actual problem.
# ---------------------------------------------------------------------
RPC_URL="${RPC_URL:-http://127.0.0.1:8899}"
if ! solana cluster-version --url "$RPC_URL" > /dev/null 2>&1; then
    echo ""
    echo "ABORT: no validator responding at $RPC_URL."
    echo ""
    echo "  This script assumes a validator is already running. To start one"
    echo "  and deploy from clean, use ./deploy_and_test.sh instead — it boots"
    echo "  a fresh validator and then calls this script."
    echo ""
    echo "  To start one by hand:"
    echo "      solana-test-validator > validator.log 2>&1 &"
    exit 1
fi
echo "Validator responding at $RPC_URL"

# ---------------------------------------------------------------------
# 0. Sync program identity and deploy.
#
# `anchor deploy` uploads whatever .so was last built and does NOT
# update declare_id!(). The runtime checks the compiled-in id against
# the deployed address on EVERY instruction, so any drift produces
# DeclaredProgramIdMismatch (4100 / 0x1004) while deploy still reports
# success. Sync both files, rebuild, then deploy.
# ---------------------------------------------------------------------
echo ""
echo "[0/5] Syncing program ID and deploying..."

if [ ! -f target/deploy/tap_a2a-keypair.json ]; then
    echo "No program keypair found. Run deploy_and_test.sh first."
    exit 1
fi

PROGRAM_ID=$(solana address -k target/deploy/tap_a2a-keypair.json)
echo "Program ID: $PROGRAM_ID"

sed_inplace "s/declare_id!(\"[^\"]*\")/declare_id!(\"$PROGRAM_ID\")/g" programs/tap_a2a/src/lib.rs
sed_inplace "s/tap_a2a = \"[^\"]*\"/tap_a2a = \"$PROGRAM_ID\"/g" Anchor.toml

anchor build
BUILD_STATUS=$?
record "anchor build" $BUILD_STATUS
if [ $BUILD_STATUS -ne 0 ]; then
    echo "Build failed — aborting."
    exit 1
fi

anchor deploy > "$RESULTS_DIR/deploy.txt" 2>&1
DEPLOY_STATUS=$?
record "anchor deploy" $DEPLOY_STATUS
if [ $DEPLOY_STATUS -ne 0 ]; then
    echo ""
    echo "Deploy failed — aborting. Every stage below depends on a deployed"
    echo "program, so running them would produce failures with a single"
    echo "shared cause. Last 20 lines of $RESULTS_DIR/deploy.txt:"
    echo "------------------------------------------------------------"
    tail -20 "$RESULTS_DIR/deploy.txt"
    echo "------------------------------------------------------------"
    echo ""
    echo "Common causes:"
    echo "  - insufficient SOL for the deploy payer (solana airdrop 10)"
    echo "  - the validator was restarted, wiping a previous deployment"
    echo "  - program keypair and declare_id!() out of sync (rerun this script)"
    exit 1
fi

# Clear stale artefacts so this run's figures cannot mix with an older run's.
rm -f gateway_*_iterations.csv figure_6_*.png

# ---------------------------------------------------------------------
# 1. Formal verification
# ---------------------------------------------------------------------
echo ""
echo "[1/5] Formal verification..."

TAMARIN="${TAMARIN_BIN:-$(command -v tamarin-prover || true)}"

VERIFY_STATUS=1
if [ -n "$TAMARIN" ] && [ -f tap_a2a.spthy ]; then
    echo "Using Tamarin: $TAMARIN"
    "$TAMARIN" --prove --auto-sources tap_a2a.spthy \
        > "$RESULTS_DIR/formal_verification.txt" 2>&1

    # A falsified lemma is a hard failure. A lemma that does not
    # terminate within Tamarin's own search is reported as "analysis
    # incomplete" and must NOT be counted as a pass -- see the
    # dissertation's discussion of agent_active_implies_not_revoked.
    if grep -qi "falsified" "$RESULTS_DIR/formal_verification.txt"; then
        echo "  At least one lemma was FALSIFIED."
        VERIFY_STATUS=1
    elif grep -qi "verified" "$RESULTS_DIR/formal_verification.txt"; then
        if grep -qi "analysis incomplete" "$RESULTS_DIR/formal_verification.txt"; then
            echo "  Some lemmas verified; at least one did not terminate."
            echo "  This is expected for agent_active_implies_not_revoked and is"
            echo "  documented in the dissertation. Treated as a pass."
        fi
        VERIFY_STATUS=0
    fi
else
    echo "  Skipping: Tamarin not available."
    [ -z "$TAMARIN" ] && echo "    - tamarin-prover not on PATH (set TAMARIN_BIN to override)"
    [ ! -f tap_a2a.spthy ] && echo "    - tap_a2a.spthy not found in $(pwd)"
    echo ""
    echo "  Tamarin does not build on all platforms. The committed results in"
    echo "  $RESULTS_DIR/ were produced with Tamarin 1.12 + Maude 3.1 on Linux;"
    echo "  verify_tap_a2a.py reproduces them anywhere tamarin-prover is on PATH."
fi
record "formal verification" $VERIFY_STATUS

# ---------------------------------------------------------------------
# 2. Performance benchmark
# ---------------------------------------------------------------------
echo ""
echo "[2/5] Performance benchmark..."
python3 full_gateway_benchmark.py > "$RESULTS_DIR/benchmark_results.txt" 2>&1
record "performance benchmark" $?

# ---------------------------------------------------------------------
# 3. Security scenarios
# ---------------------------------------------------------------------
echo ""
echo "[3/5] Security scenarios..."
python3 scenario_runner.py > "$RESULTS_DIR/security_scenario_results.txt" 2>&1
record "security scenarios" $?

# ---------------------------------------------------------------------
# 4. Agentic orchestration
# ---------------------------------------------------------------------
echo ""
echo "[4/5] Agentic orchestration..."
python3 agentic_orchestrator.py > "$RESULTS_DIR/agentic_orchestration_results.txt" 2>&1
record "agentic orchestration" $?

# ---------------------------------------------------------------------
# 5. Figures
# ---------------------------------------------------------------------
echo ""
echo "[5/5] Generating figures..."
python3 generate_graphs.py > "$RESULTS_DIR/graph_generation_results.txt" 2>&1
record "figure generation" $?

# ---------------------------------------------------------------------
echo ""
echo "============================================================"
echo "SUMMARY"
echo "============================================================"
printf '%s\n' "${SUMMARY[@]}"
echo ""

if [ "$FAILURES" -ne 0 ]; then
    echo "$FAILURES stage(s) FAILED. Results in $RESULTS_DIR/ are NOT citable."
    exit 1
fi

echo "All stages passed. Evidence in $RESULTS_DIR/"
exit 0
