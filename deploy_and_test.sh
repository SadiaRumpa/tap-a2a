#!/bin/bash
#
# TAP-A2A: clean deploy from a fresh validator, then full evaluation.
#
# CHANGED IN THIS REVISION
# ------------------------
# - No longer duplicates the evaluation stages; it starts a clean
#   validator, deploys, and delegates to run_all_evaluations.sh so the
#   pass/fail logic lives in exactly one place.
# - Propagates the suite's exit code instead of always returning 0.
# - Drops `--force` from solana-keygen (it was inside a "file does not
#   exist" guard, so it could only ever overwrite something unexpected).

set -uo pipefail

echo "============================================================"
echo "TAP-A2A: Clean Deployment and Evaluation"
echo "============================================================"

if [ -d venv ]; then
    # shellcheck disable=SC1091
    source venv/bin/activate
fi

echo "[1/4] Stopping existing validators..."
pkill -9 -f solana-test-validator 2>/dev/null || true
sleep 2

echo "[2/4] Cleaning old ledger..."
rm -rf test-ledger

echo "[3/4] Starting fresh validator..."
solana-test-validator > validator.log 2>&1 &
VALIDATOR_PID=$!

echo "Waiting for validator..."
READY=0
for _ in {1..30}; do
    if solana balance > /dev/null 2>&1; then READY=1; break; fi
    sleep 1
done

if [ "$READY" -ne 1 ]; then
    echo "Validator did not become ready in 30s. See validator.log."
    kill "$VALIDATOR_PID" 2>/dev/null || true
    exit 1
fi
echo "Validator ready (PID: $VALIDATOR_PID)"

echo "[4/4] Ensuring a fixed program identity..."

# ORDER MATTERS. `cargo clean` deletes the whole target/ directory, and
# the program keypair lives at target/deploy/tap_a2a-keypair.json. If the
# keypair is generated first, cargo clean silently removes it and
# run_all_evaluations.sh then aborts with "No program keypair found".
# So: clean first, then generate. The keypair is also preserved across
# runs so the program ID stays stable — regenerating it on every run
# would invalidate every previously recorded result.
KEYPAIR="target/deploy/tap_a2a-keypair.json"
# Plain mktemp, no -t template: GNU mktemp requires XXXXXX in a -t
# template while BSD/macOS does not, so the templated form silently
# failed on Linux and cargo clean then destroyed the program keypair.
KEYPAIR_BACKUP="$(mktemp)"

if [ -f "$KEYPAIR" ]; then
    cp "$KEYPAIR" "$KEYPAIR_BACKUP"
    HAVE_BACKUP=1
else
    HAVE_BACKUP=0
fi

# A clean deploy means a fresh chain, so force a full rebuild.
cargo clean

mkdir -p target/deploy
if [ "$HAVE_BACKUP" -eq 1 ]; then
    cp "$KEYPAIR_BACKUP" "$KEYPAIR"
    echo "Restored the existing program keypair after cargo clean."
else
    echo "Generating program keypair (first run only)..."
    solana-keygen new --no-passphrase -o "$KEYPAIR" > /dev/null
fi
rm -f "$KEYPAIR_BACKUP"
rm -f target/deploy/tap_a2a.so

if [ ! -s "$KEYPAIR" ]; then
    echo "ERROR: $KEYPAIR is missing or empty after the clean step."
    echo "  If it is tracked in git:  git checkout -- $KEYPAIR"
    echo "  Otherwise:                solana-keygen new --no-passphrase -o $KEYPAIR"
    echo "  (generating a new one changes the program ID, so prefer restoring)"
    exit 1
fi
echo "Program ID: $(solana address -k "$KEYPAIR")"

echo ""
echo "Handing off to run_all_evaluations.sh..."
echo ""
# Invoked via bash so a missing +x bit isn't a hard failure — git does
# preserve the executable bit, but files copied from a browser download
# usually arrive without it.
bash ./run_all_evaluations.sh
SUITE_STATUS=$?

echo ""
echo "Validator still running (PID: $VALIDATOR_PID). Stop it with: kill $VALIDATOR_PID"
exit $SUITE_STATUS
