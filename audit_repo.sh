#!/bin/bash
# TAP-A2A repository audit.
#
# Classifies every file in the working tree against the expected
# submission manifest. DRY RUN by default — it deletes nothing.
# Run with --delete to remove the files listed under DELETE.
#
#   ./audit_repo.sh            # report only
#   ./audit_repo.sh --delete   # act on the DELETE list

DELETE_MODE=0
[ "$1" = "--delete" ] && DELETE_MODE=1

KEEP=(
  # On-chain program
  "programs/tap_a2a/src/lib.rs"
  "programs/tap_a2a/Cargo.toml"
  "programs/tap_a2a/Xargo.toml"
  "Anchor.toml"
  "Cargo.toml"
  "Cargo.lock"
  # Evaluation suite
  "tap_a2a_common.py"
  "tap_a2a_client.py"
  "scenario_runner.py"
  "agentic_orchestrator.py"
  "full_gateway_benchmark.py"
  "generate_graphs.py"
  "gateway.py"
  # Ring signatures
  "tap_a2a_trs.py"
  "trs_benchmark.py"
  # A2A message layer (objective 3)
  "tap_a2a_messaging.py"
  "a2a_scenario_runner.py"
  "bypass_experiment.py"
  "tap_a2a_planner.py"
  "audit_overhead_experiment.py"
  "peer_scenario_runner.py"
  # Formal verification
  "tap_a2a.spthy"
  "verify_tap_a2a.py"
  # Pipeline
  "deploy_and_test.sh"
  "run_all_evaluations.sh"
  "check_submission.sh"
  "audit_repo.sh"
  # Project files
  "README.md"
  "requirements.txt"
  ".gitignore"
  ".env.example"
  ".prettierignore"
  "package.json"
  "yarn.lock"
  "tsconfig.json"
  "migrations/deploy.ts"
  "tests/tap_a2a.ts"
  # Fixed program identity — needed so the ID stays stable
  "target/deploy/tap_a2a-keypair.json"
)

# Superseded by the current suite; each is dead code or a stale artefact.
DELETE_FILES=(
  # .env holds API keys. It must exist locally and never be committed.
  "config.py"                # deprecated shim; everything uses tap_a2a_common
  "performance_test.py"      # stale program ID + wrong struct layout; cannot run
  "benchmark_runner.py"      # superseded by full_gateway_benchmark.py
  "setup_agent.py"           # superseded by scenario_runner provisioning
  "setup_agents.py"          # ditto, and invents a "scope" concept the program lacks
  "tap_a2a.spdl"             # Scyther model; Scyther dropped
  "access_audit_log.json"    # stale runtime artefact
  "metrics_data.csv"         # old benchmark output
  "metrics_summary.txt"      # old benchmark output
  "validator.log"
  "try.spthy"
)

DELETE_DIRS=(
  "scyther-main"             # Scyther dropped
  "1.12.0"                   # a Homebrew tamarin-prover install, committed by mistake
  "__pycache__"
  ".anchor"
  "test-ledger"
)

is_keep() {
  for k in "${KEEP[@]}"; do [ "$1" = "$k" ] && return 0; done
  return 1
}

echo "======================================================================"
echo "TAP-A2A repository audit"
[ $DELETE_MODE -eq 1 ] && echo "MODE: DELETE" || echo "MODE: dry run (use --delete to act)"
echo "======================================================================"

echo ""
echo "--- MISSING (expected but not present) ---"
MISSING=0
for k in "${KEEP[@]}"; do
  case "$k" in
    "programs/tap_a2a/Xargo.toml"|"package.json"|"yarn.lock"|"tsconfig.json"|\
    "migrations/deploy.ts"|".prettierignore"|"audit_repo.sh")
      continue ;;   # optional, depends on how the project was scaffolded
  esac
  [ -e "$k" ] || { echo "  $k"; MISSING=1; }
done
[ $MISSING -eq 0 ] && echo "  (none)"

echo ""
echo "--- DELETE (superseded or stale) ---"
FOUND=0
for f in "${DELETE_FILES[@]}"; do
  if [ -e "$f" ]; then
    FOUND=1
    if [ $DELETE_MODE -eq 1 ]; then rm -f "$f"; echo "  removed  $f"; else echo "  $f"; fi
  fi
done
for d in "${DELETE_DIRS[@]}"; do
  if [ -d "$d" ]; then
    FOUND=1
    if [ $DELETE_MODE -eq 1 ]; then rm -rf "$d"; echo "  removed  $d/"; else echo "  $d/"; fi
  fi
done
find . -name "ablation_*.spthy" -not -path "./venv/*" 2>/dev/null | while read -r f; do
  if [ $DELETE_MODE -eq 1 ]; then rm -f "$f"; echo "  removed  $f"; else echo "  $f"; fi
done
[ $FOUND -eq 0 ] && echo "  (none)"

echo ""
echo "--- dissertation_results/ ---"
if [ -d dissertation_results ]; then
  ls -1 dissertation_results | sed 's/^/  /'
else
  echo "  MISSING — the marker would see no evidence without running the suite"
fi

echo ""
echo "--- UNKNOWN (not in the manifest — decide individually) ---"
UNKNOWN=0
while IFS= read -r f; do
  f="${f#./}"
  case "$f" in
    .git/*|venv/*|node_modules/*|target/*|test-ledger/*|__pycache__/*|\
    .anchor/*|dissertation_results/*|scyther-main/*|1.12.0/*|*.pyc|.DS_Store)
      continue ;;
  esac
  is_keep "$f" && continue
  for d in "${DELETE_FILES[@]}"; do [ "$f" = "$d" ] && continue 2; done
  echo "  $f"
  UNKNOWN=1
done < <(find . -type f -not -path "./.git/*" 2>/dev/null)
[ $UNKNOWN -eq 0 ] && echo "  (none)"

echo ""
echo "======================================================================"
if [ $DELETE_MODE -eq 0 ]; then
  echo "Dry run. Review the UNKNOWN list, then: ./audit_repo.sh --delete"
else
  echo "Cleanup done. Next: git add -A && ./check_submission.sh"
fi
echo "======================================================================"
