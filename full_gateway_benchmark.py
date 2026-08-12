"""
TAP-A2A Performance Benchmark

Measures the three stages of an access decision, plus on-chain compute
consumption, over N iterations. Writes gateway_<N>_iterations.csv --
the single canonical data source that generate_graphs.py reads.

CHANGED IN THIS REVISION
------------------------
- Adds the `epoch` argument and derives the nullifier from the agent's
  public key, matching the on-chain verification.
- Uses a distinct action hash per iteration. Previously every iteration
  used one action hash with a different nonce, which is no longer valid:
  the nullifier is now bound to (agent, group, action, epoch), so a
  second access to the SAME action in the same epoch is correctly
  rejected as a replay. That is the intended security property, not a
  bug -- but it means a throughput benchmark must vary the action.
- Renames the "signature verification" stage honestly. The script signs
  and verifies in the same process, so this is an Ed25519 verification
  microbenchmark, not an authentication measurement. Describe it that
  way in Chapter 6.
- Exits non-zero on failure.

READING THE NUMBERS
-------------------
"Policy read" is two sequential RPC account fetches. "On-chain decision"
is submit-and-confirm for the access transaction. They are NOT additive
into a single end-to-end figure -- the confirm already includes the
program's own policy evaluation. Report them as separate stages. The
progress report's Table I summed a verification cost and a query cost
into a "total"; that framing came from the now-deleted
performance_test.py and should be regenerated from this script.
"""
import asyncio
import csv
import statistics
import sys
import time

import nacl.signing
from solders.keypair import Keypair

from tap_a2a_common import (
    load_program_id, generate_bytes32, current_epoch,
    agent_pda, policy_pda, ix_register_agent, ix_set_policy, ix_log_access,
)
from tap_a2a_client import rpc_client, load_admin, send, ensure_initialized, airdrop, COMMITMENT

ITERATIONS = 100


def metrics(data):
    if not data:
        return {"min": 0, "avg": 0, "p50": 0, "p95": 0, "max": 0}
    s = sorted(data)
    p95_idx = max(0, int(len(s) * 0.95) - 1)
    return {
        "min": min(data), "avg": statistics.mean(data),
        "p50": statistics.median(data), "p95": s[p95_idx], "max": max(data),
    }


async def main() -> int:
    print(f"TAP-A2A benchmark — {ITERATIONS} iterations\n")
    program_id = load_program_id()

    async with rpc_client() as client:
        admin = load_admin()
        await ensure_initialized(client, program_id, admin)

        agent = Keypair()
        print("Airdropping 10 SOL to the benchmark agent...")
        await airdrop(client, [agent.pubkey()], lamports=10_000_000_000)

        group_id = generate_bytes32()
        epoch = current_epoch()

        print("Registering agent...")
        await send(client, ix_register_agent(program_id, admin.pubkey(),
                                             agent.pubkey(), group_id), [admin])

        # One action hash (and therefore one policy) per iteration, so
        # each access is a distinct, legitimately authorised request.
        print(f"Provisioning {ITERATIONS} action policies (setup, not measured)...")
        actions = [generate_bytes32() for _ in range(ITERATIONS)]
        for i, action in enumerate(actions, 1):
            await send(client, ix_set_policy(program_id, admin.pubkey(),
                                             group_id, action, True), [admin])
            if i % 25 == 0:
                print(f"  {i}/{ITERATIONS} policies set")

        print("\nSetup complete. Running benchmark loop...\n")

        verify_times, read_times, decision_times, cu_list = [], [], [], []
        a_record = agent_pda(program_id, agent.pubkey())
        failures = 0

        for i, action in enumerate(actions, 1):
            # --- Stage 1: Ed25519 verification microbenchmark ----------
            payload = bytes(action) + epoch.to_bytes(8, "little")
            signature = agent.sign_message(payload)
            start = time.perf_counter()
            try:
                nacl.signing.VerifyKey(bytes(agent.pubkey())).verify(payload, bytes(signature))
            except Exception:
                print(f"Run {i}: signature verification failed unexpectedly.")
                failures += 1
                continue
            # Stage timings are buffered and only committed once the whole
            # iteration succeeds. Appending stage by stage let a stage-3
            # failure leave verify_times and read_times one entry longer
            # than decision_times, after which every CSV row past that
            # point paired the wrong measurements together.
            verify_ms = (time.perf_counter() - start) * 1000

            # --- Stage 2: off-chain policy read ------------------------
            p_pda = policy_pda(program_id, group_id, action)
            start = time.perf_counter()
            await client.get_account_info(a_record)
            await client.get_account_info(p_pda)
            read_ms = (time.perf_counter() - start) * 1000

            # --- Stage 3: on-chain decision ----------------------------
            try:
                _, latency, cus = await send(
                    client,
                    ix_log_access(program_id, agent.pubkey(), group_id, action, epoch),
                    [agent])
            except Exception as e:
                print(f"Run {i}: on-chain decision failed: {str(e)[:120]}")
                failures += 1
                continue

            verify_times.append(verify_ms)
            read_times.append(read_ms)
            decision_times.append(latency)
            cu_list.append(cus)

            if i % 10 == 0:
                print(f"  {i}/{ITERATIONS} complete")
            await asyncio.sleep(0.05)  # avoid local RPC rate limiting

        # ------------------------------------------------------------------
        rows = [
            ("Ed25519 verify (ms)", metrics(verify_times)),
            ("Policy read (ms)", metrics(read_times)),
            ("On-chain decision (ms)", metrics(decision_times)),
            ("Compute units", metrics(cu_list)),
        ]

        print("\n" + "=" * 72)
        print(f"BENCHMARK RESULTS — {len(decision_times)}/{ITERATIONS} successful iterations")
        print(f"Commitment level: {COMMITMENT}")
        print("=" * 72)
        print(f"{'Stage':<25}{'Min':>10}{'Avg':>10}{'P50':>10}{'P95':>10}{'Max':>10}")
        print("-" * 72)
        for name, m in rows:
            print(f"{name:<25}{m['min']:>10.2f}{m['avg']:>10.2f}"
                  f"{m['p50']:>10.2f}{m['p95']:>10.2f}{m['max']:>10.2f}")
        print("=" * 72)
        print("\nStages are measured independently and are NOT additive.")
        print("On-chain decision latency is commitment-dependent. Re-run with")
        print("TAP_A2A_COMMITMENT=finalized to obtain the irreversibility upper bound.")

        csv_path = f"gateway_{ITERATIONS}_iterations.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Iteration", "Ed25519_Verify_ms", "Policy_Read_ms",
                             "OnChain_Decision_ms", "Compute_Units"])
            for i in range(len(decision_times)):
                writer.writerow([i + 1, f"{verify_times[i]:.2f}", f"{read_times[i]:.2f}",
                                 f"{decision_times[i]:.2f}", cu_list[i]])
        print(f"Raw data written to '{csv_path}'.")

        if failures:
            print(f"\n{failures} iteration(s) failed — results are incomplete.")
            return 1
        return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
