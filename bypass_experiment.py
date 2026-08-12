
import asyncio
import sys

from solders.keypair import Keypair

from tap_a2a_common import (
    load_program_id, generate_bytes32, action_hash, current_epoch,
    access_nullifier, ix_register_agent, ix_set_policy, ix_log_access,
    trace_log_pda, classify_error,
)
from tap_a2a_client import (
    rpc_client, load_admin, send, ensure_initialized, airdrop, sync_clock,
)

LAMPORTS_PER_SOL = 1_000_000_000

results = {}


def record(name: str, ok: bool, detail: str = ""):
    results[name] = ok
    print(f"  {'PASS' if ok else 'FAIL'}: {name}{' — ' + detail if detail else ''}")


async def main() -> int:
    print("=" * 72)
    print("TAP-A2A — LAYER BYPASS AND STORAGE COST EXPERIMENT")
    print("=" * 72)

    program_id = load_program_id()

    async with rpc_client() as client:
        admin = load_admin()
        await ensure_initialized(client, program_id, admin)
        offset = await sync_clock(client)
        print(f"Program: {program_id}")
        if abs(offset) > 60:
            print(f"Validator clock offset: {offset:+.0f}s from wall time "
                  f"(epochs derived from the chain's clock).")
        print()

        authorised = Keypair()
        unauthorised = Keypair()
        group = generate_bytes32()
        rogue_group = generate_bytes32()

        await airdrop(client, [authorised.pubkey(), unauthorised.pubkey()])

        await send(client, ix_register_agent(program_id, admin.pubkey(),
                                             authorised.pubkey(), group), [admin])
        await send(client, ix_register_agent(program_id, admin.pubkey(),
                                             unauthorised.pubkey(), rogue_group), [admin])

        allowed = action_hash("READ_DATABASE")
        forbidden = action_hash("DELETE_RECORDS")

        # Only the authorised agent's group gets a policy. DELETE_RECORDS
        # gets none at all, in any group.
        await send(client, ix_set_policy(program_id, admin.pubkey(), group,
                                         allowed, True), [admin])

        print("Setup: one authorised agent, one agent in a group with no policy.")
        print("       READ_DATABASE allowed for the first group only.")
        print("       DELETE_RECORDS has no policy in any group.\n")

        epoch = current_epoch()

        # ------------------------------------------------------------------
        print("=" * 72)
        print("PART 1 — BYPASSING THE MESSAGE LAYER")
        print("=" * 72)
        print("Every call below skips tap_a2a_messaging entirely: no")
        print("TaskMessage, no signature check, no worker. The client talks")
        print("straight to the program, as a compromised orchestrator or a")
        print("hostile script would.\n")

        # --- 1a: authorised agent, authorised action ----------------------
        # Expected to SUCCEED. This is the honest result: bypassing the
        # message layer does not by itself constitute an attack. An agent
        # acting within its own on-chain policy is authorised however it
        # chooses to reach the chain.
        print("[1a] Authorised agent, action within its policy")
        try:
            await send(client, ix_log_access(program_id, authorised.pubkey(),
                                             group, allowed, epoch), [authorised])
            record("bypass_authorised_action_succeeds", True,
                   "granted — the chain authorises on its own state, not on how the "
                   "request arrived")
        except Exception as e:
            record("bypass_authorised_action_succeeds", False, classify_error(e)[:80])

        # --- 1b: authorised agent, action with no policy ------------------
        print("\n[1b] Authorised agent, action with NO policy (the escalation attempt)")
        try:
            await send(client, ix_log_access(program_id, authorised.pubkey(),
                                             group, forbidden, epoch), [authorised])
            record("bypass_escalation_blocked", False,
                   "CRITICAL: escalation succeeded with the message layer bypassed")
        except Exception as e:
            msg = classify_error(e)
            record("bypass_escalation_blocked", "no matching policy" in msg.lower(),
                   msg[:80])

        # --- 1c: agent whose group has no policy --------------------------
        print("\n[1c] Agent whose group holds no policy for the action")
        try:
            await send(client, ix_log_access(program_id, unauthorised.pubkey(),
                                             rogue_group, allowed, epoch), [unauthorised])
            record("bypass_wrong_group_blocked", False,
                   "CRITICAL: an agent outside the authorised group gained access")
        except Exception as e:
            msg = classify_error(e)
            record("bypass_wrong_group_blocked", "no matching policy" in msg.lower(),
                   msg[:80])

        # --- 1d: forged nullifier -----------------------------------------
        print("\n[1d] Authorised agent submitting a forged nullifier")
        try:
            await send(client, ix_log_access(program_id, authorised.pubkey(),
                                             group, allowed, epoch,
                                             nullifier=generate_bytes32()), [authorised])
            record("bypass_forged_nullifier_blocked", False,
                   "CRITICAL: a forged nullifier was accepted")
        except Exception as e:
            msg = classify_error(e)
            record("bypass_forged_nullifier_blocked", "nullifier" in msg.lower(),
                   msg[:80])

        # --- 1e: replay ----------------------------------------------------
        print("\n[1e] Replaying 1a directly against the chain")
        # The message layer's nonce check cannot help here -- there is no
        # message. Only the on-chain nullifier stands between the attacker
        # and a duplicate authorisation.
        try:
            await send(client, ix_log_access(program_id, authorised.pubkey(),
                                             group, allowed, epoch), [authorised])
            record("bypass_replay_blocked", False,
                   "CRITICAL: a replayed access was accepted")
        except Exception as e:
            msg = classify_error(e)
            record("bypass_replay_blocked", "replay" in msg.lower(), msg[:80])

        # ------------------------------------------------------------------
        print("\n" + "=" * 72)
        print("PART 2 — TRACEABILITY STORAGE COST")
        print("=" * 72)

        n = access_nullifier(authorised.pubkey(), group, allowed, epoch)
        info = await client.get_account_info(trace_log_pda(program_id, n))
        if info.value is None:
            record("storage_measured", False, "trace account not found")
        else:
            size = len(bytes(info.value.data))
            rent = info.value.lamports
            sol = rent / LAMPORTS_PER_SOL
            record("storage_measured", True, f"{size} bytes, {sol:.6f} SOL per access")

            print(f"\n  Per trace record: {size} bytes, {rent:,} lamports "
                  f"({sol:.6f} SOL)")
            print("\n  Extrapolated cost of an append-only audit trail:")
            print(f"  {'Accesses':>12}  {'Accounts':>10}  {'Storage':>12}  {'Rent (SOL)':>12}")
            print("  " + "-" * 52)
            for count in (100, 1_000, 10_000, 100_000, 1_000_000):
                print(f"  {count:>12,}  {count:>10,}  "
                      f"{size * count / 1_048_576:>10.2f}MB  "
                      f"{sol * count:>12.3f}")

            print("\n  Rent is rent-exempt deposit, not a fee: it is locked for as")
            print("  long as the record exists and is recoverable only if the")
            print("  account is closed. Permanent auditability therefore has a")
            print("  permanent capital cost, and the trade-off is governed by")
            print("  EPOCH_SECONDS -- a longer epoch means fewer, coarser records.")

    print("\n" + "=" * 72)
    print("RESULTS")
    print("=" * 72)
    for name, ok in results.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")

    passed = sum(1 for ok in results.values() if ok)
    total = len(results)
    print(f"\n{passed}/{total} checks passed.")
    print("""
INTERPRETATION

  1a succeeding is the correct result, not a weakness. Bypassing the
  message layer does not grant authority: the agent in 1a was already
  authorised for that action, and the chain does not care how the request
  reached it.

  1b-1e are the security claim. With the entire message layer removed,
  the chain independently refuses privilege escalation, cross-group
  access, forged nullifiers and replays. Worker-side checks are therefore
  a defence-in-depth layer that fails safe: removing them costs early
  rejection and the audit signal, not authorisation integrity.
""")

    if passed != total:
        print("EXPERIMENT FAILED — do not cite these results in the dissertation.")
        return 1
    print("EXPERIMENT PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
