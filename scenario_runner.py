
import asyncio
import sys

from solders.keypair import Keypair

from tap_a2a_common import (
    load_program_id, generate_bytes32, current_epoch,
    access_nullifier, agent_pda, ix_register_agent, ix_set_policy,
    ix_update_policy, ix_revoke_agent, ix_log_access,
)
from tap_a2a_client import rpc_client, load_admin, send, ensure_initialized, airdrop, expect_denied, sync_clock


async def main() -> int:
    print("=" * 70)
    print("TAP-A2A SECURITY SCENARIO SUITE")
    print("=" * 70)

    program_id = load_program_id()
    results = {}

    async with rpc_client() as client:
        admin = load_admin()
        print(f"Admin: {admin.pubkey()} | Program: {program_id}\n")

        await ensure_initialized(client, program_id, admin)

        await sync_clock(client)   # align epochs with the chain's clock

        agent_a, agent_b, agent_c = Keypair(), Keypair(), Keypair()
        rogue_admin = Keypair()
        print(f"\nAgent A (allowed):      {agent_a.pubkey()}")
        print(f"Agent B (no policy):    {agent_b.pubkey()}")
        print(f"Agent C (unregistered): {agent_c.pubkey()}")
        print(f"Rogue admin:            {rogue_admin.pubkey()}")

        print("\nAirdropping...")
        await airdrop(client, [agent_a.pubkey(), agent_b.pubkey(),
                               agent_c.pubkey(), rogue_admin.pubkey()])

        group_id = generate_bytes32()
        action_allowed = generate_bytes32()
        action_denied = generate_bytes32()   # deliberately never given a policy
        action_revocable = generate_bytes32()
        action_after_revoke = generate_bytes32()
        epoch = current_epoch()

        # ------------------------------------------------------------------
        print("\n[1] Registering Agent A and setting its policy...")
        await send(client, ix_register_agent(program_id, admin.pubkey(),
                                             agent_a.pubkey(), group_id),
                   [admin], "Register Agent A")
        await send(client, ix_set_policy(program_id, admin.pubkey(), group_id,
                                         action_allowed, True),
                   [admin], "Set Policy (allow)")
        print("  Registered and policy set.")

        # ------------------------------------------------------------------
        print("\n[2] Agent A performing an ALLOWED action...")
        try:
            await send(client, ix_log_access(program_id, agent_a.pubkey(), group_id,
                                             action_allowed, epoch),
                       [agent_a], "Agent A allowed access")
            print("  PASS: access granted and logged.")
            results["allowed_access"] = True
        except Exception as e:
            print(f"  FAIL: legitimate access was blocked: {e}")
            results["allowed_access"] = False

        # ------------------------------------------------------------------
        print("\n[3] Agent B (registered, no policy for its action)...")
        await send(client, ix_register_agent(program_id, admin.pubkey(),
                                             agent_b.pubkey(), group_id),
                   [admin], "Register Agent B")
        results["no_policy"] = await expect_denied(
            send(client, ix_log_access(program_id, agent_b.pubkey(), group_id,
                                       action_denied, epoch), [agent_b]),
            expected_snippet="no matching policy",
            label="Agent B (no policy)")

        # ------------------------------------------------------------------
        print("\n[4] Agent C (never registered)...")
        results["unregistered"] = await expect_denied(
            send(client, ix_log_access(program_id, agent_c.pubkey(), group_id,
                                       action_allowed, epoch), [agent_c]),
            expected_snippet="not registered",
            label="Agent C (unregistered)")

        # ------------------------------------------------------------------
        print("\n[5] Replaying Agent A's nullifier for this epoch...")
        results["replay"] = await expect_denied(
            send(client, ix_log_access(program_id, agent_a.pubkey(), group_id,
                                       action_allowed, epoch), [agent_a]),
            expected_snippet="replay",
            label="Replay of Agent A's access")

        # ------------------------------------------------------------------
        # The scenario that actually tests the traceability property.
        # A forged nullifier is what an adversary would really try: it
        # sidesteps replay detection entirely unless the program checks
        # the derivation.
        print("\n[6] Agent A forging a random nullifier to evade traceability...")
        forged = generate_bytes32()
        results["nullifier_forgery"] = await expect_denied(
            send(client, ix_log_access(program_id, agent_a.pubkey(), group_id,
                                       action_allowed, epoch, nullifier=forged),
                 [agent_a]),
            expected_snippet="not the correct derivation",
            label="Agent A (forged nullifier)")

        # ------------------------------------------------------------------
        print("\n[7] Rogue key attempting privileged operations...")
        rogue_agent = Keypair()
        results["rogue_register"] = await expect_denied(
            send(client, ix_register_agent(program_id, rogue_admin.pubkey(),
                                           rogue_agent.pubkey(), group_id),
                 [rogue_admin]),
            expected_snippet="not the configured protocol administrator",
            label="Rogue admin (register agent)")

        results["rogue_revoke"] = await expect_denied(
            send(client, ix_revoke_agent(program_id, rogue_admin.pubkey(),
                                         agent_a.pubkey()), [rogue_admin]),
            expected_snippet="not the configured protocol administrator",
            label="Rogue admin (revoke agent)")

        # ------------------------------------------------------------------
        print("\n[8] Policy revocation (allow -> deny) takes effect...")
        await send(client, ix_set_policy(program_id, admin.pubkey(), group_id,
                                         action_revocable, True),
                   [admin], "Set Policy (allow)")
        await send(client, ix_update_policy(program_id, admin.pubkey(), group_id,
                                            action_revocable, False),
                   [admin], "Update Policy (deny)")
        results["policy_revocation"] = await expect_denied(
            send(client, ix_log_access(program_id, agent_a.pubkey(), group_id,
                                       action_revocable, epoch), [agent_a]),
            expected_snippet="explicitly denies",
            label="Access after policy flipped to deny")

        # ------------------------------------------------------------------
        # A FRESH action hash is essential here. Anchor evaluates account
        # constraints -- including `init` on trace_log -- before the handler
        # body runs, so reusing action_allowed would fail with "already in
        # use" (replay) rather than AgentRevoked, and the scenario would be
        # silently testing the wrong thing.
        print("\n[9] Revoking Agent A, then retrying access...")
        await send(client, ix_set_policy(program_id, admin.pubkey(), group_id,
                                         action_after_revoke, True),
                   [admin], "Set Policy (allow, pre-revocation)")
        await send(client, ix_revoke_agent(program_id, admin.pubkey(),
                                           agent_a.pubkey()),
                   [admin], "Revoke Agent A")
        results["revoked_agent"] = await expect_denied(
            send(client, ix_log_access(program_id, agent_a.pubkey(), group_id,
                                       action_after_revoke, epoch), [agent_a]),
            expected_snippet="revoked",
            label="Revoked Agent A")

        # ------------------------------------------------------------------
        # Empirical counterpart of the impersonation_resistance lemma.
        #
        # Agent B signs the transaction but presents Agent A's
        # AgentRecord. lib.rs seeds that account on [b"agent",
        # agent.key()], so the record is cryptographically bound to the
        # signer and Anchor rejects the mismatch during ACCOUNT
        # VALIDATION -- before any handler logic runs. That ordering is
        # why A's revoked state at this point is irrelevant to what is
        # being tested.
        #
        # Note this is not a "malformed signature" test: the Solana
        # runtime verifies signatures before the program is invoked, so
        # a bad signature never reaches TAP-A2A. Presenting a valid
        # signature over someone else's identity is the attack the
        # program itself has to defeat.
        print("\n[10] Agent B presenting Agent A's registration (impersonation)...")
        results["impersonation"] = await expect_denied(
            send(client, ix_log_access(program_id, agent_b.pubkey(), group_id,
                                       action_allowed, epoch,
                                       impersonate_as=agent_a.pubkey()),
                 [agent_b]),
            expected_snippet="does not belong to the signing agent",
            label="Agent B impersonating Agent A")

    # ----------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("SCENARIO RESULTS")
    print("=" * 70)
    for name, ok in results.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")

    passed = sum(1 for ok in results.values() if ok)
    total = len(results)
    print(f"\n{passed}/{total} scenarios passed.")

    if passed != total:
        print("SUITE FAILED — do not cite these results in the dissertation.")
        return 1
    print("SUITE PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
