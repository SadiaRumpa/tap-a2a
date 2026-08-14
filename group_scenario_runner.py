"""
TAP-A2A — group authentication scenarios.

Evidence for the construction flagged in the first supervision: group
authentication with one-time traceable ring signatures for multi-agents.

WHAT IS BEING DEMONSTRATED
--------------------------
A member authenticates as SOMEONE in the group without revealing which.
The on-chain record carries no agent public key. If a member acts twice
under the same issue, the algebra identifies it and the verifier publishes
the identity on-chain -- nobody is trusted to reveal the signer, and
nobody can suppress it either.

Contrast with the deterministic-nullifier protocol, which is fully
attributable and fully on-chain. Neither dominates: one buys anonymity at
the cost of off-chain one-time enforcement, the other buys on-chain
enforcement at the cost of attributing every access.

Run:  python3 group_scenario_runner.py
"""
import asyncio
import sys

from solders.keypair import Keypair

from tap_a2a_common import (
    load_program_id, generate_bytes32, action_hash, current_epoch,
    ix_register_agent, ix_set_policy, ix_register_group_ring,
    ix_log_group_access, ix_log_traced_signer,
    group_access_pda, trace_event_pda, classify_error,
)
from tap_a2a_client import (
    rpc_client, load_admin, send, ensure_initialized, airdrop, sync_clock,
)
from tap_a2a_trs import keygen
from tap_a2a_group import (
    GroupMember, GroupVerifier, GroupAuthError, ring_hash,
)

RING_SIZE = 5
results = {}


def record(name: str, ok: bool, detail: str = ""):
    results[name] = ok
    print(f"  {'PASS' if ok else 'FAIL'}: {name}{' — ' + detail if detail else ''}")


async def main() -> int:
    print("=" * 72)
    print("TAP-A2A — GROUP AUTHENTICATION (TRACEABLE RING SIGNATURES)")
    print("=" * 72)

    program_id = load_program_id()

    async with rpc_client() as client:
        admin = load_admin()
        await ensure_initialized(client, program_id, admin)
        await sync_clock(client)
        print(f"Program: {program_id}\n")

        group_id = generate_bytes32()
        action = action_hash("READ_DATABASE")
        epoch = current_epoch()

        # Ring keys are the TRS identities of the group's members. They are
        # separate from the Solana keypairs used to pay fees: the whole
        # point is that the member never signs the transaction itself.
        members = [keygen() for _ in range(RING_SIZE)]
        ring = [pk for _, pk in members]

        await send(client, ix_set_policy(program_id, admin.pubkey(), group_id,
                                         action, True), [admin])
        await send(client, ix_register_group_ring(
            program_id, admin.pubkey(), group_id, ring_hash(ring), RING_SIZE),
            [admin])

        print(f"  Ring published: {RING_SIZE} members, commitment on-chain")
        print(f"  Group policy  : READ_DATABASE allowed")
        print(f"  Verifier      : {admin.pubkey()} (admin by default)\n")

        verifier = GroupVerifier(admin, program_id, ring,
                                 expected_ring_hash=ring_hash(ring))
        m2 = GroupMember("member_2", members[2][0], members[2][1], ring, 2, group_id)
        m4 = GroupMember("member_4", members[4][0], members[4][1], ring, 4, group_id)

        # --------------------------------------------------------------
        print("=" * 72)
        print("PART 1 — ANONYMOUS AUTHENTICATION")
        print("=" * 72)

        print("\n[1a] A member authenticates and the access is logged anonymously")
        outcome, commitment = verifier.verify_request(
            m2.authenticate(action, epoch, "req-1"))
        if outcome != "accepted":
            record("anonymous_access", False, f"verifier said {outcome}")
        else:
            await send(client, ix_log_group_access(
                program_id, admin.pubkey(), group_id, action, commitment, epoch),
                [admin])
            info = await client.get_account_info(
                group_access_pda(program_id, commitment))
            record("anonymous_access", info.value is not None,
                   f"{len(bytes(info.value.data))} bytes on-chain")

            # The record must not contain any member's public key.
            raw = bytes(info.value.data)
            leaked = [i for i, pk in enumerate(ring) if bytes(pk) in raw]
            record("signer_identity_not_on_chain", not leaked,
                   "no ring member's key appears in the record" if not leaked
                   else f"LEAKED index {leaked}")

        print("\n[1b] A different member authenticates — still anonymous, unlinked")
        outcome, commitment = verifier.verify_request(
            m4.authenticate(action, epoch, "req-2"))
        ok = outcome == "accepted"
        if ok:
            await send(client, ix_log_group_access(
                program_id, admin.pubkey(), group_id, action, commitment, epoch),
                [admin])
        record("second_member_independent", ok,
               "traced as independent, not linked to the first")

        # --------------------------------------------------------------
        print("\n" + "=" * 72)
        print("PART 2 — ONE-TIME USE AND TRACING")
        print("=" * 72)

        print("\n[2a] member_2 signs the SAME issue a second time")
        outcome, detail = verifier.verify_request(
            m2.authenticate(action, epoch, "req-3"))
        traced = outcome == "traced"
        record("double_use_traced", traced,
               f"identified index {detail[0]} (member_2 is index 2)" if traced
               else f"verifier said {outcome}")

        if traced:
            index, pubkey = detail
            print("\n[2b] The traced identity is published on-chain")
            # A Solana pubkey field is used to carry the 32-byte ring key,
            # which is what identifies the member within the ring.
            from solders.pubkey import Pubkey as _Pk
            await send(client, ix_log_traced_signer(
                program_id, admin.pubkey(), group_id, action, epoch,
                _Pk(bytes(pubkey))), [admin])
            info = await client.get_account_info(
                trace_event_pda(program_id, group_id, action, epoch))
            found = info.value is not None and bytes(pubkey) in bytes(info.value.data)
            record("trace_event_on_chain", found,
                   "identity now attributable and auditable")

        print("\n[2c] member_2 signs a DIFFERENT issue — anonymity restored")
        outcome, _ = verifier.verify_request(
            m2.authenticate(action, epoch + 1, "req-4"))
        record("different_issue_anonymous", outcome == "accepted",
               "a later epoch is a new issue, so single use is anonymous again")

        # --------------------------------------------------------------
        print("\n" + "=" * 72)
        print("PART 3 — REFUSALS")
        print("=" * 72)

        print("\n[3a] A non-member cannot produce a valid signature")
        out_sk, out_pk = keygen()
        forged = False
        try:
            outsider = GroupMember("outsider", out_sk, out_pk, ring, 0, group_id)
            verifier.verify_request(outsider.authenticate(action, epoch, "x"))
            forged = True
        except (ValueError, GroupAuthError):
            forged = False
        record("non_member_refused", not forged,
               "membership cannot be asserted without a ring secret")

        print("\n[3b] A substituted ring is refused")
        small = GroupVerifier(admin, program_id, ring[:2],
                              expected_ring_hash=ring_hash(ring))
        try:
            small.verify_request(m2.authenticate(action, epoch + 2, "y"))
            record("ring_substitution_refused", False, "substitution accepted")
        except GroupAuthError as e:
            record("ring_substitution_refused", True, str(e)[:52])

        print("\n[3c] An unauthorised submitter cannot write a group record")
        # Use the CURRENT epoch. An out-of-window epoch would also be
        # refused, but by the epoch check rather than the authorisation
        # check -- the scenario would pass while testing the wrong thing.
        rogue = Keypair()
        await airdrop(client, [rogue.pubkey()])

        # A member who has NOT yet signed this issue. Reusing member_2 or
        # member_4 here would be a second signature under the same issue,
        # so the verifier would (correctly) trace it instead of returning
        # a commitment -- and this scenario would fail for a reason that
        # has nothing to do with verifier authorisation.
        m0 = GroupMember("member_0", members[0][0], members[0][1], ring, 0, group_id)
        outcome, commitment = verifier.verify_request(
            m0.authenticate(action, epoch, "z"))
        if outcome != "accepted":
            record("rogue_verifier_refused", False,
                   f"setup failed: verifier returned '{outcome}'")
            commitment = None

        try:
            if commitment is None:
                raise RuntimeError("no commitment to submit")
            await send(client, ix_log_group_access(
                program_id, rogue.pubkey(), group_id, action, commitment,
                epoch), [rogue])
            record("rogue_verifier_refused", False, "rogue submission accepted")
        except Exception as e:
            msg = classify_error(e)
            record("rogue_verifier_refused", "verifier" in msg.lower(), msg[:60])

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

  A member proves group membership without revealing which member: the
  on-chain record contains no agent key, only the group, the action, the
  epoch and a commitment to the signature.

  Acting twice under one issue forfeits that anonymity automatically. No
  authority decides to reveal the signer and none can prevent it — the
  identity falls out of comparing the two signatures, and the verifier
  publishes it so the finding is auditable rather than private to the
  verifier.

  The cost is that one-time enforcement cannot be on-chain. An FS-TRS
  signature yields no per-signer value extractable from one signature, so
  the chain cannot deduplicate without learning who signed. This is a
  property of the scheme, not of the implementation, and it is the reason
  the deterministic-nullifier protocol remains the enforced path while
  this one provides anonymity where that matters more.
""")

    if passed != total:
        print("SUITE FAILED — do not cite these results in the dissertation.")
        return 1
    print("SUITE PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
