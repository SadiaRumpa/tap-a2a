"""
TAP-A2A — A2A message layer security scenarios.

Evidence for objective 3: secure agent-to-agent communication under the
least-privilege policies of objective 2.

Seven scenarios. One legitimate exchange, six attacks that must be
refused. Each attack targets a different check, so a single failing
mechanism cannot be masked by another.

Exit code is 0 only if every scenario behaves as expected.

Run:  python3 a2a_scenario_runner.py
"""
import asyncio
import sys
import time

from solders.keypair import Keypair

from tap_a2a_common import (
    load_program_id, generate_bytes32, action_hash,
    ix_register_agent, ix_set_policy, ix_revoke_agent,
)
from tap_a2a_client import (
    rpc_client, load_admin, send, ensure_initialized, airdrop, sync_clock,
)
from tap_a2a_messaging import (
    A2AError, Orchestrator, Worker, compose,
)

results = {}


def record(name: str, ok: bool, detail: str = ""):
    results[name] = ok
    print(f"  {'PASS' if ok else 'FAIL'}: {name}{' — ' + detail if detail else ''}")


async def expect_rejected(coro, snippet: str, name: str):
    """A scenario passes when the message is refused for the RIGHT reason."""
    try:
        out = await coro
    except A2AError as e:
        out = str(e)
    if snippet.lower() in out.lower():
        record(name, True, out.split("—")[0].strip()[:70])
    else:
        record(name, False, f"unexpected outcome: {out[:90]}")


async def main() -> int:
    print("=" * 70)
    print("TAP-A2A — A2A MESSAGE LAYER SCENARIOS")
    print("=" * 70)

    program_id = load_program_id()

    async with rpc_client() as client:
        admin = load_admin()
        await ensure_initialized(client, program_id, admin)
        await sync_clock(client)   # align epochs with the chain's clock
        print(f"Program: {program_id}\n")

        # ------------------------------------------------------------------
        # Provisioning. The orchestrator and the workers sit in DIFFERENT
        # groups: the orchestrator holds no data capabilities of its own,
        # which is the point of the separation.
        # ------------------------------------------------------------------
        orch_group = generate_bytes32()
        reader_group = generate_bytes32()
        writer_group = generate_bytes32()

        orch_kp, reader_kp, writer_kp = Keypair(), Keypair(), Keypair()
        rogue_kp = Keypair()          # never registered on-chain
        revoked_kp = Keypair()        # registered, then revoked

        await airdrop(client, [k.pubkey() for k in
                               (orch_kp, reader_kp, writer_kp, rogue_kp, revoked_kp)])

        for kp, grp in ((orch_kp, orch_group), (reader_kp, reader_group),
                        (writer_kp, writer_group), (revoked_kp, orch_group)):
            await send(client, ix_register_agent(program_id, admin.pubkey(),
                                                 kp.pubkey(), grp), [admin])

        # Least privilege: reader may READ_DATABASE, writer may WRITE_REPORT.
        # Neither may DELETE_RECORDS — no policy is ever created for it.
        await send(client, ix_set_policy(program_id, admin.pubkey(), reader_group,
                                         action_hash("READ_DATABASE"), True), [admin])
        await send(client, ix_set_policy(program_id, admin.pubkey(), writer_group,
                                         action_hash("WRITE_REPORT"), True), [admin])

        await send(client, ix_revoke_agent(program_id, admin.pubkey(),
                                           revoked_kp.pubkey()), [admin])

        orchestrator = Orchestrator(orch_kp, orch_group, program_id)
        reader = Worker("reader", reader_kp, reader_group, program_id)
        writer = Worker("writer", writer_kp, writer_group, program_id)

        print("  orchestrator, reader, writer registered")
        print("  reader -> READ_DATABASE | writer -> WRITE_REPORT")
        print("  (no policy exists for DELETE_RECORDS in any group)\n")

        # ------------------------------------------------------------------
        print("[1] Legitimate dispatch to a worker within its scope")
        out = await orchestrator.send_to(client, reader, "READ_DATABASE")
        record("legitimate_dispatch", out.startswith("ACCEPTED"), out[:70])

        # ------------------------------------------------------------------
        print("\n[2] Capability outside the receiving worker's scope")
        # The orchestrator asks the reader to delete records. No policy
        # exists, so the worker refuses before touching the chain -- a
        # compromised orchestrator cannot widen a worker's authority.
        await expect_rejected(
            orchestrator.send_to(client, reader, "DELETE_RECORDS"),
            "outside this agent's least-privilege scope",
            "capability_outside_scope")

        # ------------------------------------------------------------------
        print("\n[3] Cross-scope dispatch (reader asked to do writer's job)")
        await expect_rejected(
            orchestrator.send_to(client, reader, "WRITE_REPORT"),
            "outside this agent's least-privilege scope",
            "cross_scope_dispatch")

        # ------------------------------------------------------------------
        print("\n[4] Forged signature")
        msg = compose(orch_kp, writer.keypair.pubkey(), "WRITE_REPORT")
        msg.capability = "DELETE_RECORDS"   # tampered after signing
        await expect_rejected(
            writer.handle(client, msg),
            "signature does not verify",
            "forged_signature")

        # ------------------------------------------------------------------
        print("\n[5] Sender not registered on-chain")
        # A perfectly valid signature from a key nobody registered. Proves
        # key possession, not authorisation to participate.
        rogue_msg = compose(rogue_kp, writer.keypair.pubkey(), "WRITE_REPORT")
        await expect_rejected(
            writer.handle(client, rogue_msg),
            "not a registered agent",
            "unregistered_sender")

        # ------------------------------------------------------------------
        print("\n[6] Sender revoked on-chain")
        revoked_msg = compose(revoked_kp, writer.keypair.pubkey(), "WRITE_REPORT")
        await expect_rejected(
            writer.handle(client, revoked_msg),
            "revoked",
            "revoked_sender")

        # ------------------------------------------------------------------
        print("\n[7] Expired message")
        stale = compose(orch_kp, writer.keypair.pubkey(), "WRITE_REPORT", ttl=-1)
        await expect_rejected(
            writer.handle(client, stale),
            "expired",
            "expired_message")

        # ------------------------------------------------------------------
        print("\n[8] Replayed message")
        # Capture a message the writer already accepted and resend it.
        replay = compose(orch_kp, writer.keypair.pubkey(), "WRITE_REPORT")
        first = await writer.handle(client, replay)
        if not first.startswith("ACCEPTED"):
            record("replayed_message", False, f"setup failed: {first[:70]}")
        else:
            await expect_rejected(
                writer.handle(client, replay),
                "replayed message",
                "replayed_message")

        # ------------------------------------------------------------------
        print("\n[9] Message addressed to a different agent")
        misdirected = compose(orch_kp, reader.keypair.pubkey(), "READ_DATABASE")
        await expect_rejected(
            writer.handle(client, misdirected),
            "addressed to a different agent",
            "misdirected_message")

    print("\n" + "=" * 70)
    print("A2A SCENARIO RESULTS")
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
