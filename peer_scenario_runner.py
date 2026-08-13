"""
TAP-A2A — peer-to-peer agent communication.

Objective 3 in full: agents communicating WITH EACH OTHER under
least-privilege policy, not merely receiving dispatch from a central
orchestrator.

WHY THE TOPOLOGY MATTERS
------------------------
A star topology -- one orchestrator, many workers, no lateral traffic --
has a simple security story: only the orchestrator sends, so only the
orchestrator need be authenticated.

Once workers message each other directly, that story breaks in a specific
way. A worker checking only its OWN policy scope will act on any
capability it holds, for anyone who asks. A low-privilege agent can
therefore ask a high-privilege peer to do something the requester is not
authorised for, and the peer complies. The requester has borrowed
authority it was never granted: the CONFUSED DEPUTY.

This suite demonstrates the pipeline working, demonstrates the attack the
topology introduces, and demonstrates the defence.

Run:  python3 peer_scenario_runner.py
"""
import asyncio
import sys

from solders.keypair import Keypair

from tap_a2a_common import (
    load_program_id, generate_bytes32, action_hash,
    ix_register_agent, ix_set_policy,
)
from tap_a2a_client import (
    rpc_client, load_admin, send, ensure_initialized, airdrop, sync_clock,
)
from tap_a2a_messaging import A2AError, Orchestrator, Worker

results = {}


def record(name: str, ok: bool, detail: str = ""):
    results[name] = ok
    print(f"  {'PASS' if ok else 'FAIL'}: {name}{' — ' + detail if detail else ''}")


async def main() -> int:
    print("=" * 72)
    print("TAP-A2A — PEER-TO-PEER AGENT COMMUNICATION")
    print("=" * 72)

    program_id = load_program_id()

    async with rpc_client() as client:
        admin = load_admin()
        await ensure_initialized(client, program_id, admin)
        await sync_clock(client)
        print(f"Program: {program_id}\n")

        # --------------------------------------------------------------
        # Three capability groups, deliberately unequal.
        #   reader  : READ_DATABASE only
        #   writer  : WRITE_REPORT only
        #   archiver: WRITE_REPORT and EXPORT_PII  (the privileged peer)
        # --------------------------------------------------------------
        orch_group = generate_bytes32()
        reader_group = generate_bytes32()
        writer_group = generate_bytes32()
        archiver_group = generate_bytes32()

        orch_kp = Keypair()
        reader_kp, writer_kp, archiver_kp = Keypair(), Keypair(), Keypair()

        await airdrop(client, [k.pubkey() for k in
                               (orch_kp, reader_kp, writer_kp, archiver_kp)])

        for kp, grp in ((orch_kp, orch_group), (reader_kp, reader_group),
                        (writer_kp, writer_group), (archiver_kp, archiver_group)):
            await send(client, ix_register_agent(program_id, admin.pubkey(),
                                                 kp.pubkey(), grp), [admin])

        for grp, cap in ((reader_group, "READ_DATABASE"),
                         (writer_group, "WRITE_REPORT"),
                         (archiver_group, "WRITE_REPORT"),
                         (archiver_group, "EXPORT_PII")):
            await send(client, ix_set_policy(program_id, admin.pubkey(), grp,
                                             action_hash(cap), True), [admin])

        orchestrator = Orchestrator(orch_kp, orch_group, program_id)
        reader = Worker("reader", reader_kp, reader_group, program_id)
        writer = Worker("writer", writer_kp, writer_group, program_id)
        archiver = Worker("archiver", archiver_kp, archiver_group, program_id)

        print("  reader   -> READ_DATABASE")
        print("  writer   -> WRITE_REPORT")
        print("  archiver -> WRITE_REPORT, EXPORT_PII   (privileged peer)")
        print("  (reader holds NO write or export capability)\n")

        # --------------------------------------------------------------
        print("=" * 72)
        print("PART 1 — A PEER-TO-PEER PIPELINE")
        print("=" * 72)
        print("The orchestrator starts the work; the reader then hands its")
        print("output DIRECTLY to the writer without routing back through")
        print("the orchestrator.\n")

        print("[1a] orchestrator -> reader : READ_DATABASE")
        out = await orchestrator.send_to(client, reader, "READ_DATABASE")
        record("orchestrator_to_reader", out.startswith("ACCEPTED"), out[:64])

        print("\n[1b] reader -> writer : WRITE_REPORT, carrying the read result")
        out = await reader.send_to(client, writer, "WRITE_REPORT",
                                   result="rows=1042,digest=a91f")
        ok = out.startswith("ACCEPTED") and "using input from" in out
        record("peer_to_peer_handoff", ok, out[:80])
        print("       The result is inside the signed envelope, so the")
        print("       writer can attribute the input to the reader.")

        # --------------------------------------------------------------
        print("\n" + "=" * 72)
        print("PART 2 — THE CONFUSED DEPUTY")
        print("=" * 72)

        print("\n[2a] reader -> archiver : EXPORT_PII  (default worker policy)")
        print("     The reader holds no export capability. The archiver does.")
        print("     A worker that checks only its own scope will comply.")
        out = await reader.send_to(client, archiver, "EXPORT_PII")
        deputised = out.startswith("ACCEPTED")
        record("confused_deputy_reproduced", deputised,
               "archiver acted for an unauthorised requester" if deputised
               else f"unexpectedly refused: {out[:60]}")
        if deputised:
            print("       The reader has exercised EXPORT_PII through a peer.")
            print("       Least privilege held for each agent individually and")
            print("       still failed for the system.")

        print("\n[2b] Same request, archiver enforcing requester scope")
        strict = Worker("archiver_strict", archiver_kp, archiver_group,
                        program_id, require_requester_scope=True)
        out = await reader.send_to(client, strict, "EXPORT_PII")
        blocked = "refusing to act as its deputy" in out
        record("confused_deputy_blocked", blocked, out[:80])

        print("\n[2c] A legitimate peer request still succeeds under the check")
        # The writer holds WRITE_REPORT, so asking the archiver for it is
        # not borrowed authority -- the check must not block genuine work.
        out = await writer.send_to(client, strict, "WRITE_REPORT",
                                   result="draft=v2")
        record("legitimate_peer_request_allowed", out.startswith("ACCEPTED"),
               out[:70])

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

  Part 1 shows agents communicating directly: the reader hands its output
  to the writer inside a signed envelope, and the writer applies the same
  verification it would to any sender. There is no privileged party.

  Part 2 is the finding. Moving from star dispatch to peer-to-peer
  communication introduces the confused deputy: per-agent least privilege
  is individually intact and collectively insufficient, because a worker
  that checks only its own scope lends its authority to whoever asks.
  Requiring the REQUESTER to hold the capability closes it, at the cost of
  making genuine privilege delegation impossible -- an honest trade for a
  system that dispatches rather than delegates.

  Note 2a is expected to SUCCEED. Reporting the attack working under the
  default configuration is the point; a suite that only showed the
  defended case would not establish that the defence does anything.
""")

    if passed != total:
        print("SUITE FAILED — do not cite these results in the dissertation.")
        return 1
    print("SUITE PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
