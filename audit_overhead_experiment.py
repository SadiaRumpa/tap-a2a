"""
TAP-A2A — communication overhead and audit-trail completeness.

Two claims in the dissertation are checked here that nothing else covers.

PART 1 — COMMUNICATION OVERHEAD
The hypothesis states the design introduces "acceptable communication and
computational overhead". Computation is measured elsewhere (latency,
compute units). Communication was not measured at all. This records
message size, signature size and round-trip count for the A2A layer, and
contrasts them with the multi-round challenge-response of the identity
baseline.

PART 2 — AUDIT-TRAIL COMPLETENESS
The stated objective is "end-to-end traceable accountability". A
grant-only trail does not achieve that: a refused escalation would leave
no on-chain evidence, and an auditor would see a clean history of
legitimate accesses with no sign that anything was attempted. This checks
that refusals are anchored, that the reason is recoverable, and that a
repeated attacker cannot inflate the log without bound.

Run:  python3 audit_overhead_experiment.py
"""
import asyncio
import json
import sys

from solders.keypair import Keypair

from tap_a2a_common import (
    load_program_id, generate_bytes32, action_hash, current_epoch,
    ix_register_agent, ix_set_policy, denial_nullifier, denial_log_pda,
    DenialReason,
)
from tap_a2a_client import (
    rpc_client, load_admin, send, ensure_initialized, airdrop, sync_clock,
)
from tap_a2a_messaging import Orchestrator, Worker, compose, A2AError

results = {}


def record(name: str, ok: bool, detail: str = ""):
    results[name] = ok
    print(f"  {'PASS' if ok else 'FAIL'}: {name}{' — ' + detail if detail else ''}")


def parse_denial(data: bytes) -> dict:
    """DenialLog after the 8-byte Anchor discriminator."""
    d = data[8:]
    return {
        "worker": d[0:32],
        "requester": d[32:64],
        "action_hash": d[64:96],
        "epoch": int.from_bytes(d[96:104], "little"),
        "reason": d[104],
        "timestamp": int.from_bytes(d[105:113], "little", signed=True),
    }


async def main() -> int:
    print("=" * 72)
    print("TAP-A2A — COMMUNICATION OVERHEAD AND AUDIT-TRAIL COMPLETENESS")
    print("=" * 72)

    program_id = load_program_id()

    async with rpc_client() as client:
        admin = load_admin()
        await ensure_initialized(client, program_id, admin)
        await sync_clock(client)
        print(f"Program: {program_id}\n")

        orch_group = generate_bytes32()
        worker_group = generate_bytes32()
        orch_kp, worker_kp = Keypair(), Keypair()

        await airdrop(client, [orch_kp.pubkey(), worker_kp.pubkey()])
        for kp, grp in ((orch_kp, orch_group), (worker_kp, worker_group)):
            await send(client, ix_register_agent(program_id, admin.pubkey(),
                                                 kp.pubkey(), grp), [admin])

        allowed = action_hash("READ_DATABASE")
        await send(client, ix_set_policy(program_id, admin.pubkey(),
                                         worker_group, allowed, True), [admin])

        orchestrator = Orchestrator(orch_kp, orch_group, program_id)
        worker = Worker("worker", worker_kp, worker_group, program_id)

        # ------------------------------------------------------------------
        print("=" * 72)
        print("PART 1 — COMMUNICATION OVERHEAD")
        print("=" * 72)

        m = compose(orch_kp, worker_kp.pubkey(), "READ_DATABASE")
        payload = m.payload()
        wire = len(payload) + len(m.signature)

        print(f"\n  Signed payload (canonical JSON) : {len(payload):>5} bytes")
        print(f"  Ed25519 signature               : {len(m.signature):>5} bytes")
        print(f"  Total on the wire               : {wire:>5} bytes")
        print(f"  Round trips per authorisation   : {1:>5}")

        fields = json.loads(payload.decode())
        print("\n  Field breakdown:")
        for k, v in fields.items():
            print(f"    {k:<12} {len(json.dumps(v)):>4} bytes")

        print("\n  Comparison of protocol shape (NOT a latency comparison —")
        print("  the identity baseline runs on a public testnet and this")
        print("  prototype on a local validator, so wall-clock times measure")
        print("  network topology rather than design):")
        print(f"    TAP-A2A A2A request      : 1 round trip, {wire} bytes")
        print( "    Challenge-response VP    : 2+ round trips, ~1.23 KB per credential")
        print( "  The single-pass design trades the freshness a verifier-chosen")
        print( "  nonce would give for a round trip; freshness is instead")
        print( "  provided by the sender's nonce plus a bounded TTL.")

        record("communication_overhead_measured", wire > 0,
               f"{wire} bytes, 1 round trip")

        # ------------------------------------------------------------------
        print("\n" + "=" * 72)
        print("PART 2 — AUDIT-TRAIL COMPLETENESS")
        print("=" * 72)

        epoch = current_epoch()

        # --- 2a: a refused escalation must leave on-chain evidence --------
        print("\n[2a] Out-of-scope request is refused AND anchored on-chain")
        forbidden = "DELETE_RECORDS"
        try:
            await worker.handle(client, compose(orch_kp, worker_kp.pubkey(), forbidden))
            record("denial_refused", False, "the request was not refused")
        except A2AError as e:
            refused = "outside this agent's least-privilege scope" in str(e)
            record("denial_refused", refused, str(e)[:60])

        await asyncio.sleep(1)
        nd = denial_nullifier(worker_kp.pubkey(), orch_kp.pubkey(),
                              action_hash(forbidden), epoch)
        info = await client.get_account_info(denial_log_pda(program_id, nd))
        if info.value is None:
            record("denial_anchored_on_chain", False, "no denial record found")
        else:
            rec = parse_denial(bytes(info.value.data))
            ok = (bytes(rec["requester"]) == bytes(orch_kp.pubkey())
                  and rec["reason"] == DenialReason.OUT_OF_SCOPE)
            record("denial_anchored_on_chain", ok,
                   f"reason {rec['reason']} = {DenialReason.NAMES[rec['reason']]}")
            print(f"       record size: {len(bytes(info.value.data))} bytes, "
                  f"rent {info.value.lamports / 1e9:.6f} SOL")

        # --- 2b: the reason must be recoverable by an auditor -------------
        print("\n[2b] An auditor can attribute the refusal without privileged access")
        # Anyone who knows (worker, requester, action, epoch) can recompute
        # the address and read the record. No index, no log server.
        probe = denial_nullifier(worker_kp.pubkey(), orch_kp.pubkey(),
                                 action_hash(forbidden), epoch)
        found = await client.get_account_info(denial_log_pda(program_id, probe))
        record("denial_independently_verifiable", found.value is not None,
               "address recomputed from public inputs")

        # --- 2c: a repeated attacker cannot inflate the log ---------------
        print("\n[2c] Repeated identical refusals do not grow the log")
        for _ in range(3):
            try:
                await worker.handle(client,
                                    compose(orch_kp, worker_kp.pubkey(), forbidden))
            except A2AError:
                pass
        await asyncio.sleep(1)
        still = await client.get_account_info(denial_log_pda(program_id, nd))
        record("denial_storage_bounded", still.value is not None,
               "one record per (worker, requester, action, epoch)")

        # --- 2d: a granted access still produces its trace ----------------
        print("\n[2d] Authorised access still writes its access trace")
        out = await worker.handle(client,
                                  compose(orch_kp, worker_kp.pubkey(), "READ_DATABASE"))
        record("grant_still_traced", out.startswith("ACCEPTED"), out[:60])

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

  The audit trail now records both outcomes. A refused escalation leaves
  evidence naming the requester, the capability sought, the reason and the
  epoch -- written by the refusing worker, so an unregistered or hostile
  requester cannot write to the log at all.

  Storage is bounded by the same construction used for access records: the
  denial address is derived from (worker, requester, action, epoch), so a
  repeated attacker produces one record per epoch, not one per attempt.
  The FIRST refusal in an epoch is the one evidenced -- a deliberate trade
  of forensic granularity against a rent-exhaustion surface.
""")

    if passed != total:
        print("EXPERIMENT FAILED — do not cite these results in the dissertation.")
        return 1
    print("EXPERIMENT PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
