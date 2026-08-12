
import asyncio
import json
import os
import time
from pathlib import Path

from solders.keypair import Keypair
from solders.message import Message
from solders.transaction import VersionedTransaction
from solana.rpc.async_api import AsyncClient
from solana.rpc.commitment import Commitment

from tap_a2a_common import (
    RPC_URL, CLOCK_SYSVAR, CLOCK_UNIX_TIMESTAMP_OFFSET,
    config_pda, classify_error, ix_initialize, set_clock_offset,
)

# ----------------------------------------------------------------------
# Commitment level. THIS IS A MEASUREMENT-CRITICAL SETTING.
#
# solana-py defaults to `finalized`, which waits ~31 slots (~13s on a
# local validator) before returning. Benchmarking against that default
# measures Solana's finality clock, not the access decision -- it
# produced an on-chain decision latency of ~17,000 ms where the actual
# program execution is a few hundred milliseconds.
#
# `confirmed` (supermajority vote, one slot) is what production clients
# treat as the actionable point and is the honest default here. The
# access decision itself is already enforced at `processed` -- the
# program has run and either allowed or rejected -- so `confirmed` is a
# conservative choice rather than an optimistic one.
#
# Override with TAP_A2A_COMMITMENT=finalized to measure the
# irreversibility upper bound. Chapter 6 should report both and explain
# the difference: it is a genuine security/performance trade-off
# (revert risk vs latency), not a tuning knob.
# ----------------------------------------------------------------------
COMMITMENT = Commitment(os.environ.get("TAP_A2A_COMMITMENT", "confirmed"))


def rpc_client() -> AsyncClient:

    return AsyncClient(RPC_URL, commitment=COMMITMENT)


def load_admin() -> Keypair:
    path = Path.home() / ".config" / "solana" / "id.json"
    return Keypair.from_bytes(bytes(json.loads(path.read_text())))


async def send(client: AsyncClient, instruction, signers, label: str = None):
    """Send one instruction and return (signature, latency_ms, compute_units)."""
    blockhash = (await client.get_latest_blockhash()).value.blockhash
    msg = Message.new_with_blockhash([instruction], signers[0].pubkey(), blockhash)
    tx = VersionedTransaction(msg, signers)

    start = time.perf_counter()
    sig = (await client.send_transaction(tx)).value
    await client.confirm_transaction(sig, commitment=COMMITMENT)
    latency_ms = (time.perf_counter() - start) * 1000

    details = await client.get_transaction(sig, encoding="json", max_supported_transaction_version=0)
    cus = 0
    if details.value and details.value.transaction.meta:
        cus = details.value.transaction.meta.compute_units_consumed or 0

    if label:
        print(f"    [{label}] Latency: {latency_ms:.2f} ms | CUs: {cus}")
    return sig, latency_ms, cus



async def sync_clock(client) -> float:

    info = await client.get_account_info(CLOCK_SYSVAR)
    if info.value is None:
        return 0.0
    data = bytes(info.value.data)
    chain_time = int.from_bytes(
        data[CLOCK_UNIX_TIMESTAMP_OFFSET:CLOCK_UNIX_TIMESTAMP_OFFSET + 8],
        "little", signed=True)
    offset = chain_time - time.time()
    set_clock_offset(offset)
    return offset

async def ensure_initialized(client: AsyncClient, program_id, admin: Keypair) -> bool:

    cfg = config_pda(program_id)
    existing = await client.get_account_info(cfg)
    if existing.value is not None:
        print(f"Protocol already initialised (config {cfg}).")
        return False

    print(f"Initialising protocol with admin {admin.pubkey()}...")
    try:
        await send(client, ix_initialize(program_id, admin.pubkey()), [admin])
        print("Protocol initialised.")
        return True
    except Exception as e:
        if "already in use" in str(e):
            print("Protocol already initialised (race).")
            return False
        raise


async def airdrop(client: AsyncClient, pubkeys, lamports: int = 1_000_000_000,
                  settle_seconds: float = 2.0):
    for pk in pubkeys:
        await client.request_airdrop(pk, lamports)
    await asyncio.sleep(settle_seconds)


async def expect_denied(coro, expected_snippet: str, label: str) -> bool:

    try:
        await coro
        print(f"  FAIL: {label} was NOT blocked (a denial was expected).")
        return False
    except Exception as e:
        classification = classify_error(e)
        if expected_snippet.lower() in classification.lower():
            print(f"  PASS: {label} blocked -> {classification}")
            return True
        print(f"  FAIL: {label} blocked for the WRONG reason -> {classification}")
        return False
