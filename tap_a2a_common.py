"""
Shared utilities for the TAP-A2A evaluation suite.

Single source of truth for PDA derivation, instruction encoding,
nullifier derivation and error classification. MUST be kept in sync
with programs/tap_a2a/src/lib.rs.

CHANGED IN THIS REVISION
------------------------
1. Nullifier derivation now mirrors the on-chain check exactly and is
   built from the agent's PUBLIC key, not its secret key. The program
   recomputes it and rejects any other value, so an agent can no longer
   evade traceability by supplying random bytes.

2. Terminology: the old name `generate_trs_nullifier` implied a
   traceable ring signature. There is no ring and no anonymity set in
   this system -- the agent signs its own transaction and its public key
   is stored in the trace log. It is now `access_nullifier`, which is
   what it actually is.

3. Added the Config PDA, the `epoch` argument, and error codes
   6005-6007 introduced by the authority and nullifier fixes.
"""
import hashlib
import os
import re
import struct
import time
from pathlib import Path

from solders.instruction import AccountMeta, Instruction
from solders.pubkey import Pubkey
from solders.system_program import ID as SYS_PROGRAM_ID

RPC_URL = "http://127.0.0.1:8899"

# Solana's Clock sysvar. Layout: slot(8) epoch_start_timestamp(8)
# epoch(8) leader_schedule_epoch(8) unix_timestamp(8) -- so the wall
# clock the program sees sits at byte offset 32.
CLOCK_SYSVAR = Pubkey.from_string("SysvarC1ock11111111111111111111111111111111")
CLOCK_UNIX_TIMESTAMP_OFFSET = 32

# Must equal EPOCH_SECONDS in lib.rs.
EPOCH_SECONDS = 3600


# ----------------------------------------------------------------------
# Anchor custom error codes.
# Must match the #[error_code] enum in lib.rs IN DECLARATION ORDER --
# Anchor assigns codes from 6000 in the order variants are declared.
# ----------------------------------------------------------------------
class ErrorCode:
    AGENT_REVOKED = 6000            # 0x1770
    POLICY_DENIED = 6001            # 0x1771
    AGENT_ALREADY_REVOKED = 6002    # 0x1772
    POLICY_GROUP_MISMATCH = 6003    # 0x1773 (unreachable; PDA seeds enforce)
    POLICY_ACTION_MISMATCH = 6004   # 0x1774 (unreachable; PDA seeds enforce)
    INVALID_NULLIFIER = 6005        # 0x1775
    INVALID_EPOCH = 6006            # 0x1776
    UNAUTHORIZED_ADMIN = 6007       # 0x1777
    INVALID_DENIAL_REASON = 6008    # 0x1778


def load_program_id(anchor_toml_path: str = "Anchor.toml") -> Pubkey:
    """Always read the program id live. No script should hardcode one."""
    text = Path(anchor_toml_path).read_text()
    match = re.search(r'tap_a2a\s*=\s*"([^"]+)"', text)
    if not match:
        raise ValueError(f"Could not find tap_a2a program id in {anchor_toml_path}")
    return Pubkey.from_string(match.group(1))


def discriminator(name: str) -> bytes:
    return hashlib.sha256(f"global:{name}".encode()).digest()[:8]


def serialize_u8_array_32(arr) -> bytes:
    b = bytes(arr)
    if len(b) != 32:
        raise ValueError(f"Expected exactly 32 bytes, got {len(b)}")
    return b


def serialize_bool(flag: bool) -> bytes:
    return struct.pack("<?", flag)


def serialize_u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def serialize_pubkey(pk: Pubkey) -> bytes:
    return bytes(pk)


def generate_bytes32() -> list:
    return list(os.urandom(32))


# ----------------------------------------------------------------------
# Epoch and nullifier.
#
# lib.rs computes:
#     sha256("tap-a2a-nullifier" || agent_pubkey || group_id
#            || action_hash || epoch_le)
# and rejects the instruction unless the supplied nullifier matches.
# This function must produce byte-identical output.
#
# Because the derivation uses only public inputs, the nullifier is
# publicly computable. That is intentional: the design provides
# accountability, not anonymity. Anonymity would require a real
# linkable/traceable ring signature with the key image derived from the
# secret key and a membership proof verified on-chain.
# ----------------------------------------------------------------------
# Offset between this machine's wall clock and the chain's clock, in
# seconds. Set by tap_a2a_client.sync_clock() once per run.
#
# WHY THIS EXISTS. lib.rs derives the current epoch from Clock::get(),
# which on solana-test-validator advances with SLOT PROGRESSION rather
# than wall time. A validator left running drifts behind real time, and a
# client computing the epoch from time.time() eventually lands in a
# different bucket. The on-chain grace window is deliberately asymmetric
# -- it accepts a client one epoch BEHIND (absorbing propagation delay)
# but not one AHEAD (which would let an agent pre-compute nullifiers for
# future epochs) -- so a drifting validator rejects every request with
# InvalidEpoch. Reading the chain's own clock removes the assumption that
# the two agree.
_CLOCK_OFFSET = 0.0


def set_clock_offset(offset: float) -> None:
    global _CLOCK_OFFSET
    _CLOCK_OFFSET = offset


def current_epoch(now: float = None) -> int:
    """Current access epoch, as the CHAIN would compute it."""
    t = now if now is not None else time.time() + _CLOCK_OFFSET
    return int(t) // EPOCH_SECONDS


# Denial reason codes. Must match the doc comment on DenialLog in lib.rs.
class DenialReason:
    OUT_OF_SCOPE = 1        # capability outside the worker's policy scope
    POLICY_DENIES = 2       # policy exists and explicitly denies
    NOT_REGISTERED = 3      # requester is not a registered agent
    REVOKED = 4             # requester revoked on-chain
    EXPIRED = 5             # message past its expiry
    REPLAYED = 6            # nonce already seen
    BAD_SIGNATURE = 7       # signature verification failed

    NAMES = {1: "capability outside worker scope", 2: "policy denies action",
             3: "requester not registered", 4: "requester revoked",
             5: "message expired", 6: "message replayed",
             7: "signature invalid"}


def denial_nullifier(worker: Pubkey, requester: Pubkey, action_hash_bytes,
                     epoch: int) -> list:
    """
    N_d = SHA256("tap-a2a-denial" || worker || requester || action || epoch_le)

    Recomputed on-chain, and used as the denial record's PDA seed, so a
    worker files at most one denial per (worker, requester, action, epoch).
    That bounds how much log a repeated attacker can cause to be written.
    """
    payload = (b"tap-a2a-denial" + bytes(worker) + bytes(requester)
               + bytes(action_hash_bytes) + serialize_u64(epoch))
    return list(hashlib.sha256(payload).digest())


def denial_log_pda(program_id: Pubkey, nullifier) -> Pubkey:
    pda, _ = Pubkey.find_program_address([b"denial", bytes(nullifier)], program_id)
    return pda


def ix_log_denial(program_id: Pubkey, worker: Pubkey, requester: Pubkey,
                  action_hash_bytes, epoch: int, reason: int) -> Instruction:
    """Build a log_denied_request instruction, signed by the refusing worker."""
    nd = denial_nullifier(worker, requester, action_hash_bytes, epoch)
    data = (discriminator("log_denied_request")
            + serialize_pubkey(requester)
            + serialize_u8_array_32(action_hash_bytes)
            + serialize_u8_array_32(nd)
            + serialize_u64(epoch)
            + bytes([reason]))
    accounts = [
        AccountMeta(worker, True, True),
        AccountMeta(agent_pda(program_id, worker), False, False),
        AccountMeta(denial_log_pda(program_id, nd), False, True),
        AccountMeta(SYS_PROGRAM_ID, False, False),
    ]
    return Instruction(program_id, data, accounts)


def action_hash(name: str) -> list:
    """
    Deterministic 32-byte hash for a named capability, e.g. READ_DATABASE.

    Deriving action hashes from names rather than using random bytes means
    an auditor reading a TraceabilityLog can recompute which capability an
    entry refers to. With random hashes the audit trail is only meaningful
    to whoever still holds the mapping, which undercuts the point of an
    immutable log.
    """
    return list(hashlib.sha256(b"tap-a2a-action" + name.encode()).digest())


def access_nullifier(agent_pubkey: Pubkey, group_id, action_hash, epoch: int) -> list:
    payload = (
        b"tap-a2a-nullifier"
        + bytes(agent_pubkey)
        + bytes(group_id)
        + bytes(action_hash)
        + epoch.to_bytes(8, "little")
    )
    return list(hashlib.sha256(payload).digest())


# ----------------------------------------------------------------------
# PDA helpers. Seeds MUST match #[account(seeds = [...])] in lib.rs.
# ----------------------------------------------------------------------
def config_pda(program_id: Pubkey) -> Pubkey:
    pda, _ = Pubkey.find_program_address([b"config"], program_id)
    return pda


def agent_pda(program_id: Pubkey, agent_pubkey: Pubkey) -> Pubkey:
    pda, _ = Pubkey.find_program_address([b"agent", bytes(agent_pubkey)], program_id)
    return pda


def policy_pda(program_id: Pubkey, group_id, action_hash) -> Pubkey:
    pda, _ = Pubkey.find_program_address(
        [b"policy", bytes(group_id), bytes(action_hash)], program_id
    )
    return pda


def trace_log_pda(program_id: Pubkey, nullifier) -> Pubkey:
    pda, _ = Pubkey.find_program_address([b"trace_log", bytes(nullifier)], program_id)
    return pda


# ----------------------------------------------------------------------
# Instruction builders.
#
# Account ORDER must match the #[derive(Accounts)] struct field order in
# lib.rs exactly. AccountMeta is (pubkey, is_signer, is_writable).
# ----------------------------------------------------------------------


def ix_initialize(program_id: Pubkey, admin: Pubkey) -> Instruction:
    return Instruction(
        program_id,
        discriminator("initialize"),
        [
            AccountMeta(admin, True, True),
            AccountMeta(config_pda(program_id), False, True),
            AccountMeta(SYS_PROGRAM_ID, False, False),
        ],
    )


def ix_register_agent(program_id: Pubkey, admin: Pubkey, new_agent: Pubkey,
                      group_id) -> Instruction:
    return Instruction(
        program_id,
        discriminator("register_agent") + serialize_u8_array_32(group_id),
        [
            AccountMeta(admin, True, True),
            AccountMeta(config_pda(program_id), False, False),
            AccountMeta(new_agent, False, False),
            AccountMeta(agent_pda(program_id, new_agent), False, True),
            AccountMeta(SYS_PROGRAM_ID, False, False),
        ],
    )


def ix_set_policy(program_id: Pubkey, admin: Pubkey, group_id, action_hash,
                  is_allowed: bool) -> Instruction:
    data = (discriminator("set_policy") + serialize_u8_array_32(group_id)
            + serialize_u8_array_32(action_hash) + serialize_bool(is_allowed))
    return Instruction(
        program_id,
        data,
        [
            AccountMeta(admin, True, True),
            AccountMeta(config_pda(program_id), False, False),
            AccountMeta(policy_pda(program_id, group_id, action_hash), False, True),
            AccountMeta(SYS_PROGRAM_ID, False, False),
        ],
    )


def ix_update_policy(program_id: Pubkey, admin: Pubkey, group_id, action_hash,
                     is_allowed: bool) -> Instruction:
    return Instruction(
        program_id,
        discriminator("update_policy") + serialize_bool(is_allowed),
        [
            AccountMeta(admin, True, False),
            AccountMeta(config_pda(program_id), False, False),
            AccountMeta(policy_pda(program_id, group_id, action_hash), False, True),
        ],
    )


def ix_revoke_agent(program_id: Pubkey, admin: Pubkey, target_agent: Pubkey) -> Instruction:
    return Instruction(
        program_id,
        discriminator("revoke_agent"),
        [
            AccountMeta(admin, True, True),
            AccountMeta(config_pda(program_id), False, False),
            AccountMeta(target_agent, False, False),
            AccountMeta(agent_pda(program_id, target_agent), False, True),
        ],
    )


def ix_log_access(program_id: Pubkey, agent: Pubkey, group_id, action_hash,
                  epoch: int, nullifier=None, impersonate_as=None) -> Instruction:
    """
    Build a log_traceable_access instruction.

    `nullifier` defaults to the correct derivation. Pass an explicit
    value only to test that the program rejects a forged one -- see the
    nullifier-forgery scenario in scenario_runner.py.

    `impersonate_as` is TEST-ONLY. When set, the agent_record account is
    derived from that key while `agent` remains the signer, producing a
    request in which the signer presents someone else's registration.
    lib.rs seeds agent_record on [b"agent", agent.key()], so Anchor
    rejects this during account validation with ConstraintSeeds. This is
    the empirical counterpart of the impersonation_resistance lemma in
    tap_a2a.spthy.
    """
    if nullifier is None:
        nullifier = access_nullifier(agent, group_id, action_hash, epoch)
    record_owner = impersonate_as if impersonate_as is not None else agent

    data = (discriminator("log_traceable_access")
            + serialize_u8_array_32(action_hash)
            + serialize_u8_array_32(nullifier)
            + serialize_u64(epoch))
    return Instruction(
        program_id,
        data,
        [
            AccountMeta(agent, True, True),
            AccountMeta(agent_pda(program_id, record_owner), False, False),
            AccountMeta(policy_pda(program_id, group_id, action_hash), False, False),
            AccountMeta(trace_log_pda(program_id, nullifier), False, True),
            AccountMeta(SYS_PROGRAM_ID, False, False),
        ],
    )


# ----------------------------------------------------------------------
# On-chain account layouts. Must match the #[account] structs in lib.rs.
# Each is prefixed on-chain by Anchor's 8-byte discriminator, which the
# caller must strip before calling these parsers.
#
#   Config:       admin(32) + bump(1)                                = 33
#   AgentRecord:  agent_pubkey(32) + group_id(32) + active(1) + bump(1) = 66
#   PolicyRecord: group_id(32) + action_hash(32) + allowed(1) + bump(1) = 66
# ----------------------------------------------------------------------
CONFIG_STRUCT = "<32sB"
AGENT_RECORD_STRUCT = "<32s32s?B"
POLICY_RECORD_STRUCT = "<32s32s?B"


def parse_config(data: bytes) -> dict:
    admin, bump = struct.unpack(CONFIG_STRUCT, data[:struct.calcsize(CONFIG_STRUCT)])
    return {"admin": Pubkey(admin), "bump": bump}


def parse_agent_record(data: bytes) -> dict:
    size = struct.calcsize(AGENT_RECORD_STRUCT)
    agent_pubkey, group_id, is_active, bump = struct.unpack(AGENT_RECORD_STRUCT, data[:size])
    return {
        "agent_pubkey": Pubkey(agent_pubkey),
        "agent_group_id": group_id,
        "is_active": is_active,
        "bump": bump,
    }


def parse_policy_record(data: bytes) -> dict:
    size = struct.calcsize(POLICY_RECORD_STRUCT)
    group_id, action_hash, is_allowed, bump = struct.unpack(POLICY_RECORD_STRUCT, data[:size])
    return {
        "agent_group_id": group_id,
        "action_hash": action_hash,
        "is_allowed": is_allowed,
        "bump": bump,
    }


# ----------------------------------------------------------------------
# Error classification. Anchor's logs carry both the CustomError variant
# name and the failing account's field name as plain text, which is more
# version-stable than numeric codes -- so codes are a secondary check.
# ----------------------------------------------------------------------
def classify_error(error: Exception) -> str:
    msg = str(error)

    def has(name: str, code: int) -> bool:
        return name in msg or f"Error Number: {code}" in msg or f"0x{code:x}" in msg

    if has("AgentRevoked", ErrorCode.AGENT_REVOKED):
        return "DENIED: Agent has been REVOKED by the administrator."
    if has("PolicyDenied", ErrorCode.POLICY_DENIED):
        return "DENIED: Policy explicitly denies this action."
    if has("InvalidNullifier", ErrorCode.INVALID_NULLIFIER):
        return "DENIED: Nullifier is not the correct derivation for this agent/action/epoch."
    if has("InvalidEpoch", ErrorCode.INVALID_EPOCH):
        return "DENIED: Epoch is not the current access epoch."
    if has("UnauthorizedAdmin", ErrorCode.UNAUTHORIZED_ADMIN):
        return "DENIED: Signer is not the configured protocol administrator."
    if has("AgentAlreadyRevoked", ErrorCode.AGENT_ALREADY_REVOKED):
        return "DENIED: Agent is already revoked."
    if "already in use" in msg:
        return "DENIED: REPLAY DETECTED — this nullifier was already consumed this epoch."
    if "ConstraintSeeds" in msg and "agent_record" in msg:
        return ("DENIED: IMPERSONATION BLOCKED — the agent record presented does not "
                "belong to the signing agent.")
    if has("InvalidDenialReason", ErrorCode.INVALID_DENIAL_REASON):
        return "DENIED: Denial reason code out of range."
    if "AccountNotInitialized" in msg or "ConstraintSeeds" in msg:
        if "policy_record" in msg:
            return "DENIED: No matching policy for this agent group/action (least-privilege enforced)."
        if "agent_record" in msg:
            return "DENIED: Agent is not registered."
        if "config" in msg:
            return "DENIED: Protocol not initialised — run initialize first."
        return "DENIED: Required on-chain account is missing or does not match expected PDA seeds."
    return f"DENIED: Blocked by TAP-A2A program. Raw error: {msg[:150]}"
