"""
TAP-A2A — agent-to-agent message layer.

Objective 3: secure A2A communication governed by the least-privilege
policies of objective 2.

The layer sits ABOVE the on-chain program and changes nothing in
lib.rs. A message travels from one agent to another, and the receiving
agent verifies it against on-chain state before acting:

    orchestrator                         worker
        |                                  |
        |-- TaskMessage{to, capability,    |
        |     task_id, nonce, issued_at,   |
        |     expires_at} + Ed25519 sig -->|
        |                                  | 1. signature valid?
        |                                  | 2. sender registered + active
        |                                  |    on-chain?
        |                                  | 3. message fresh (not expired)?
        |                                  | 4. nonce unused?
        |                                  | 5. capability inside the
        |                                  |    RECEIVER's own on-chain
        |                                  |    policy scope?
        |                                  |
        |                                  |-- log_traceable_access -->  chain
        |                                  |    (the program re-checks
        |<------- TaskResult --------------|     everything independently)

WHY THE RECEIVER CHECKS ITS OWN SCOPE
-------------------------------------
Check 5 is what makes this least-privilege rather than plain messaging.
A worker refuses a capability outside its own policy BEFORE touching the
chain, so a compromised or injected orchestrator cannot widen a worker's
authority by asking nicely. The chain then re-checks independently: two
enforcement points, neither trusting the other.

SCOPE -- READ BEFORE CITING
---------------------------
1. This is DISPATCH, not DELEGATION. The orchestrator asks a worker to
   exercise authority the worker already holds under standing policy. It
   does not grant, attenuate, or forward authority of its own. There are
   no capability tokens and no delegation chain, so
   delegation-without-escalation is NOT demonstrated. Doing that properly
   needs on-chain support and is future work.

2. Transport is in-process for reproducibility. Messages are real signed
   byte strings that are verified on receipt, but they are passed between
   Python objects rather than over a network. Nothing in the verification
   logic depends on that; a socket or HTTP transport would substitute
   without changing the checks.

3. NOT covered by tap_a2a.spthy. The Tamarin model describes the deployed
   on-chain protocol. Formal analysis of this layer is future work.

4. The nonce store is per-process. A production deployment would need it
   shared across a worker's replicas, or the freshness window narrowed to
   the point where replay is bounded by expiry alone.
"""
import json
import time
import uuid

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from tap_a2a_common import (
    action_hash, agent_pda, current_epoch, ix_log_access, ix_log_denial,
    policy_pda, parse_agent_record, classify_error, DenialReason,
)
from tap_a2a_client import send

# How long a task message stays valid. Short enough that a captured
# message is useless quickly; long enough to absorb scheduling delay.
MESSAGE_TTL_SECONDS = 30


class A2AError(Exception):
    """
    Raised when a message fails verification at the receiver.

    Carries the DenialReason code so the worker can anchor the refusal
    on-chain. Without a code the audit trail could record THAT something
    was refused but not WHY, which is most of the forensic value.
    """

    def __init__(self, message: str, reason: int = None):
        super().__init__(message)
        self.reason = reason


# ----------------------------------------------------------------------
# Message
# ----------------------------------------------------------------------
class TaskMessage:
    """
    A signed request from one agent to another.

    The signature covers the canonical JSON encoding of every field, so
    changing the recipient, the capability, or the expiry invalidates it.
    """

    __slots__ = ("sender", "recipient", "capability", "task_id",
                 "nonce", "issued_at", "expires_at", "signature")

    def __init__(self, sender: Pubkey, recipient: Pubkey, capability: str,
                 task_id: str, nonce: str, issued_at: int, expires_at: int,
                 signature: bytes = None):
        self.sender = sender
        self.recipient = recipient
        self.capability = capability
        self.task_id = task_id
        self.nonce = nonce
        self.issued_at = issued_at
        self.expires_at = expires_at
        self.signature = signature

    def payload(self) -> bytes:
        """Canonical bytes covered by the signature. Sorted keys and no
        whitespace, so the encoding is identical on both sides."""
        return json.dumps({
            "sender": str(self.sender),
            "recipient": str(self.recipient),
            "capability": self.capability,
            "task_id": self.task_id,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }, sort_keys=True, separators=(",", ":")).encode()

    def __repr__(self):
        return (f"TaskMessage({self.capability} -> "
                f"{str(self.recipient)[:8]}..., task={self.task_id[:8]})")


def compose(sender_kp: Keypair, recipient: Pubkey, capability: str,
            task_id: str = None, ttl: int = MESSAGE_TTL_SECONDS) -> TaskMessage:
    """Build and sign a task message."""
    now = int(time.time())
    msg = TaskMessage(
        sender=sender_kp.pubkey(),
        recipient=recipient,
        capability=capability,
        task_id=task_id or uuid.uuid4().hex,
        nonce=uuid.uuid4().hex,
        issued_at=now,
        expires_at=now + ttl,
    )
    msg.signature = bytes(sender_kp.sign_message(msg.payload()))
    return msg


# ----------------------------------------------------------------------
# Receiver
# ----------------------------------------------------------------------
class Worker:
    """
    An agent that accepts task messages and acts on them.

    Holds its own keypair and its own on-chain group. Verifies every
    message before doing anything.
    """

    def __init__(self, agent_id: str, keypair: Keypair, group_id,
                 program_id: Pubkey):
        self.agent_id = agent_id
        self.keypair = keypair
        self.group_id = group_id
        self.program_id = program_id
        self._seen_nonces = set()

    # -- individual checks, separated so failures are attributable ------
    def _check_signature(self, msg: TaskMessage):
        if msg.signature is None:
            raise A2AError("REJECTED: message carries no signature.",
                           DenialReason.BAD_SIGNATURE)
        try:
            VerifyKey(bytes(msg.sender)).verify(msg.payload(), msg.signature)
        except BadSignatureError:
            raise A2AError("REJECTED: signature does not verify against the "
                           "claimed sender.", DenialReason.BAD_SIGNATURE)

    def _check_addressed_to_me(self, msg: TaskMessage):
        if msg.recipient != self.keypair.pubkey():
            raise A2AError("REJECTED: message is addressed to a different agent.",
                           DenialReason.BAD_SIGNATURE)

    def _check_freshness(self, msg: TaskMessage):
        now = int(time.time())
        if now > msg.expires_at:
            raise A2AError(f"REJECTED: message expired {now - msg.expires_at}s ago.",
                           DenialReason.EXPIRED)
        if msg.issued_at > now + 5:
            raise A2AError("REJECTED: message is dated in the future.",
                           DenialReason.EXPIRED)

    def _check_nonce(self, msg: TaskMessage):
        if msg.nonce in self._seen_nonces:
            raise A2AError("REJECTED: nonce already seen — replayed message.",
                           DenialReason.REPLAYED)

    async def _check_sender_registered(self, client, msg: TaskMessage):
        """The sender must be a registered, active agent on-chain. A valid
        signature alone only proves key possession, not authorisation to
        participate."""
        info = await client.get_account_info(agent_pda(self.program_id, msg.sender))
        if info.value is None:
            raise A2AError("REJECTED: sender is not a registered agent on-chain.",
                           DenialReason.NOT_REGISTERED)
        record = parse_agent_record(bytes(info.value.data)[8:])
        if not record["is_active"]:
            raise A2AError("REJECTED: sender has been revoked on-chain.",
                           DenialReason.REVOKED)

    async def _check_within_my_scope(self, client, msg: TaskMessage):
        """
        The heart of objective 3. The capability must fall inside THIS
        worker's own least-privilege policy. A worker refuses to act
        outside its scope no matter who asks, so a compromised
        orchestrator cannot widen it.
        """
        action = action_hash(msg.capability)
        pda = policy_pda(self.program_id, self.group_id, action)
        info = await client.get_account_info(pda)
        if info.value is None:
            raise A2AError(
                f"REJECTED: '{msg.capability}' is outside this agent's "
                f"least-privilege scope (no policy for its group).",
                DenialReason.OUT_OF_SCOPE)

    # -- public entry point --------------------------------------------
    async def _anchor_denial(self, client, msg: TaskMessage, reason: int):
        """
        Write the refusal on-chain, signed by this worker.

        Best-effort by design. A failure here must not turn a correct
        refusal into an exception the caller mistakes for something else:
        the request was still refused. The most common failure is benign
        -- the same requester attempting the same capability twice in one
        epoch produces the same denial nullifier, so the record already
        exists and the second write fails. That is the storage bound
        working, not an error.
        """
        from tap_a2a_client import send
        try:
            await send(client,
                       ix_log_denial(self.program_id, self.keypair.pubkey(),
                                     msg.sender, action_hash(msg.capability),
                                     current_epoch(), reason),
                       [self.keypair])
        except Exception:
            pass

    async def handle(self, client, msg: TaskMessage, log_denials: bool = True) -> str:
        """
        Verify and, if it passes, execute on-chain.

        Checks run cheapest-first so a malformed message costs no RPC
        round trips.

        When a check fails and log_denials is set, the refusal is anchored
        on-chain before the error propagates. The audit trail would
        otherwise be grant-only: a refused escalation would leave no
        evidence anywhere, and an auditor reading the chain would see a
        clean history of legitimate accesses with no sign that anything
        was attempted. The refusals are where the attack evidence is.
        """
        try:
            self._check_signature(msg)
            self._check_addressed_to_me(msg)
            self._check_freshness(msg)
            self._check_nonce(msg)
            await self._check_sender_registered(client, msg)
            await self._check_within_my_scope(client, msg)
        except A2AError as e:
            if log_denials and e.reason is not None:
                await self._anchor_denial(client, msg, e.reason)
            raise

        # Only recorded once the message has fully passed, so a rejected
        # message cannot be used to burn a nonce the sender may retry.
        self._seen_nonces.add(msg.nonce)

        action = action_hash(msg.capability)
        try:
            await send(client,
                       ix_log_access(self.program_id, self.keypair.pubkey(),
                                     self.group_id, action, current_epoch()),
                       [self.keypair])
            return (f"ACCEPTED: {self.agent_id} executed {msg.capability}; "
                    f"trace logged on-chain.")
        except Exception as e:
            # The chain is the second, independent enforcement point.
            return f"ON-CHAIN {classify_error(e)}"


# ----------------------------------------------------------------------
# Sender
# ----------------------------------------------------------------------
class Orchestrator:
    """
    An agent that dispatches capabilities to workers over the A2A layer.

    It has its own on-chain identity, so a worker can verify that the
    request came from a registered, unrevoked agent. It does NOT hold or
    forward authority for the capabilities it requests — see the scope
    note at the top of this module.
    """

    def __init__(self, keypair: Keypair, group_id, program_id: Pubkey):
        self.keypair = keypair
        self.group_id = group_id
        self.program_id = program_id

    def dispatch(self, worker: Worker, capability: str,
                 task_id: str = None, ttl: int = MESSAGE_TTL_SECONDS) -> TaskMessage:
        return compose(self.keypair, worker.keypair.pubkey(), capability,
                       task_id=task_id, ttl=ttl)

    async def send_to(self, client, worker: Worker, capability: str,
                      task_id: str = None) -> str:
        msg = self.dispatch(worker, capability, task_id=task_id)
        try:
            return await worker.handle(client, msg)
        except A2AError as e:
            return str(e)
