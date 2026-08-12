
import json
import time
import uuid

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from tap_a2a_common import (
    action_hash, agent_pda, current_epoch, ix_log_access, policy_pda,
    parse_agent_record, classify_error,
)
from tap_a2a_client import send

# How long a task message stays valid. Short enough that a captured
# message is useless quickly; long enough to absorb scheduling delay.
MESSAGE_TTL_SECONDS = 30


class A2AError(Exception):
    """Raised when a message fails verification at the receiver."""


# ----------------------------------------------------------------------
# Message
# ----------------------------------------------------------------------
class TaskMessage:

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
            raise A2AError("REJECTED: message carries no signature.")
        try:
            VerifyKey(bytes(msg.sender)).verify(msg.payload(), msg.signature)
        except BadSignatureError:
            raise A2AError("REJECTED: signature does not verify against the "
                           "claimed sender.")

    def _check_addressed_to_me(self, msg: TaskMessage):
        if msg.recipient != self.keypair.pubkey():
            raise A2AError("REJECTED: message is addressed to a different agent.")

    def _check_freshness(self, msg: TaskMessage):
        now = int(time.time())
        if now > msg.expires_at:
            raise A2AError(f"REJECTED: message expired {now - msg.expires_at}s ago.")
        if msg.issued_at > now + 5:
            raise A2AError("REJECTED: message is dated in the future.")

    def _check_nonce(self, msg: TaskMessage):
        if msg.nonce in self._seen_nonces:
            raise A2AError("REJECTED: nonce already seen — replayed message.")

    async def _check_sender_registered(self, client, msg: TaskMessage):

        info = await client.get_account_info(agent_pda(self.program_id, msg.sender))
        if info.value is None:
            raise A2AError("REJECTED: sender is not a registered agent on-chain.")
        record = parse_agent_record(bytes(info.value.data)[8:])
        if not record["is_active"]:
            raise A2AError("REJECTED: sender has been revoked on-chain.")

    async def _check_within_my_scope(self, client, msg: TaskMessage):

        action = action_hash(msg.capability)
        pda = policy_pda(self.program_id, self.group_id, action)
        info = await client.get_account_info(pda)
        if info.value is None:
            raise A2AError(
                f"REJECTED: '{msg.capability}' is outside this agent's "
                f"least-privilege scope (no policy for its group).")

    # -- public entry point --------------------------------------------
    async def handle(self, client, msg: TaskMessage) -> str:

        self._check_signature(msg)
        self._check_addressed_to_me(msg)
        self._check_freshness(msg)
        self._check_nonce(msg)
        await self._check_sender_registered(client, msg)
        await self._check_within_my_scope(client, msg)

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
