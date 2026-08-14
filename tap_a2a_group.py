"""
TAP-A2A — group authentication with one-time traceable ring signatures.

The protocol the supervisor's first meeting flagged: an agent
authenticates as A MEMBER OF A GROUP without revealing which member, and
forfeits that anonymity automatically if it acts twice under the same
issue.

THE PROTOCOL
------------
    Enrolment (admin)
        ring R = ordered public keys of the group's members
        publish  H(R)  on-chain as a commitment; R itself is distributed
        off-chain, so on-chain cost is constant in group size

    Authentication (agent i, holding x_i with y_i in R)
        issue   = H("tap-a2a-issue" || group || action || epoch)
        message = H(group || action || epoch || nonce)
        sigma   = TRS.Sign(issue, R, message, x_i, i)
        send (group, action, epoch, nonce, sigma) to the verifier

    Verification (verifier)
        1. H(R) matches the on-chain commitment
        2. TRS.Verify(issue, R, message, sigma)
        3. TRS.Trace against every signature already seen for this issue
             INDEPENDENT -> accept, log anonymously on-chain
             LINKED      -> duplicate submission, reject
             (index, y)  -> DOUBLE USE, signer identified, publish on-chain
        4. submit log_group_access; the chain re-checks the group's policy

WHAT EACH PARTY IS TRUSTED FOR
------------------------------
The verifier is trusted for LIVENESS and for ONE-TIME ENFORCEMENT. It is
NOT trusted for authorisation: log_group_access re-checks the group's
policy on-chain, so a compromised verifier cannot grant a group authority
it was never given, only refuse to relay or fail to notice double use.

WHY ONE-TIME ENFORCEMENT CANNOT BE ON-CHAIN
-------------------------------------------
This is the architectural finding, not an implementation shortcut.

An FS-TRS signature yields no extractable per-signer value. Two
signatures by the same member under the same issue carry DIFFERENT tag
lines, agreeing only at the signer's own index -- and that index is
discoverable only by comparing the two signatures. Any value the chain
could derive from one signature alone is therefore either constant across
all members (useless for deduplication) or identifies the signer
(destroying the anonymity the scheme exists to provide).

So the chain cannot deduplicate without learning who signed. It enforces
what it can -- policy, epoch, and replay of an identical signature -- and
the verifier holds the per-issue set needed for tracing.

This is the trade the deterministic-nullifier protocol does not make: that
one is fully attributable and fully on-chain; this one is anonymous and
partly off-chain. Neither dominates, and the pair is the point.

NOT COVERED BY tap_a2a.spthy. The Tamarin model describes the
deterministic-nullifier protocol. Formal analysis of this one is future
work.
"""
import hashlib
import json

from solders.pubkey import Pubkey

from tap_a2a_trs import (
    LINKED, INDEPENDENT, TraceableRingSignature, sign, trace, verify,
)


class GroupAuthError(Exception):
    """Raised when a group-authentication attempt is refused."""


def ring_hash(ring) -> list:
    """
    Commitment to an ordered ring.

    Order matters: the TRS binds signatures to the ring as given, so a
    reordered ring is a different ring and must not match the commitment.
    """
    h = hashlib.sha256(b"tap-a2a-ring")
    for pk in ring:
        h.update(bytes(pk))
    return list(h.digest())


def issue_for(group_id, action_hash_bytes, epoch: int) -> bytes:
    """
    The scope within which a member may sign once.

    Binding the issue to (group, action, epoch) is what makes double use
    detectable: signing the same capability twice in one epoch produces
    two signatures under one issue, and tracing them identifies the
    signer. A different action or a later epoch is a different issue and
    stays anonymous.
    """
    return hashlib.sha256(
        b"tap-a2a-issue" + bytes(group_id) + bytes(action_hash_bytes)
        + epoch.to_bytes(8, "little")).digest()


def message_for(group_id, action_hash_bytes, epoch: int, nonce: str) -> bytes:
    """The signed statement: this group, this action, this epoch, this request."""
    return hashlib.sha256(json.dumps({
        "group": bytes(group_id).hex(),
        "action": bytes(action_hash_bytes).hex(),
        "epoch": epoch,
        "nonce": nonce,
    }, sort_keys=True, separators=(",", ":")).encode()).digest()


def signature_commitment(sig: TraceableRingSignature, issue: bytes) -> list:
    """
    32-byte on-chain handle for a signature.

    Binds the record to the signature without revealing the signer. It
    prevents the SAME signature being submitted twice; it cannot detect
    the same MEMBER submitting a different signature -- see the module
    docstring.
    """
    return list(hashlib.sha256(
        b"tap-a2a-groupsig" + issue + sig.to_bytes()).digest())


# ----------------------------------------------------------------------
# Agent side
# ----------------------------------------------------------------------
class GroupMember:
    """An agent that can authenticate as an anonymous member of its group."""

    def __init__(self, agent_id: str, secret, public, ring, index: int, group_id):
        if ring[index] != public:
            raise ValueError("index does not match this member's public key")
        self.agent_id = agent_id
        self.secret = secret
        self.public = public
        self.ring = ring
        self.index = index
        self.group_id = group_id

    def authenticate(self, action_hash_bytes, epoch: int, nonce: str):
        """Produce a ring signature asserting membership, not identity."""
        issue = issue_for(self.group_id, action_hash_bytes, epoch)
        message = message_for(self.group_id, action_hash_bytes, epoch, nonce)
        sig = sign(issue, self.ring, message, self.secret, self.index)
        return {
            "group_id": self.group_id,
            "action_hash": action_hash_bytes,
            "epoch": epoch,
            "nonce": nonce,
            "signature": sig,
        }


# ----------------------------------------------------------------------
# Verifier side
# ----------------------------------------------------------------------
class GroupVerifier:
    """
    Checks ring signatures, enforces one-time use, and anchors the result.

    Holds the per-issue signature set because the chain cannot: tracing
    requires comparing two signatures, and the chain sees them one at a
    time with no way to relate them without breaking anonymity.
    """

    def __init__(self, keypair, program_id: Pubkey, ring, expected_ring_hash=None):
        self.keypair = keypair
        self.program_id = program_id
        self.ring = ring
        self.expected_ring_hash = expected_ring_hash
        # issue -> [(message, signature)]
        self._seen = {}

    def check_ring(self):
        """
        The ring must match its on-chain commitment.

        Without this a verifier could be handed a ring of one and would
        happily accept a signature that proves nothing: membership of a
        singleton set is not anonymity.
        """
        if self.expected_ring_hash is None:
            return
        if ring_hash(self.ring) != list(self.expected_ring_hash):
            raise GroupAuthError(
                "REFUSED: ring does not match the on-chain commitment.")

    def verify_request(self, req):
        """
        Returns (outcome, detail).

          ("accepted", commitment)     valid, first use under this issue
          ("duplicate", None)          this exact signature was seen before
          ("traced", (index, pubkey))  the member signed this issue twice
        """
        self.check_ring()

        issue = issue_for(req["group_id"], req["action_hash"], req["epoch"])
        message = message_for(req["group_id"], req["action_hash"],
                              req["epoch"], req["nonce"])
        sig = req["signature"]

        if not verify(issue, self.ring, message, sig):
            raise GroupAuthError(
                "REFUSED: ring signature invalid — the requester is not a "
                "member of this group.")

        # Compare against every signature already seen under this issue.
        # Anonymity survives an honest single use; a second use collapses
        # it automatically, with no party trusted to reveal the signer.
        for prev_msg, prev_sig in self._seen.get(issue, []):
            result = trace(issue, self.ring, prev_msg, prev_sig, message, sig)
            if result == LINKED:
                return "duplicate", None
            if result != INDEPENDENT:
                index, pubkey = result
                return "traced", (index, pubkey)

        self._seen.setdefault(issue, []).append((message, sig))
        return "accepted", signature_commitment(sig, issue)
