
import hashlib
import os
import secrets

from nacl.bindings import (
    crypto_core_ed25519_add as _p_add,
    crypto_core_ed25519_sub as _p_sub,
    crypto_core_ed25519_from_uniform as _from_uniform,
    crypto_core_ed25519_is_valid_point as _is_valid,
    crypto_core_ed25519_scalar_add as _s_add,
    crypto_core_ed25519_scalar_invert as _s_inv,
    crypto_core_ed25519_scalar_mul as _s_mul,
    crypto_core_ed25519_scalar_reduce as _s_reduce,
    crypto_core_ed25519_scalar_sub as _s_sub,
    crypto_scalarmult_ed25519_base_noclamp as _p_base,
    crypto_scalarmult_ed25519_noclamp as _p_mul,
)

# Order of the ed25519 prime-order subgroup.
GROUP_ORDER = 2 ** 252 + 27742317777372353535851937790883648493

# Cofactor. from_uniform() can land outside the prime-order subgroup, so
# every hashed point is multiplied by 8 to force it in. Without this a
# small-order component would survive into the tags and could leak.
_COFACTOR = (8).to_bytes(32, "little")


# ----------------------------------------------------------------------
# Scalar and point helpers
# ----------------------------------------------------------------------
def _s_from_int(i: int) -> bytes:
    return (i % GROUP_ORDER).to_bytes(32, "little")


def _s_rand() -> bytes:

    while True:
        s = _s_reduce(secrets.token_bytes(64))
        if s != bytes(32):
            return s


def _hash_to_scalar(*parts: bytes) -> bytes:
    h = hashlib.sha512()
    for p in parts:
        h.update(len(p).to_bytes(4, "little"))
        h.update(p)
    return _s_reduce(h.digest())


def _hash_to_point(*parts: bytes) -> bytes:
    h = hashlib.sha512()
    for p in parts:
        h.update(len(p).to_bytes(4, "little"))
        h.update(p)
    return _p_mul(_COFACTOR, _from_uniform(h.digest()[:32]))


def _ring_bytes(ring) -> bytes:
    return b"".join(ring)


# ----------------------------------------------------------------------
# Keys
# ----------------------------------------------------------------------
def keygen():

    x = _s_rand()
    return x, _p_base(x)


# ----------------------------------------------------------------------
# Signature container
# ----------------------------------------------------------------------
class TraceableRingSignature:

    __slots__ = ("a1", "c0", "z")

    def __init__(self, a1: bytes, c0: bytes, z: list):
        self.a1, self.c0, self.z = a1, c0, list(z)

    def to_bytes(self) -> bytes:
        return self.a1 + self.c0 + b"".join(self.z)

    @classmethod
    def from_bytes(cls, blob: bytes):
        if len(blob) < 64 or (len(blob) - 64) % 32:
            raise ValueError("malformed signature")
        n = (len(blob) - 64) // 32
        z = [blob[64 + 32 * j: 96 + 32 * j] for j in range(n)]
        return cls(blob[:32], blob[32:64], z)

    def anchor(self, issue: bytes) -> bytes:

        return hashlib.sha256(b"tap-a2a-trs-anchor" + issue + self.a1).digest()

    def __len__(self):
        return len(self.z)


# ----------------------------------------------------------------------
# Core algebra shared by sign / verify / trace
# ----------------------------------------------------------------------
def _tag_base(issue: bytes, ring) -> bytes:
    return _hash_to_point(b"tap-a2a-trs-h", issue, _ring_bytes(ring))


def _a0(issue: bytes, ring, message: bytes) -> bytes:
    return _hash_to_point(b"tap-a2a-trs-A0", issue, _ring_bytes(ring), message)


def _tag_line(a0: bytes, a1: bytes, n: int) -> list:

    return [_p_add(a0, _p_mul(_s_from_int(j), a1)) for j in range(1, n + 1)]


def _challenge(issue, ring, a0, a1, message, a, b) -> bytes:
    return _hash_to_scalar(b"tap-a2a-trs-c", issue, _ring_bytes(ring),
                           a0, a1, message, a, b)


# ----------------------------------------------------------------------
# Sign / Verify / Trace
# ----------------------------------------------------------------------
def sign(issue: bytes, ring: list, message: bytes,
         secret: bytes, index: int) -> TraceableRingSignature:

    n = len(ring)
    if n < 2:
        raise ValueError("a ring needs at least 2 members to provide anonymity")
    if not 0 <= index < n:
        raise ValueError("index outside the ring")
    if _p_base(secret) != ring[index]:
        raise ValueError("secret key does not match ring[index]")

    h = _tag_base(issue, ring)
    tag = _p_mul(secret, h)                       # sigma_i = h^{x_i}
    a0 = _a0(issue, ring, message)

    # A1 = (tag - A0) * (index+1)^{-1}, so that sigma_{index+1} == tag.
    a1 = _p_mul(_s_inv(_s_from_int(index + 1)), _p_sub(tag, a0))
    sigmas = _tag_line(a0, a1, n)
    assert sigmas[index] == tag, "tag line does not pass through the signer's tag"

    a = [None] * n
    b = [None] * n
    c = [None] * n
    z = [None] * n

    # Commit for the real index, then walk the ring simulating the rest.
    w = _s_rand()
    a[index] = _p_base(w)
    b[index] = _p_mul(w, h)
    c[(index + 1) % n] = _challenge(issue, ring, a0, a1, message, a[index], b[index])

    j = (index + 1) % n
    while j != index:
        z[j] = _s_rand()
        a[j] = _p_add(_p_base(z[j]), _p_mul(c[j], ring[j]))
        b[j] = _p_add(_p_mul(z[j], h), _p_mul(c[j], sigmas[j]))
        c[(j + 1) % n] = _challenge(issue, ring, a0, a1, message, a[j], b[j])
        j = (j + 1) % n

    # Close the chain using the real secret.
    z[index] = _s_sub(w, _s_mul(c[index], secret))
    return TraceableRingSignature(a1, c[0], z)


def verify(issue: bytes, ring: list, message: bytes,
           sig: TraceableRingSignature) -> bool:

    n = len(ring)
    if n < 2 or len(sig) != n:
        return False
    if not _is_valid(sig.a1):
        return False

    try:
        h = _tag_base(issue, ring)
        a0 = _a0(issue, ring, message)
        sigmas = _tag_line(a0, sig.a1, n)

        c = sig.c0
        for j in range(n):
            a_j = _p_add(_p_base(sig.z[j]), _p_mul(c, ring[j]))
            b_j = _p_add(_p_mul(sig.z[j], h), _p_mul(c, sigmas[j]))
            c = _challenge(issue, ring, a0, sig.a1, message, a_j, b_j)
        return c == sig.c0
    except Exception:
        # Malformed points or zero scalars are simply invalid signatures.
        return False


# Trace outcomes
INDEPENDENT = "independent"
LINKED = "linked"


def trace(issue: bytes, ring: list,
          message_a: bytes, sig_a: TraceableRingSignature,
          message_b: bytes, sig_b: TraceableRingSignature):

    n = len(ring)
    line_a = _tag_line(_a0(issue, ring, message_a), sig_a.a1, n)
    line_b = _tag_line(_a0(issue, ring, message_b), sig_b.a1, n)

    agree = [j for j in range(n) if line_a[j] == line_b[j]]
    if len(agree) == n:
        return LINKED
    if len(agree) == 1:
        j = agree[0]
        return j, ring[j]
    return INDEPENDENT


# ----------------------------------------------------------------------
# Self-test
# ----------------------------------------------------------------------
def self_test(ring_size: int = 5, verbose: bool = True) -> bool:

    ok = True

    def check(name, cond):
        nonlocal ok
        ok = ok and bool(cond)
        if verbose:
            print(f"  {'PASS' if cond else 'FAIL'}  {name}")

    keys = [keygen() for _ in range(ring_size)]
    ring = [pk for _, pk in keys]
    issue = b"READ_DATABASE|epoch=471234"
    other_issue = b"WRITE_REPORT|epoch=471234"

    if verbose:
        print(f"\nFS-TRS self-test (ring size {ring_size})")
        print("-" * 52)

    # 1. Correctness — every member can sign, and it verifies.
    sigs = [sign(issue, ring, b"task-%d" % i, keys[i][0], i) for i in range(ring_size)]
    check("every member produces a verifying signature",
          all(verify(issue, ring, b"task-%d" % i, s) for i, s in enumerate(sigs)))

    # 2. Soundness — tampering must break verification.
    s = sign(issue, ring, b"payload", keys[2][0], 2)
    check("rejects a modified message", not verify(issue, ring, b"payload!", s))
    check("rejects a different issue", not verify(other_issue, ring, b"payload", s))
    bad = TraceableRingSignature(s.a1, s.c0, list(s.z))
    bad.z[0] = _s_rand()
    check("rejects a tampered response", not verify(issue, ring, b"payload", bad))
    shuffled = list(reversed(ring))
    check("rejects a different ring",
          not verify(issue, shuffled, b"payload", s))

    # 3. Non-membership — an outsider cannot sign.
    out_x, out_y = keygen()
    forged = False
    try:
        f = sign(issue, ring, b"payload", out_x, 0)
        forged = verify(issue, ring, b"payload", f)
    except ValueError:
        forged = False
    check("a non-member cannot produce a valid signature", not forged)

    # 4. Traceability — signing one issue twice identifies the signer.
    s1 = sign(issue, ring, b"first", keys[3][0], 3)
    s2 = sign(issue, ring, b"second", keys[3][0], 3)
    res = trace(issue, ring, b"first", s1, b"second", s2)
    check("double-signing identifies the signer",
          isinstance(res, tuple) and res[0] == 3 and res[1] == ring[3])

    # 5. Linkability — same issue and message is reported as a duplicate.
    s3 = sign(issue, ring, b"same", keys[1][0], 1)
    s4 = sign(issue, ring, b"same", keys[1][0], 1)
    check("identical issue+message is LINKED",
          trace(issue, ring, b"same", s3, b"same", s4) == LINKED)

    # 6. Anonymity of single use — different signers stay independent.
    s5 = sign(issue, ring, b"m-a", keys[0][0], 0)
    s6 = sign(issue, ring, b"m-b", keys[4][0], 4)
    check("distinct signers are INDEPENDENT",
          trace(issue, ring, b"m-a", s5, b"m-b", s6) == INDEPENDENT)

    # 7. Issue separation — signing two different issues does not trace.
    s7 = sign(issue, ring, b"x", keys[2][0], 2)
    s8 = sign(other_issue, ring, b"x", keys[2][0], 2)
    check("the same signer on DIFFERENT issues stays anonymous",
          trace(issue, ring, b"x", s7, b"x", s8) == INDEPENDENT)

    # 8. Encoding round-trip.
    blob = s1.to_bytes()
    check("signature survives serialisation round-trip",
          verify(issue, ring, b"first", TraceableRingSignature.from_bytes(blob)))

    # 9. Anchor stability.
    check("anchor is deterministic per signature",
          s1.anchor(issue) == TraceableRingSignature.from_bytes(blob).anchor(issue))
    check("anchor differs across signatures", s1.anchor(issue) != s2.anchor(issue))

    if verbose:
        print("-" * 52)
        print("ALL PROPERTIES HOLD" if ok else "SELF-TEST FAILED")
    return ok


if __name__ == "__main__":
    import sys
    sys.exit(0 if self_test() else 1)
