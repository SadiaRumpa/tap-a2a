"""
TAP-A2A — traceable ring signature benchmark.

Measures how signing time, verification time, trace time and signature
size scale with ring size. Ring size IS the anonymity parameter, so this
table is the security/performance trade-off for the ring-signature
extension: a larger anonymity set costs linearly more work and bytes.

Writes trs_ring_size.csv and, if matplotlib is available,
figure_6_3_trs_ring_size.png.

Run:  python3 trs_benchmark.py
"""
import csv
import statistics
import sys
import time

from tap_a2a_trs import (
    keygen, sign, verify, trace, self_test, TraceableRingSignature,
)

RING_SIZES = [2, 4, 8, 16, 32, 64]
REPEATS = 20
ISSUE = b"READ_DATABASE|epoch=471234"


def bench_one(n, repeats=REPEATS):
    keys = [keygen() for _ in range(n)]
    ring = [pk for _, pk in keys]
    signer = n // 2

    sign_ms, verify_ms, trace_ms = [], [], []
    sig = None
    msg = None

    for r in range(repeats):
        msg = b"request-%d" % r

        t0 = time.perf_counter()
        sig = sign(ISSUE, ring, msg, keys[signer][0], signer)
        sign_ms.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        good = verify(ISSUE, ring, msg, sig)
        verify_ms.append((time.perf_counter() - t0) * 1000)
        if not good:
            raise SystemExit(f"verification failed at ring size {n} — do not cite this run")

    # Trace cost: the gateway runs this against each stored signature for
    # the issue, so it is the per-comparison cost, not a one-off.
    other = sign(ISSUE, ring, b"other-request", keys[signer][0], signer)
    # `msg` must be the message `sig` was actually produced for: trace
    # recomputes A0 from the message, so a mismatch silently compares two
    # unrelated lines and reports INDEPENDENT.
    for _ in range(repeats):
        t0 = time.perf_counter()
        result = trace(ISSUE, ring, msg, sig, b"other-request", other)
        trace_ms.append((time.perf_counter() - t0) * 1000)

    if not (isinstance(result, tuple) and result[0] == signer):
        raise SystemExit(f"trace failed to identify the double-signer at ring size {n}")

    return {
        "ring_size": n,
        "sign_ms": statistics.mean(sign_ms),
        "verify_ms": statistics.mean(verify_ms),
        "trace_ms": statistics.mean(trace_ms),
        "sig_bytes": len(sig.to_bytes()),
        "anchor_bytes": len(sig.anchor(ISSUE)),
    }


def main():
    print("Validating the implementation before measuring it...")
    if not self_test(verbose=False):
        raise SystemExit("SELF-TEST FAILED — benchmark aborted, results would be meaningless")
    print("Self-test passed.\n")

    print(f"Benchmarking ring sizes {RING_SIZES}, {REPEATS} repeats each...\n")
    rows = []
    for n in RING_SIZES:
        row = bench_one(n)
        rows.append(row)
        print(f"  ring={n:<4} sign={row['sign_ms']:7.2f} ms  "
              f"verify={row['verify_ms']:7.2f} ms  "
              f"trace={row['trace_ms']:6.2f} ms  sig={row['sig_bytes']:5d} B")

    print("\n" + "=" * 74)
    print("TRACEABLE RING SIGNATURE — COST vs ANONYMITY SET")
    print("=" * 74)
    print(f"{'Ring':<8}{'Sign (ms)':>12}{'Verify (ms)':>14}"
          f"{'Trace (ms)':>13}{'Signature (B)':>16}")
    print("-" * 74)
    for r in rows:
        print(f"{r['ring_size']:<8}{r['sign_ms']:>12.2f}{r['verify_ms']:>14.2f}"
              f"{r['trace_ms']:>13.2f}{r['sig_bytes']:>16d}")
    print("=" * 74)
    print("Signature size is 64 + 32n bytes: A1, c0, and one response per")
    print("ring member. Cost is linear in ring size, so the anonymity set is")
    print("bounded in practice by verification budget and message size, not")
    print("by the scheme.")
    print(f"\nOn-chain anchor is {rows[0]['anchor_bytes']} bytes regardless of ring size.")

    with open("trs_ring_size.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print("Raw data written to trs_ring_size.csv")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed — skipping the figure.")
        return 0

    sizes = [r["ring_size"] for r in rows]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    ax1.plot(sizes, [r["sign_ms"] for r in rows], "o-", label="Sign")
    ax1.plot(sizes, [r["verify_ms"] for r in rows], "s-", label="Verify")
    ax1.plot(sizes, [r["trace_ms"] for r in rows], "^-", label="Trace")
    ax1.set_xlabel("Ring size (anonymity set)")
    ax1.set_ylabel("Time (ms)")
    ax1.set_title("Cost against anonymity set")
    ax1.legend()
    ax1.grid(alpha=0.3, linestyle="--")

    ax2.plot(sizes, [r["sig_bytes"] for r in rows], "d-", color="#DD8452")
    ax2.set_xlabel("Ring size (anonymity set)")
    ax2.set_ylabel("Signature size (bytes)")
    ax2.set_title("Signature size against anonymity set")
    ax2.grid(alpha=0.3, linestyle="--")

    fig.suptitle("Figure 6.3: Traceable ring signature cost vs anonymity set", fontsize=13)
    fig.tight_layout()
    fig.savefig("figure_6_3_trs_ring_size.png", dpi=300)
    print("Saved figure_6_3_trs_ring_size.png")
    return 0


if __name__ == "__main__":
    sys.exit(main())
