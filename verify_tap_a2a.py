"""
TAP-A2A formal verification runner.

Two experiments:

  PART 1 - prove every lemma against the full model, recording result,
           step count and wall-clock time.

  PART 2 - ABLATION. Remove one enforcement mechanism at a time and
           check that the lemma it protects becomes FALSIFIED. This is
           the part that matters academically: it shows the properties
           hold because of the mechanisms, not because the model is too
           weak to express a violation. A lemma that stays verified
           after its protection is removed is a modelling artefact, and
           the ablation is what catches it.

Run in Colab after the setup cell that puts tamarin-prover on PATH.
Expects tap_a2a.spthy in the working directory.
"""
import re
import subprocess
import time
from datetime import datetime, timezone

MODEL = "tap_a2a.spthy"
TIMEOUT = 420

LEMMAS = [
    "executable",
    "no_access_without_registration",
    "no_access_without_policy",
    "one_access_per_agent_action_epoch",
    "agent_active_implies_not_revoked",
    "revocation_is_effective",
    "every_access_is_logged",
    "impersonation_resistance",
    "accountability",
]

BASE = open(MODEL).read()


def run(lemma, path=MODEL, flags=(), timeout=TIMEOUT):
    """Return (status, steps, seconds)."""
    start = time.perf_counter()
    try:
        p = subprocess.run(
            ["tamarin-prover", f"--prove={lemma}", "--auto-sources", *flags, path],
            capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "TIMEOUT", "-", time.perf_counter() - start
    secs = time.perf_counter() - start

    for line in p.stdout.splitlines():
        if lemma in line and ("verified" in line or "falsified" in line):
            status = "VERIFIED" if "verified" in line else "FALSIFIED"
            m = re.search(r"\((\d+) steps\)", line)
            return status, (m.group(1) if m else "?"), secs
    return "NO RESULT", "-", secs


# ----------------------------------------------------------------------
# Ablations. Each removes exactly one enforcement mechanism from
# Chain_Verify (or bypasses registration) and names the lemma that
# mechanism is supposed to protect.
# ----------------------------------------------------------------------
ABLATIONS = {
    "no_nullifier_recomputation": dict(
        target="one_access_per_agent_action_epoch",
        why="Chain accepts a caller-supplied nullifier instead of deriving it",
        edit=lambda s: s.replace(
            """  let n   = h(<'tap-a2a-nullifier', pkA, $g, $act, $e>)
      req = <'access', pkA, $act, $e>
  in
    [ In(<req, sig>)""",
            """  let req = <'access', pkA, $act, $e, n>
  in
    [ In(<req, sig>)"""),
    ),
    "no_policy_check": dict(
        target="no_access_without_policy",
        why="Chain no longer requires a policy permitting the action",
        edit=lambda s: s.replace(
            """    , AgentActive($A)
    , !PolicyAllows($g, $act) ]""",
            """    , AgentActive($A) ]"""),
    ),
    "no_active_state_check": dict(
        target="revocation_is_effective",
        why="Chain no longer requires the agent to be active, so revocation is inert",
        # The [reuse] annotation must also go. Proving a single lemma makes
        # Tamarin ASSUME any reuse lemma rather than prove it, so leaving it
        # in lets revocation_is_effective verify in 2 steps from an
        # assumption this ablation has just falsified. Dropping `reuse`
        # forces the lemma to stand on its own -- and removing AgentActive
        # from Chain_Verify also removes the loop, so it now terminates.
        edit=lambda s: s.replace(
            "lemma agent_active_implies_not_revoked [use_induction, reuse]:",
            "lemma agent_active_implies_not_revoked [use_induction]:").replace(
            """    , !AgentGroup($A, $g)
    , AgentActive($A)
    , !PolicyAllows($g, $act) ]""",
            """    , !AgentGroup($A, $g)
    , !PolicyAllows($g, $act) ]""").replace(
            """    [ AgentActive($A)
    , TraceLog($A, $g, $act, $e, n) ]""",
            """    [ TraceLog($A, $g, $act, $e, n) ]"""),
    ),
    "no_signature_verification": dict(
        target="impersonation_resistance",
        why="Chain accepts a request without checking the signature",
        edit=lambda s: s.replace(
            "  --[ Eq(verify(sig, req, pkA), true)\n    , Access($A, $g, $act, $e)",
            "  --[ Access($A, $g, $act, $e)"),
    ),
    "unregistered_agents_allowed": dict(
        target="no_access_without_registration",
        why="A rogue rule provisions agent state without going through Register_Agent",
        edit=lambda s: s.replace(
            "// ---------------------------------------------------------------------\n"
            "// Access protocol",
            """rule Rogue_Provision:
    [ !Pk($A, pkA) ]
  --[ RogueProvision($A, $g) ]->
    [ !AgentGroup($A, $g), AgentActive($A) ]

// ---------------------------------------------------------------------
// Access protocol"""),
    ),
}


def main():
    ver = subprocess.run(["tamarin-prover", "--version"],
                         capture_output=True, text=True).stdout.splitlines()[0]
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    out = [f"TAP-A2A formal verification", f"{ver}", f"Run: {stamp}",
           f"Heuristic: default (--auto-sources)", f"Per-lemma timeout: {TIMEOUT}s", ""]

    # -------- Part 1 --------
    out += ["PART 1 - FULL MODEL", "-" * 68,
            f"{'Lemma':<38}{'Result':<12}{'Steps':<8}{'Time(s)':>8}", "-" * 68]
    print("\n".join(out), flush=True)

    for L in LEMMAS:
        status, steps, secs = run(L)
        row = f"{L:<38}{status:<12}{steps:<8}{secs:>8.1f}"
        out.append(row)
        print(row, flush=True)
        open("tamarin_results.txt", "w").write("\n".join(out))

    # -------- Part 2 --------
    out += ["", "PART 2 - ABLATION (expect FALSIFIED)", "-" * 68,
            f"{'Ablation':<32}{'Target lemma':<36}{'Result':<12}", "-" * 68]
    print("\n".join(out[-5:]), flush=True)

    for name, spec in ABLATIONS.items():
        variant = spec["edit"](BASE)
        if variant == BASE:
            row = f"{name:<32}{spec['target']:<36}{'EDIT FAILED':<12}"
        else:
            path = f"ablation_{name}.spthy"
            open(path, "w").write(variant)
            status, steps, secs = run(spec["target"], path=path)
            flag = "" if status == "FALSIFIED" else "   <-- CHECK THIS"
            row = f"{name:<32}{spec['target']:<36}{status:<12}{flag}"
        out.append(row)
        print(row, flush=True)
        open("tamarin_results.txt", "w").write("\n".join(out))

    out += ["", "Notes:",
            "  A FALSIFIED result in Part 2 is the desired outcome: it shows the",
            "  property in Part 1 depends on the mechanism that was removed.",
            "  A VERIFIED result in Part 2 means the lemma does NOT actually test",
            "  that mechanism and should be reviewed before being cited.",
            "  An EDIT FAILED row means the ablation's text substitution did not",
            "  match the model -- fix the pattern rather than reporting the row."]
    open("tamarin_results.txt", "w").write("\n".join(out))
    print("\n" + "\n".join(out[-7:]))


if __name__ == "__main__":
    main()
