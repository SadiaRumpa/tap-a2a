# TAP-A2A

Traceable Authentication and Access Control for Agentic AI and Smart Contracts.

Prototype accompanying the ELE8095 Individual Research Project, Queen's
University Belfast.

---

## If you are marking this and do not want to install anything

Every result cited in the dissertation is committed under
`dissertation_results/`. Nothing needs to be run to inspect them.

All paths below are under `dissertation_results/`.

| File | What it contains |
|---|---|
| `security_scenario_results.txt` | Ten on-chain security scenarios, pass/fail with the denial reason |
| `a2a_scenario_results.txt` | Nine A2A message-layer scenarios |
| `peer_scenario_results.txt` | Peer-to-peer communication and the confused-deputy finding |
| `group_auth_results.txt` | Group authentication via traceable ring signatures |
| `bypass_experiment_results.txt` | Defence in depth with the message layer removed; trace storage cost |
| `audit_overhead_results.txt` | Audit-trail completeness and message overhead |
| `agentic_orchestration_results.txt` | Model-driven orchestration, including prompt injection |
| `planner_ollama_llama3.2.txt` | Planner behaviour under injection, three repeats |
| `tamarin_results.txt` | Formal verification and the ablation study |
| `benchmark_results.txt` | Latency and compute units at `confirmed`, 100 iterations |
| `benchmark_finalized.txt` | The same at `finalized`, for the irreversibility bound |
| `figure_6_1_latency_by_stage.png` | Latency distribution by stage |
| `figure_6_2_cu_bar_chart.png` | Compute units against the Solana budget |
| `figure_6_3_trs_ring_size.png` | Ring-signature cost against anonymity set |
| `gateway_confirmed_100.csv`, `gateway_finalized_100.csv`, `trs_ring_size.csv` | Raw per-iteration data |

The on-chain program is `programs/tap_a2a/src/lib.rs`. The formal model is
`tap_a2a.spthy`.

---

## Reproducing the results

### Prerequisites

| Tool | Version used |
|---|---|
| Rust | rustc 1.96.1 (31fca3adb 2026-06-26) |
| Solana CLI | solana-cli 3.1.14 (Agave client) |
| Anchor CLI | anchor-cli 0.30.1 |
| anchor-lang (crate) | 0.31.1 |
| Python | 3.14.6 |

**On the Anchor version.** The prototype was built and evaluated with
anchor-cli 0.30.1. The on-chain program depends on the `anchor-lang` 0.31.1
crate, which is what actually compiles `lib.rs`, so the CLI version is not
critical. `Anchor.toml` also carries `[toolchain] anchor_version = "0.31.1"`:
this is an instruction to avm (Anchor's version manager) and is ignored when
avm is not installed. Either arrangement builds successfully.

If you prefer to match the pinned version exactly:

```bash
cargo install --git https://github.com/coral-xyz/anchor avm --locked
avm install 0.31.1 && avm use 0.31.1
```

A funded local wallet is required; `solana-test-validator` provisions one
automatically at `~/.config/solana/id.json` on first run.

### One command

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
./deploy_and_test.sh
```

`deploy_and_test.sh` stops any running validator, wipes the ledger, starts a
fresh one, syncs the program ID across `lib.rs` and `Anchor.toml`, builds,
deploys, and runs the full evaluation suite. Expect 10–15 minutes; the
benchmark provisions 100 policies before it starts measuring.

Results are written to `dissertation_results/`. **Any stage that fails is
reported as FAIL and the suite exits non-zero** — the pipeline is designed so
that results cannot be produced by a run that did not actually succeed.

To re-run the evaluation against an already-running validator:

```bash
./run_all_evaluations.sh
```

### Expected output

```
PASS  anchor build
PASS  anchor deploy
SKIP  formal verification   (unless tamarin-prover is on PATH)
PASS  performance benchmark
PASS  security scenarios
PASS  A2A message layer
PASS  layer bypass experiment
PASS  audit trail + overhead
PASS  peer-to-peer A2A
PASS  group authentication
PASS  agentic orchestration
PASS  figure generation
```

The orchestration stage needs a model backend (see below). Without one it
falls back to the deterministic planner and says so; with `TAP_A2A_LLM=none`
that fallback is explicit and the suite is fully reproducible without any
model.

---

## Formal verification

The Tamarin model is `tap_a2a.spthy`. Tamarin is **not** required to run the
rest of the suite; if it is absent, that stage reports as skipped and the
committed results in `dissertation_results/tamarin_results.txt` stand.

To reproduce:

```bash
tamarin-prover --prove --auto-sources tap_a2a.spthy
```

or, for the full run including the ablation study:

```bash
python3 verify_tap_a2a.py
```

Tamarin 1.12 with Maude 3.1 was used. It was run on a Linux host (Google
Colab) because it does not build on the development machine's macOS version;
`verify_tap_a2a.py` is self-contained and runs anywhere Tamarin is on PATH.

Tamarin is the only prover used. Scyther was evaluated early on as an
alternative but was not adopted: it has no mutable global state, so it
cannot express nullifier freshness or revocation — the two properties this
protocol exists to provide.

**On the results.** Seven properties are verified unconditionally. Revocation
integrity is verified relative to the invariant
`agent_active_implies_not_revoked`, on which automated proof search did not
terminate; this is documented in the dissertation and in the model's own
comments. Revocation is additionally demonstrated empirically in scenario 9
of the security suite.

`verify_tap_a2a.py` also runs an ablation study: each enforcement mechanism
is removed in turn and the corresponding lemma is expected to become
FALSIFIED, evidencing that the properties hold because of those mechanisms
rather than because the model is too weak to express a violation.

---

## Layout

```
programs/tap_a2a/src/lib.rs   on-chain program (Anchor)
tap_a2a_common.py             PDA derivation, serialization, error classification
tap_a2a_client.py             RPC client, transaction helpers, commitment level
scenario_runner.py            nine security scenarios
full_gateway_benchmark.py     latency and compute-unit benchmark
agentic_orchestrator.py       multi-agent orchestration and prompt-injection test
gateway.py                    standalone off-chain policy-check reference
tap_a2a_planner.py            LangChain model-driven planner (+ deterministic fallback)
tap_a2a_messaging.py          signed agent-to-agent message layer (objective 3)
a2a_scenario_runner.py        nine A2A message-layer security scenarios
bypass_experiment.py          defence-in-depth and trace-storage experiment
audit_overhead_experiment.py  audit-trail completeness and message overhead
peer_scenario_runner.py       peer-to-peer A2A and confused-deputy scenarios
planner_comparison.py         model behaviour under injection (no validator needed)
tap_a2a_group.py              group authentication protocol (ring signatures)
group_scenario_runner.py      group authentication scenarios
tap_a2a_trs.py                Fujisaki-Suzuki traceable ring signatures
trs_benchmark.py              ring size vs cost benchmark
generate_graphs.py            figures from benchmark CSV
tap_a2a.spthy                 Tamarin model
verify_tap_a2a.py             verification + ablation runner
deploy_and_test.sh            full pipeline from a clean validator
run_all_evaluations.sh        evaluation against a running validator
tests/tap_a2a.ts              Anchor integration tests (anchor test)
```

`tap_a2a_common.py` must be kept in sync with `lib.rs` — account layouts,
PDA seeds, instruction discriminators and error codes are all mirrored there,
and the file documents each correspondence.

---

## Notes for the reader

- **Commitment level.** Benchmarks run at `confirmed`. `solana-py` defaults to
  `finalized`, which waits ~31 slots and measures Solana's finality clock
  rather than the access decision. Set `TAP_A2A_COMMITMENT=finalized` to
  obtain the irreversibility upper bound instead.
- **Scope.** W3C DIDs and Verifiable Credentials are out of scope for this
  prototype by agreement with the supervisor. Identity binding uses Ed25519
  keypairs registered on-chain.
- **A2A messaging is dispatch, not delegation.** The orchestrator asks a
  worker to exercise authority the worker already holds under standing
  policy; it does not grant or forward authority of its own. Capability
  tokens and a verifiable delegation chain would need on-chain support and
  are future work. The message layer is also not covered by the Tamarin
  model, which describes the deployed on-chain protocol.
- **Model backend.** The planner runs through LangChain. Copy `.env.example`
  to `.env` and set `TAP_A2A_LLM` to `ollama`, `google`, `openai`, `anthropic`,
  `groq`, or `none`. The committed orchestration result was produced with
  `llama3.2` via Ollama; that model complied with the prompt injection on all
  three repeats, which is what makes the enforcement scenario meaningful.
  `.env` is gitignored and must never be committed.
- **Two authentication protocols, deliberately.** The deterministic-nullifier
  protocol is fully attributable and enforced entirely on-chain. The group
  protocol is anonymous until double use and enforced partly off-chain,
  because an FS-TRS signature yields no per-signer value the chain could
  deduplicate on without identifying the signer. Neither dominates; the
  contrast is the point.
- **The nullifier is not a ring signature.** It is a deterministic one-time
  access token derived from public inputs and recomputed on-chain. It provides
  accountability, not anonymity. See the dissertation for the full discussion.
