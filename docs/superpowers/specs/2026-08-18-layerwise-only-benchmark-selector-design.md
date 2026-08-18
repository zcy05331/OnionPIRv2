# Layerwise-only benchmark selector design

## Goal

Measure Standard OnionPIR and Naive Layerwise independently for 32 measured
trials each, without executing Naive Flat as an unintended side effect. Both
formal runs use the frozen v2/H24 workload, x86_64 + Intel HEXL under Rosetta,
three warmups, the same deterministic trial seed, and one shared helper-key
session per case.

## Selected approach

Add `merkle_layerwise` as a fourth `BenchmarkCaseSelection` value. The selector
is accepted by the C++ CLI, `run.py`, and the benchmark shell runner's existing
`BENCHMARK_CASE` forwarding path. It calls the existing
`run_merkle_layerwise_case` implementation directly and returns exactly one
case named `merkle_layerwise`.

This is a dispatch-only change. It does not alter database construction,
cryptographic parameters, query generation, helper-key reuse, timer boundaries,
throughput formulas, response serialization, or correctness checks.

## Alternatives rejected

- Run `merkle_paths` and discard Flat: correct but adds roughly 18–20 minutes
  of unrelated Flat work and changes the machine state before Layerwise.
- Apply an uncommitted temporary patch: faster to write but makes the artifact's
  recorded commit unable to identify the executed source exactly.

## CLI and report contract

- `--benchmark-case merkle_layerwise` is valid in the native binary and
  `run.py`.
- Existing values `all`, `standard_onionpir`, and `merkle_paths` retain their
  behavior.
- A layerwise-only report contains one case, `merkle_layerwise`.
- Optional 8 GB behavior continues to use the same case selection.
- The shell runner requires no new flag; callers set
  `BENCHMARK_CASE=merkle_layerwise`.

## Test strategy

1. Extend the existing benchmark-selection regression test first.
2. Observe it fail because `BenchmarkCaseSelection::merkle_layerwise` does not
   exist.
3. Add the enum, dispatcher, CLI, and Python choice with the minimum code needed
   to pass.
4. Run the selector test, Merkle integration test, runtime-layout test, shared
   session test, and `hexl_ntt` correctness gate.
5. Run a small `2^8`-leaf layerwise-only benchmark smoke and verify the report
   contains exactly one correct case.

## Formal measurement and acceptance

- Rebuild once from the committed selector implementation.
- Use `TRIAL_SEED=2026081800000032`, `WARMUPS=3`, and `EXPERIMENTS=32` for both
  modes.
- Verify all 35 IDs in each run are distinct, both modes have identical ID
  schedules, and the 32 measured IDs do not overlap the earlier Standard-32
  schedule.
- Preserve raw server-time and per-trial throughput samples in JSON.
- Report per-run mean, median, p95, sample variance/standard deviation, headline
  database throughput, communication totals, and a trial-weighted cumulative
  comparison with prior formal artifacts.
