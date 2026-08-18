# Layerwise-only Benchmark Selector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an auditable `merkle_layerwise` benchmark selection that runs only the existing Layerwise case.

**Architecture:** Extend the existing selection enum and dispatch branch; do not create a second Layerwise implementation. Keep the shell runner generic by forwarding its existing `BENCHMARK_CASE` value, and expose the new value through both native and Python CLIs.

**Tech Stack:** C++20, existing OnionPIRv2 test dispatcher, Python argparse, Bash benchmark runner, CMake, Intel HEXL under Rosetta.

---

### Task 1: Add the selector through test-first dispatch changes

**Files:**
- Modify: `src/tests/test_merkle_benchmark_stats.cpp`
- Modify: `src/includes/merkle_benchmark.h`
- Modify: `src/merkle_benchmark.cpp`
- Modify: `src/main.cpp`
- Modify: `run.py`
- Modify: `README.md`

- [ ] **Step 1: Write the failing report-selection test**

Append to `PirTest::test_merkle_benchmark_stats()` after the existing
`merkle_paths` assertions:

```cpp
  MerkleBenchmarkOptions layerwise_only_options = options;
  layerwise_only_options.case_selection =
      BenchmarkCaseSelection::merkle_layerwise;
  BenchmarkReport layerwise_only_report =
      run_merkle_benchmark_suite(layerwise_only_options);
  require_test(layerwise_only_report.cases.size() == 1,
               "layerwise-only selection must execute exactly one case");
  require_test(layerwise_only_report.cases[0].name == "merkle_layerwise",
               "layerwise-only selection must exclude Standard and Flat");
```

- [ ] **Step 2: Verify RED**

Run the x86_64/HEXL build:

```bash
cmake --build build-x86_64-benchmark -j2
```

Expected: compilation fails because
`BenchmarkCaseSelection::merkle_layerwise` is not declared.

- [ ] **Step 3: Add the minimal enum and dispatcher**

Add the enum member in `src/includes/merkle_benchmark.h`:

```cpp
enum class BenchmarkCaseSelection {
  all,
  standard_onionpir,
  merkle_paths,
  merkle_layerwise,
};
```

In `execute_case_set()` accept the new value, run Standard only for `all` or
`standard_onionpir`, and return a single existing Layerwise result for the new
selection:

```cpp
  if (selection == BenchmarkCaseSelection::all ||
      selection == BenchmarkCaseSelection::standard_onionpir) {
    BenchmarkCaseExecution standard =
        run_standard_case(workload, reference, trials);
    standard.result.name += name_suffix;
    results.push_back(std::move(standard.result));
    if (selection == BenchmarkCaseSelection::standard_onionpir) {
      return results;
    }
  }

  if (selection == BenchmarkCaseSelection::merkle_layerwise) {
    BenchmarkCaseExecution layerwise =
        run_merkle_layerwise_case(workload, reference, trials);
    layerwise.result.name += name_suffix;
    results.push_back(std::move(layerwise.result));
    return results;
  }
```

Leave the existing paired Flat/Layerwise path and cross-case equality checks
unchanged for `all` and `merkle_paths`.

- [ ] **Step 4: Expose the value through both CLIs**

In `src/main.cpp`, map the string to the enum and include it in the validation
message:

```cpp
        } else if (value == "merkle_layerwise") {
          benchmark_case = BenchmarkCaseSelection::merkle_layerwise;
```

In `run.py`, extend argparse choices:

```python
choices=("all", "standard_onionpir", "merkle_paths", "merkle_layerwise")
```

- [ ] **Step 5: Document the dispatch-only option**

Update the README option table and runner section to say that
`BENCHMARK_CASE=merkle_layerwise` executes Layerwise without constructing or
timing Standard or Flat.

- [ ] **Step 6: Verify GREEN and regression coverage**

Run:

```bash
cmake --build build-x86_64-benchmark -j2
/usr/bin/arch -x86_64 build-x86_64-benchmark/Onion-PIR --test merkle_benchmark_stats --experiments 1 --warmup 0
/usr/bin/arch -x86_64 build-x86_64-benchmark/Onion-PIR --test merkle_integration --experiments 1 --warmup 0
/usr/bin/arch -x86_64 build-x86_64-benchmark/Onion-PIR --test shared_session --experiments 1 --warmup 0
/usr/bin/arch -x86_64 build-x86_64-benchmark/Onion-PIR --test hexl_ntt --experiments 1 --warmup 0
/usr/bin/arch -x86_64 build-x86_64-benchmark/Onion-PIR --test merkle_benchmarks --leaf-count 256 --experiments 1 --warmup 0 --benchmark-case merkle_layerwise
python3 run.py --help
git diff --check
```

Expected: every test exits zero; the smoke report prints exactly one
`merkle_layerwise,true` case; Python help lists the new choice.

- [ ] **Step 7: Commit the implementation**

Stage only the six files above and commit with Lore trailers recording the
dispatch-only scope, Rosetta test evidence, and the absence of a full H24 run
at implementation time.

### Task 2: Run and validate the paired formal measurements

**Files:**
- Create: `outputs/merkle_baselines/${short_commit}-m4-rosetta-v2-standard-32-20260818.json`
- Create: `outputs/merkle_baselines/${short_commit}-m4-rosetta-v2-standard-32-20260818.txt`
- Create: `outputs/merkle_baselines/${short_commit}-m4-rosetta-v2-layerwise-32-20260818.json`
- Create: `outputs/merkle_baselines/${short_commit}-m4-rosetta-v2-layerwise-32-20260818.txt`

- [ ] **Step 1: Run Standard from the selector commit**

```bash
short_commit=$(git rev-parse --short=12 HEAD)
JOBS=2 WARMUPS=3 EXPERIMENTS=32 TRIAL_SEED=2026081800000032 \
BENCHMARK_CASE=standard_onionpir \
RESULT_STEM="${short_commit}-m4-rosetta-v2-standard-32-20260818" \
scripts/run_merkle_baselines_x86_64.sh
```

- [ ] **Step 2: Run Layerwise from the same selector commit**

```bash
short_commit=$(git rev-parse --short=12 HEAD)
JOBS=2 WARMUPS=3 EXPERIMENTS=32 TRIAL_SEED=2026081800000032 \
BENCHMARK_CASE=merkle_layerwise \
RESULT_STEM="${short_commit}-m4-rosetta-v2-layerwise-32-20260818" \
scripts/run_merkle_baselines_x86_64.sh
```

- [ ] **Step 3: Validate and summarize**

Parse both JSON artifacts and assert:

```text
schema_version == onionpir-merkle-baselines-v2
environment.architecture == x86_64
environment.rosetta == true
workload.leaf_count == 16777216
workload.warmups == 3
workload.measured_trials == 32
workload.trial_seed == 2026081800000032
all 35 query IDs are distinct
Standard and Layerwise query schedules are identical
each report contains exactly one correctness-passing case
each case stores exactly 32 positive server-time samples
```

Compute new-run and cumulative trial-weighted latency/throughput summaries from
the preserved JSON artifacts. Commit the two formal JSON/TXT pairs with their
SHA-256 hashes and test evidence in the Lore commit message.
