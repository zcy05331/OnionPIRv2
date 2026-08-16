# Merkle PIR Baselines Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build correctness-gated flat-database and per-layer Merkle-path PIR baselines, then measure them beside standard OnionPIRv2 with paper-aligned v2 parameters on x86_64/HEXL under Rosetta.

**Execution status (2026-08-15):** Implemented and verified through Task 9. The canonical schema-v2 H=24 result is `outputs/merkle_baselines/fff03386deea-m4-rosetta-v2-unique-queries.json`; it records a distinct query ID for every warm-up and measured trial. The earlier gated run records H=27 as `skipped_resource_limit` rather than extrapolating it.

**Architecture:** Keep the existing OnionPIRv2 cryptographic pipeline intact while separating runtime database layout from scheme parameters. Add deterministic Merkle packing and database sources around that core, reuse one immutable client helper-key bundle across all layer servers, and run all three cases through one timing/communication collector with JSON output.

**Tech Stack:** C++20, existing OnionPIRv2 RLWE/RGSW/BV code, Intel HEXL 1.2.6, CMake, Python 3/shell launch scripts, manual JSON serialization without new dependencies.

---

## File structure

- Modify `src/includes/pir.h`, `src/pir.cpp`: runtime `PirLayoutConfig`, exact target/padded shape fields, scheme compatibility.
- Modify `src/includes/utils.h`, `src/utils.cpp`: explicit first-dimension shape policy.
- Modify `src/includes/client.h`, `src/client.cpp`: generate queries for compatible runtime layouts using one secret.
- Create `src/includes/pir_session.h`: immutable shared BV/RGSW helper-key bundle.
- Modify `src/includes/server.h`, `src/server.cpp`: shared session-key lookup and deterministic streaming plaintext loader.
- Create `src/includes/merkle_baseline.h`, `src/merkle_baseline.cpp`: node codec, Merkle indexing, layerwise planner, deterministic plaintext sources.
- Create `src/includes/merkle_benchmark.h`, `src/merkle_benchmark.cpp`: standard/flat/layerwise runners, timings, communication statistics, JSON writer, resource gate.
- Modify `src/includes/tests.h`, `src/tests/run_test.cpp`: hard-failing test dispatch and new test routes.
- Create `src/tests/test_runtime_layout.cpp`, `src/tests/test_merkle_baseline.cpp`, `src/tests/test_shared_session.cpp`, `src/tests/test_server_loader.cpp`, `src/tests/test_merkle_benchmark_stats.cpp`.
- Modify `src/tests/test_pir.cpp`: make the existing standard PIR mismatch terminate nonzero.
- Modify `src/main.cpp`, `run.py`, `README.md`: benchmark CLI integration and documented commands.
- Create `scripts/run_merkle_baselines_x86_64.sh`: isolated Rosetta/HEXL configure-build-run entry point.
- Create `outputs/merkle_baselines/.gitkeep`; generated JSON remains ignored except the final checked result chosen after verification.

### Task 1: Make the test executable fail reliably

**Files:**
- Modify: `src/includes/tests.h`
- Modify: `src/tests/run_test.cpp`
- Modify: `src/tests/test_pir.cpp`

- [ ] **Step 1: Verify the current unknown-test behavior is RED**

Run:

```bash
cmake -S . -B build-x86_64-tdd \
  -DCMAKE_OSX_ARCHITECTURES=x86_64 \
  '-DCMAKE_CXX_COMPILER=/usr/bin/arch;-x86_64;/usr/bin/clang++' \
  -DCMAKE_BUILD_TYPE=Benchmark \
  -DACTIVE_CONFIG=CONFIG_N2048_K1_COMP \
  -DUSE_HEXL=ON
cmake --build build-x86_64-tdd -j2
/usr/bin/arch -x86_64 ./build-x86_64-tdd/Onion-PIR --test definitely_missing
echo $?
```

Expected: the current executable prints `Unknown test` and exits `0`, proving the failure contract is missing.

- [ ] **Step 2: Add one reusable hard assertion**

Add to `src/includes/tests.h`:

```cpp
inline void require_test(bool condition, const std::string &message) {
  if (!condition) throw std::runtime_error(message);
}
```

Include `<stdexcept>` and change the unknown-test branch in `run_test.cpp` to:

```cpp
throw std::invalid_argument("Unknown test: " + test_name);
```

- [ ] **Step 3: Make standard PIR mismatches fail the process**

After the experiment loop in `test_pir.cpp`, add:

```cpp
require_test(success_count == num_experiments,
             "standard OnionPIR correctness mismatch");
```

- [ ] **Step 4: Build and verify GREEN**

Run:

```bash
cmake --build build-x86_64-tdd -j2
/usr/bin/arch -x86_64 ./build-x86_64-tdd/Onion-PIR --test definitely_missing >/tmp/onionpir-missing-test.log 2>&1; test $? -ne 0
```

Expected: build succeeds and the unknown test returns nonzero.

- [ ] **Step 5: Commit**

```bash
git add src/includes/tests.h src/tests/run_test.cpp src/tests/test_pir.cpp
git commit -m "Make PIR correctness failures terminate tests"
```

### Task 2: Separate runtime layout from v2 scheme parameters

**Files:**
- Modify: `src/includes/pir.h`
- Modify: `src/pir.cpp`
- Modify: `src/includes/utils.h`
- Modify: `src/utils.cpp`
- Create: `src/tests/test_runtime_layout.cpp`
- Modify: `src/includes/tests.h`
- Modify: `src/tests/run_test.cpp`

- [ ] **Step 1: Write the failing runtime-layout test**

Create `test_runtime_layout.cpp` with exact v2 anchors:

```cpp
#include "tests.h"

void PirTest::test_runtime_layout() {
  PirParams defaults;
  const PirLayoutConfig flat{349526, 10, true};
  PirParams flat_params = defaults.with_layout(flat);
  require_test(flat_params.get_target_num_pt() == 349526, "flat target");
  require_test(flat_params.get_fst_dim_sz() == 512, "flat fst dim");
  require_test(flat_params.get_num_dims() == 11, "flat dimensions");
  require_test(flat_params.get_num_pt() == 349696, "flat rounded shape");
  require_test(flat_params.get_expan_height() == 10, "flat expansion height");

  PirParams singleton = defaults.with_layout({1, 0, true});
  require_test(singleton.get_num_pt() == 1, "singleton shape");
  require_test(singleton.get_num_dims() == 1, "singleton dimensions");
  require_test(singleton.get_expan_height() == 0, "singleton expansion");

  auto [tight_fst, tight_dims] =
      utils::calculate_db_shape(43, DBConsts::L_EP, 5, false);
  require_test(tight_fst == 26 && tight_dims == 2, "explicit tight policy");
}
```

Register route `runtime_layout` in `tests.h` and `run_test.cpp`.

- [ ] **Step 2: Run RED**

Run:

```bash
cmake --build build-x86_64-tdd -j2
```

Expected: compilation fails because `PirLayoutConfig`, `with_layout`, and the four-argument `calculate_db_shape` do not exist.

- [ ] **Step 3: Add the minimal runtime-layout API**

Add to `pir.h`:

```cpp
struct PirLayoutConfig {
  size_t target_num_pt;
  size_t expansion_height;
  bool fst_dim_pow2;
};

class PirParams {
 public:
  PirParams with_layout(const PirLayoutConfig &layout) const;
  bool scheme_compatible(const PirParams &other) const;
  size_t get_target_num_pt() const { return target_num_pt_; }
  size_t get_expan_height() const { return expansion_height_; }
  bool get_fst_dim_pow2() const { return fst_dim_pow2_; }

 private:
  void apply_layout(const PirLayoutConfig &layout);
  size_t target_num_pt_ = 0;
  size_t expansion_height_ = DBConsts::TREE_HEIGHT;
  bool fst_dim_pow2_ = DBConsts::FST_DIM_POW2;
};
```

Change the shape helper declaration to:

```cpp
std::pair<size_t, size_t> calculate_db_shape(
    size_t target_num_pt, size_t l, size_t h,
    bool fst_dim_pow2 = DBConsts::FST_DIM_POW2);
```

Implement `apply_layout` by validating `target_num_pt > 0`, `h <= log2(N)`, calling the explicit-policy helper, and setting `num_pt_ = fst_dim_sz_ * roundup_div(target_num_pt_, fst_dim_sz_)`. `with_layout` copies `*this`, calls `apply_layout`, and returns the copy.

- [ ] **Step 4: Verify GREEN and default compatibility**

Run:

```bash
cmake --build build-x86_64-tdd -j2
/usr/bin/arch -x86_64 ./build-x86_64-tdd/Onion-PIR --test runtime_layout --experiments 1 --warmup 0
/usr/bin/arch -x86_64 ./build-x86_64-tdd/Onion-PIR --test db_shape --experiments 1 --warmup 0
```

Expected: both routes exit `0`; default `PirParams()` retains the compile-time 128 MiB shape.

- [ ] **Step 5: Commit**

```bash
git add src/includes/pir.h src/pir.cpp src/includes/utils.h src/utils.cpp src/tests/test_runtime_layout.cpp src/includes/tests.h src/tests/run_test.cpp
git commit -m "Make PIR database layout runtime-configurable"
```

### Task 3: Add Merkle indexing, codec, sources, and layer planner

**Files:**
- Create: `src/includes/merkle_baseline.h`
- Create: `src/merkle_baseline.cpp`
- Create: `src/tests/test_merkle_baseline.cpp`
- Modify: `src/includes/tests.h`
- Modify: `src/tests/run_test.cpp`

- [ ] **Step 1: Write failing pure-function tests**

Test these exact behaviors in `test_merkle_baseline.cpp`:

```cpp
void PirTest::test_merkle_baseline() {
  PirParams scheme;
  MerkleWorkload small{size_t{1} << 8, 8, 32};
  require_test(merkle_sibling_local(0, 8, 8) == 1, "leaf zero sibling");
  require_test(merkle_sibling_local(255, 8, 8) == 254, "last sibling");
  require_test(merkle_flat_ordinal(1, 0) == 0, "first flat node");
  require_test(merkle_flat_ordinal(8, 255) == 509, "last flat node");

  std::vector<MerkleNode> nodes(96);
  for (size_t i = 0; i < nodes.size(); ++i) nodes[i] = synthetic_merkle_node(8, i);
  RlwePt encoded = encode_merkle_nodes(nodes, scheme);
  require_test(decode_merkle_node(encoded, 0, scheme) == nodes[0], "codec first");
  require_test(decode_merkle_node(encoded, 95, scheme) == nodes[95], "codec last");

  PirParams reference = scheme.with_layout({349526, 10, true});
  auto plan = plan_layer_layouts(24, 96, reference);
  require_test(plan.at(0).params.get_expan_height() == 0, "level 1 h");
  require_test(plan.at(11).params.get_num_pt() == 48, "level 12 rounded");
  require_test(plan.at(23).params.get_num_pt() == 174848, "level 24 rounded");
  require_test(sum_padded_bytes(plan) == 1074843648ULL, "layer padded total");
}
```

- [ ] **Step 2: Run RED**

Run the build and expect missing `merkle_baseline.h`/symbols.

- [ ] **Step 3: Implement the exact public types**

Declare:

```cpp
using MerkleNode = std::array<uint8_t, 32>;
struct MerkleWorkload { size_t leaf_count; size_t tree_height; size_t node_bytes; };
struct LayerLayout { size_t level; size_t node_count; size_t target_num_pt; PirParams params; };

size_t merkle_sibling_local(size_t leaf, size_t tree_height, size_t level);
size_t merkle_flat_ordinal(size_t level, size_t local_index);
MerkleNode synthetic_merkle_node(size_t level, size_t local_index);
RlwePt encode_merkle_nodes(std::span<const MerkleNode> nodes,
                           const PirParams &params);
MerkleNode decode_merkle_node(const RlwePt &pt, size_t node_offset,
                              const PirParams &params);
RlwePt make_flat_merkle_plaintext(size_t plaintext_index,
                                  const MerkleWorkload &workload,
                                  const PirParams &params);
RlwePt make_layer_merkle_plaintext(size_t level, size_t plaintext_index,
                                   const MerkleWorkload &workload,
                                   const PirParams &params);
std::vector<LayerLayout> plan_layer_layouts(
    size_t tree_height, size_t nodes_per_pt, const PirParams &reference);
uint64_t sum_padded_bytes(const std::vector<LayerLayout> &layouts);
```

Use LSB-first 12-bit coefficient packing, reject more than 96 nodes, zero-fill the rest, and compare planner candidates by `(rounded_num_pt, fst_dim_sz + L_EP*num_other_dims, num_other_dims, h)`.

- [ ] **Step 4: Verify GREEN plus boundary failures**

Add throws for invalid level, leaf, node offset, codec capacity, and non-power-of-two leaf counts. Run `--test merkle_baseline` and expect exit `0`.

- [ ] **Step 5: Commit**

```bash
git add src/includes/merkle_baseline.h src/merkle_baseline.cpp src/tests/test_merkle_baseline.cpp src/includes/tests.h src/tests/run_test.cpp
git commit -m "Add deterministic Merkle packing and layout planning"
```

### Task 4: Stream deterministic plaintexts into server preprocessing

**Files:**
- Modify: `src/includes/server.h`
- Modify: `src/server.cpp`
- Create: `src/tests/test_server_loader.cpp`
- Modify: `src/includes/tests.h`
- Modify: `src/tests/run_test.cpp`

- [ ] **Step 1: Write the failing loader test**

Use a small runtime layout and a source that sets coefficient `i` to `(logical_index+i) % t`; assert recorded/source plaintexts and zero padding:

```cpp
void PirTest::test_server_loader() {
  PirParams params = PirParams().with_layout({3, 2, true});
  PirServer server(params);
  PlaintextSource source = [&](size_t index, RlwePt &out) {
    out.data.resize(params.get_poly_degree());
    for (size_t i = 0; i < out.data.size(); ++i)
      out.data[i] = (index + i) % params.get_plain_mod();
  };
  server.load_data(3, source, {0, 2, 3});
  require_test(server.direct_get_original_plaintext(0).data[7] == 7, "source row");
  require_test(server.direct_get_original_plaintext(2).data[7] == 9, "source row 2");
  require_test(server.direct_get_original_plaintext(3).data[7] == 0, "shape padding");
}
```

- [ ] **Step 2: Run RED**

Expected: compile fails because `PlaintextSource` and `load_data` do not exist.

- [ ] **Step 3: Refactor preprocessing behind one source callback**

Add:

```cpp
using PlaintextSource = std::function<void(size_t logical_index, RlwePt &out)>;
void load_data(size_t logical_num_pt, const PlaintextSource &source,
               const std::vector<size_t> &record_indices = {});
```

The tile loop must call `source` only for `index < logical_num_pt`, produce an all-zero plaintext otherwise, validate `out.data.size()==N` and every coefficient `< plain_mod`, then reuse the existing NTT/split/transpose code. Reimplement `gen_data` as a random source passed to the same internal preprocessing path.

- [ ] **Step 4: Verify GREEN and existing standard data generation**

Run:

```bash
/usr/bin/arch -x86_64 ./build-x86_64-tdd/Onion-PIR --test server_loader --experiments 1 --warmup 0
/usr/bin/arch -x86_64 ./build-x86_64-tdd/Onion-PIR --test fst_dim --experiments 1 --warmup 0
```

Expected: both exit `0`.

- [ ] **Step 5: Commit**

```bash
git add src/includes/server.h src/server.cpp src/tests/test_server_loader.cpp src/includes/tests.h src/tests/run_test.cpp
git commit -m "Stream deterministic plaintext sources into PIR servers"
```

### Task 5: Share one client secret and immutable helper-key bundle across layers

**Files:**
- Create: `src/includes/pir_session.h`
- Modify: `src/includes/client.h`
- Modify: `src/client.cpp`
- Modify: `src/includes/server.h`
- Modify: `src/server.cpp`
- Create: `src/tests/test_shared_session.cpp`
- Modify: `src/includes/tests.h`
- Modify: `src/tests/run_test.cpp`

- [ ] **Step 1: Write the failing shared-session integration test**

Create one reference client and helper bundle, then query deterministic servers at layouts `{1,0}`, `{43,5}`, and `{174763,9}`. Assert all decrypt correctly and every server reports the same bundle pointer.

```cpp
PirParams reference = PirParams().with_layout({349526, 10, true});
PirClient client(reference);
auto keys = client.create_session_keys();
for (const PirLayoutConfig layout : std::array{
         PirLayoutConfig{1,0,true}, {43,5,true}, {174763,9,true}}) {
  PirParams params = reference.with_layout(layout);
  PirServer server(params);
  server.set_client_session_keys(client.get_client_id(), keys);
  require_test(server.client_session_keys(client.get_client_id()).get() == keys.get(),
               "shared bundle identity");
  // load deterministic data, query last logical plaintext, decrypt and compare.
}
```

Also assert `reference.scheme_compatible(params)` for every runtime layout and that an
out-of-range plaintext index throws before encryption.

- [ ] **Step 2: Run RED**

Expected: compile fails on the missing session types and cross-layout query overload.

- [ ] **Step 3: Add the immutable bundle and cross-layout query API**

Create:

```cpp
struct PirSessionKeys {
  bvks::BvGaloisKeys bv_galois_keys;
  GSWCt gsw_key;
};
using SharedPirSessionKeys = std::shared_ptr<const PirSessionKeys>;
```

Add to `PirClient`:

```cpp
RlweCt fast_generate_query(const PirParams &query_params, size_t pt_idx);
SharedPirSessionKeys create_session_keys();
```

Make query-index and GSW-packing helpers accept `query_params`; validate scheme compatibility before using the existing secret. Keep the old one-argument method as a wrapper around `pir_params_`.

Add to `PirServer`:

```cpp
void set_client_session_keys(size_t client_id, SharedPirSessionKeys keys);
SharedPirSessionKeys client_session_keys(size_t client_id) const;
```

Use bundle lookups in expansion/completion. Keep the old maps/setters for compatibility;
key lookup prefers a registered shared bundle and otherwise falls back to the legacy map.
Baseline paths must use only the shared-bundle API.

- [ ] **Step 4: Verify GREEN**

Run shared-session, fast-expand, and standard PIR tests. Expected: all exit `0`; helper-key generation happens once in the shared-session test.

- [ ] **Step 5: Commit**

```bash
git add src/includes/pir_session.h src/includes/client.h src/client.cpp src/includes/server.h src/server.cpp src/tests/test_shared_session.cpp src/includes/tests.h src/tests/run_test.cpp
git commit -m "Share one PIR session key bundle across runtime layouts"
```

### Task 6: Implement exact communication and throughput accounting

**Files:**
- Create: `src/includes/merkle_benchmark.h`
- Create: `src/merkle_benchmark.cpp`
- Create: `src/tests/test_merkle_benchmark_stats.cpp`
- Modify: `src/includes/tests.h`
- Modify: `src/tests/run_test.cpp`

- [ ] **Step 1: Write failing byte-accounting tests**

Assert the frozen exact values without running HE:

```cpp
void PirTest::test_merkle_benchmark_stats() {
  PirParams reference = PirParams().with_layout({349526, 10, true});
  require_test(reference.get_BFV_size(true) == 14880, "query bytes");
  require_test(modeled_helper_key_bytes(reference) == 1488000, "helper bytes");
  CommunicationStats standard = communication_stats(reference, 1, {11264});
  require_test(standard.online_total_bytes_mixed == 26144, "standard online");
  require_test(standard.first_session_total_bytes_mixed == 1514144,
               "standard first session");
  CommunicationStats path = communication_stats(reference, 24,
                                                  std::vector<size_t>(24,11264));
  require_test(path.online_total_bytes_mixed == 627456, "path online");
  require_test(path.first_session_total_bytes_mixed == 2115456,
               "path first session");
}
```

- [ ] **Step 2: Run RED**

Expected: missing benchmark statistics types/functions.

- [ ] **Step 3: Implement statistics as pure checked functions**

Define `TrialTiming`, `CommunicationStats`, `BenchmarkCaseResult`, and `BenchmarkReport`. Use integer byte fields, `std::chrono::steady_clock`, and these formulas:

```cpp
paper_server_throughput_MBps =
    paper_plaintext_database_bytes / server_compute_seconds / (1ULL << 20);
paper_scan_throughput_MBps =
    paper_plaintext_scan_bytes / server_compute_seconds / (1ULL << 20);
padded_scan_throughput_MBps =
    logical_padded_scan_bytes / server_compute_seconds / (1ULL << 20);
first_session_total_bytes_mixed =
    helper_key_bytes_modeled + online_total_bytes_mixed;
```

Reject mismatched call/response counts, zero timing denominators, overflow, and communication values that differ between flat/layerwise for the same `H`.

- [ ] **Step 4: Add deterministic JSON serialization test**

Serialize a fixed report, assert required field names and byte values occur, parse it with Python's standard library, and do not add a JSON dependency.

Run:

```bash
/usr/bin/arch -x86_64 ./build-x86_64-tdd/Onion-PIR --test merkle_benchmark_stats --experiments 1 --warmup 0
python3 -m json.tool /tmp/onionpir-benchmark-stats-test.json >/dev/null
```

- [ ] **Step 5: Commit**

```bash
git add src/includes/merkle_benchmark.h src/merkle_benchmark.cpp src/tests/test_merkle_benchmark_stats.cpp src/includes/tests.h src/tests/run_test.cpp
git commit -m "Add exact Merkle PIR benchmark accounting"
```

### Task 7: Implement standard, flat, and layerwise execution cases

**Files:**
- Modify: `src/includes/merkle_benchmark.h`
- Modify: `src/merkle_benchmark.cpp`
- Modify: `src/tests/test_merkle_baseline.cpp`
- Create: `src/tests/test_merkle_integration.cpp`
- Modify: `src/includes/tests.h`
- Modify: `src/tests/run_test.cpp`

- [ ] **Step 1: Write failing H=8 and H=16 end-to-end tests**

The H=8 test must cover leaves `0`, `255`, and `128` for both layouts. The H=16 test must force more than 1024 logical nodes and exercise other-dimension MUX. Both must compare all sibling bytes against `synthetic_merkle_node(level, local)` and compare flat vs layerwise paths byte-for-byte.

- [ ] **Step 2: Run RED**

Expected: missing `run_standard_case`, `run_merkle_flat_case`, and `run_merkle_layerwise_case`.

- [ ] **Step 3: Implement one timed PIR call primitive**

Add a helper that performs exactly:

```text
query generation -> server make_query -> response serialization
-> client load/decrypt -> public node extraction
```

Measure the five frozen online fields independently. The helper accepts a reference client, compatible query params, server, client id, plaintext index, and optional node offset.

- [ ] **Step 4: Implement the three case runners**

- Standard: one deterministic flat-source plaintext query per trial on the exact reference shape.
- Flat: one preprocessed root-excluded BFS database; query levels `H..1` against it.
- Layerwise: one server per level using planner layouts and the same client/key pointer; query one sibling in each server.

Construct/destroy large cases sequentially. Record useful payload `3072` for standard and `H*32` for Merkle. Keep correctness comparison outside measured intervals.

- [ ] **Step 5: Verify GREEN**

Run:

```bash
/usr/bin/arch -x86_64 ./build-x86_64-tdd/Onion-PIR --test merkle_integration --experiments 1 --warmup 0
```

Expected: standard/flat/layerwise hard-pass, including edge/middle leaves and shared helper identity.

- [ ] **Step 6: Commit**

```bash
git add src/includes/merkle_benchmark.h src/merkle_benchmark.cpp src/tests/test_merkle_baseline.cpp src/tests/test_merkle_integration.cpp src/includes/tests.h src/tests/run_test.cpp
git commit -m "Run standard and naive Merkle PIR cases end to end"
```

### Task 8: Add the Rosetta benchmark entry point and resource gate

**Files:**
- Modify: `src/main.cpp`
- Modify: `run.py`
- Create: `scripts/run_merkle_baselines_x86_64.sh`
- Modify: `README.md`
- Modify: `.gitignore`
- Create: `outputs/merkle_baselines/.gitkeep`

- [ ] **Step 1: Write CLI failure checks**

Before implementation, verify `--test merkle_benchmarks` and `--benchmark-json` are rejected or ignored. Record the RED exit/output.

- [ ] **Step 2: Add benchmark options**

Support:

```text
--test merkle_benchmarks
--benchmark-json PATH
--leaf-count 16777216
--run-optional-8gb
--experiments 5
--warmup 3
```

Require power-of-two leaves. Default to H=24. Estimate physical bytes before constructing a server; optional H=27 runs only when estimated storage plus a fixed safety margin fits detected physical memory, otherwise emit `skipped_resource_limit` and a reason.

- [ ] **Step 3: Add the isolated x86_64 build script**

The script must execute:

```bash
cmake --fresh -S "$PROJECT_DIR" -B "$BUILD_DIR" \
  -DCMAKE_OSX_ARCHITECTURES=x86_64 \
  '-DCMAKE_CXX_COMPILER=/usr/bin/arch;-x86_64;/usr/bin/clang++' \
  -DCMAKE_BUILD_TYPE=Benchmark \
  -DACTIVE_CONFIG=CONFIG_N2048_K1_COMP \
  -DUSE_HEXL=ON
cmake --build "$BUILD_DIR" --clean-first -j2
file "$BUILD_DIR/Onion-PIR" | grep 'x86_64'
/usr/bin/arch -x86_64 "$BUILD_DIR/Onion-PIR" \
  --test merkle_benchmarks --warmup 3 --experiments 5 \
  --benchmark-json "$RESULT"
```

It must record commit, branch, OS, CPU, compiler, CMake, HEXL, architecture, Rosetta, and the non-native label in JSON.
Keep the output directory ignored except for `.gitkeep`; the final verified result is added
explicitly with `git add -f` so transient runs never become canonical accidentally.

- [ ] **Step 4: Verify CLI/build GREEN**

Run a small `--leaf-count 256 --warmup 0 --experiments 1` smoke and validate JSON with `python3 -m json.tool`. Verify flat/layerwise online bytes are equal and helper bytes are counted once.

- [ ] **Step 5: Commit**

```bash
git add src/main.cpp run.py scripts/run_merkle_baselines_x86_64.sh README.md .gitignore
git commit -m "Add reproducible Rosetta Merkle benchmark entry point"
```

### Task 9: Run correctness gates and paper-aligned measurements

**Files:**
- Create: `outputs/merkle_baselines/<commit>-m4-rosetta-v2.json`
- Create: `outputs/merkle_baselines/<commit>-m4-rosetta-v2.txt`
- Modify: `README.md` only if commands or field descriptions differ from verified behavior.

- [ ] **Step 1: Fresh x86_64/HEXL build**

Remove only the dedicated generated build directory, configure it from the current commit, build, and verify the binary and linked HEXL architectures.

- [ ] **Step 2: Run all pure and cryptographic correctness routes**

Run at minimum:

```text
runtime_layout
merkle_baseline
server_loader
shared_session
merkle_benchmark_stats
merkle_integration
fast_expand
pir
```

Every route must exit `0`; any mismatch aborts benchmark publication.

- [ ] **Step 3: Run the required 1 GiB experiment**

Execute `scripts/run_merkle_baselines_x86_64.sh`. Capture three cases with 3 warmups + 5 measured trials. Do not estimate missing timings.

- [ ] **Step 4: Validate the result artifact**

Use Python to assert:

```python
assert names == {"standard_onionpir", "merkle_flat", "merkle_layerwise"}
assert all(case["correctness_passed"] for case in cases)
assert standard["online_total_bytes_mixed"] == 26144
assert flat["online_total_bytes_mixed"] == layerwise["online_total_bytes_mixed"] == 627456
assert flat["first_session_total_bytes_mixed"] == 2115456
assert report["environment"]["architecture"] == "x86_64"
assert report["environment"]["rosetta"] is True
```

Confirm the optional 8 GiB row either contains real measurements or an explicit resource skip; never extrapolate it.

- [ ] **Step 5: Run final repository verification**

```bash
git diff --check
git status --short
python3 -m json.tool outputs/merkle_baselines/<result>.json >/dev/null
```

- [ ] **Step 6: Commit verified artifacts and report**

Commit source plus only canonical verified result artifacts with Lore trailers listing exact tested commands and any unrun optional workload.

---

## Plan self-review

- Spec coverage: runtime layout, deterministic codec/source, flat and per-layer databases, shared helper keys, hard correctness gates, online and first-session communication, three throughput byte domains, standard comparison, Rosetta build metadata, and 8 GiB resource gating each map to a task above.
- Placeholder scan: this plan contains no `TBD`, deferred implementation step, or unspecified test command.
- Type consistency: `PirLayoutConfig`, `SharedPirSessionKeys`, `MerkleNode`, `LayerLayout`, and benchmark statistics retain the same names and responsibilities from declaration through integration.
- Scope boundary: no Respire operations, native ARM64 backend, new cryptographic dependency, or claimed Xeon performance reproduction is introduced.
