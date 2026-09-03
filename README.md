# OnionPIR version 2

> **WARNING:** Note that this repository is for research purpose. Do not use this in production directly.

### Preliminaries

We ran our code on a `Intel(R) Xeon(R) Platinum 8358 CPU @ 2.60GHz` (Ice Lake, 32 cores per socket, AVX-512). AVX2 and AVX-512 are used to accelerate the first-dimension matrix multiply and NTT-related computation.

We use c++20 and `GCC 11.4.0` for compilation.

### Installation

OnionPIRv2 only depends on [Intel HEXL](https://github.com/intel/hexl) for fast NTT. The expected install path is set in the top-level `CMakeLists.txt` (`HEXL_DIR`) — adjust it to match your environment, or pass `-DHEXL_DIR=...` on the cmake line. HEXL is required: the ring kernels have no scalar fallback, and `-DUSE_HEXL=OFF` is rejected at configure time.

```
python3 run.py            # build (Benchmark) + run pir test on k1_comp
python3 run.py --build-only
```

### Usage

`run.py` handles building with the correct compile flags and running the binary.

```
python run.py [options]
```

| Option | Description |
|---|---|
| `-c NAME`, `--config NAME` | Build configuration (default: `k1_comp`). See available configs below |
| `-v`, `--verbose` | Build in Debug mode (enables `DEBUG_PRINT` at compile time) |
| `--no-compress` | Run PIR without query compression/decompression |
| `-t NAME`, `--test NAME` | Test to run (default: `pir`). See available tests below |
| `-n N`, `--experiments N` | Number of experiment iterations (default: 5) |
| `-w N`, `--warmup N` | Number of warmup iterations (default: 3) |
| `-o FILE`, `--output FILE` | Write results to file (bare name goes to `outputs/`) |
| `-j N`, `--jobs N` | Parallel make jobs (default: all cores) |
| `--build-only` | Build without running |
| `--leaf-count N` | Merkle benchmark leaf count; power of two (default: `2^24`) |
| `--benchmark-json FILE` | Write structured Merkle benchmark output |
| `--benchmark-case NAME` | Run `all`, only `standard_onionpir`, both `merkle_paths`, or only `merkle_layerwise` (default: `all`) |
| `--run-optional-4gb` | Attempt the resource-gated `2^26`-leaf (4 GB) workload; always 4 measured trials |
| `-h`, `--help` | Show help message |

**Examples:**

```bash
# Default: k1_comp config, pir test, 5 trials + 3 warmup
python3 run.py

# Pick a different config
python3 run.py -c k1
python3 run.py -c k2_mp
python3 run.py -c n4096_k2_mp

# Verbose/debug mode — recompiles with DEBUG_PRINT enabled
python3 run.py -v

# Save results to outputs/results.txt
python3 run.py -o results.txt

# Just build, don't run
python3 run.py --build-only

# Run a specific test
python3 run.py -t fst_dim
```

### Merkle PIR baselines on Apple Silicon

The frozen comparison uses the paper-aligned v2 configuration
`CONFIG_N2048_K1_COMP` (`n=2048`, `log(q)=58`, `log(t)=13`,
`log(q')=22`, `L_KEY=10`, `L_EP=6`, `L_KS=8`, `sigma=2.55`). On an
Apple M4 it deliberately runs an x86_64 binary with Intel HEXL 1.2.6 under
Rosetta 2:

```bash
scripts/run_merkle_baselines_x86_64.sh
```

The script builds in the isolated `build-x86_64-benchmark/` directory, checks
both the executable and HEXL archive architectures, runs the `2^24`-leaf
(1 GB paper row) workload with 3 warmups and 5 measured trials, and writes JSON
plus human-readable output under `outputs/merkle_baselines/`. Use environment
variables for a bounded smoke run, for example:

```bash
LEAF_COUNT=256 WARMUPS=0 EXPERIMENTS=1 \
  RESULT_STEM=smoke scripts/run_merkle_baselines_x86_64.sh
```

Set `TRIAL_SEED` to choose a reproducible query schedule. Warm-up and measured
query IDs are sampled without replacement, so every trial in one run uses a
different ID; all three cases reuse that same schedule for paired comparison.
Set `BENCHMARK_CASE=standard_onionpir` when repeating only the Standard case;
the runner returns before allocating or executing either Merkle-path baseline.
Set `BENCHMARK_CASE=merkle_paths` to run paired Flat and Layerwise trials
without constructing or timing Standard. Set
`BENCHMARK_CASE=merkle_layerwise` to run Layerwise alone without constructing
or timing Standard or Flat. JSON preserves every measured server-time/
throughput sample plus population and sample variance.
The top-level throughput remains database bytes divided by mean server time,
while the per-trial throughput statistics use the arithmetic mean of the
individual trial throughputs.

Set `RUN_OPTIONAL_4GB=1` to request the `2^26`-leaf (4 GB) row, which always
measures 4 trials. It is skipped
with an explicit `skipped_resource_limit` result unless estimated
preprocessed storage plus a 2 GiB safety margin fits physical memory.

The report labels these measurements
`x86_64 + Intel HEXL under Rosetta 2 on Apple M4; non-native result`. They
align protocol parameters and accounting with the paper, but they are not
native M4 measurements or a reproduction of the paper's Xeon/AVX-512 timings.
Query and helper-key byte counts are modeled seed-compressed sizes; response
bytes are measured from the repository's serializer, so totals ending in
`_mixed` are intentionally not described as fully measured wire traffic.

The canonical H=24 run from commit `fff03386deea` used 3 warmups and 5 measured
trials with seed `15794071829771909372`. Its eight query IDs are distinct and
recorded in the artifact. Full metadata and per-stage timings are in
`outputs/merkle_baselines/fff03386deea-m4-rosetta-v2-unique-queries.json`
(SHA-256 `c41b147c1d2caa432b2cf5e7bc9cc96562fb3df2874b2b1d31eb61f3492ff556`).

| Case | Avg. server time | Paper throughput (DB/time) | Repeated-scan bandwidth | Modeled queries | Actual responses | Online mixed | Shared helper keys | First session mixed |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `standard_onionpir` | 2,397.800 ms | 427.059 MiB/s | 427.059 MiB/s | 14,880 B | 11,264 B | 26,144 B | 1,488,000 B | 1,514,144 B |
| `merkle_flat` | 35,265.343 ms | 29.037 MiB/s | 696.889 MiB/s | 357,120 B | 270,336 B | 627,456 B | 1,488,000 B | 2,115,456 B |
| `merkle_layerwise` | 1,990.784 ms | 514.390 MiB/s | 514.390 MiB/s | 357,120 B | 270,336 B | 627,456 B | 1,488,000 B | 2,115,456 B |

The earlier `abaca522bc98` artifact is retained for provenance and uses the
original v1 schema, where
`paper_server_throughput_MBps` was incorrectly computed from repeated scan
bytes. Treat its 705.389 MiB/s flat value as scan bandwidth. The current schema
v2 artifact uses plaintext database bytes divided by the complete case's server
time and reports repeated work separately as `paper_scan_throughput_MBps`.

Flat scan bandwidth can still exceed layerwise scan bandwidth without a timing
error. Every H=24 flat call uses a `512 x 683` first-dimension shape. The largest
layerwise call uses `256 x 683`: it scans half as many plaintexts but still
produces 683 encrypted candidates and performs the same 682 remaining-dimension
MUX reductions. Smaller layers repeatedly pay query expansion, RGSW completion,
candidate conversion, MUX, and modulus-switch costs for progressively fewer
bytes. Those non-linear costs are amortized better by the large regular flat
scan, but flat repeats the full database 24 times. Consequently layerwise still
has 17.71x lower full-path server latency and 385.778 versus 21.778 useful
response bytes/s.

The optional H=27 row was not extrapolated: its estimated peak allocation was
45,822,181,376 bytes, so the 17,179,869,184-byte host recorded
`skipped_resource_limit` after applying the fixed 2 GiB safety margin in the
earlier gated run. All 392 decryptions in the current unique-query run passed;
the logged residual noise budget ranged from 1 to 3 bits, so the H=24 result is
correct but has a narrow minimum noise margin.

**Available configs:** `k1`, `k1_comp` (default, composite-mod K=1), `k2_mp`, `n4096_k2_mp`. See `src/includes/database_constants.h` for per-config parameters.

**Available tests:** `pir` (default), `bfv`, `ext_prod`, `ext_prod_mux`, `fst_dim`, `fast_expand`, `decrypt_mod_q`, `mod_switch`, `db_shape`, `bv_ks`, `cpu_info`, `hexl_ntt`, `utils_arith`, `noise_sampling`, `rlwe_enc`, `barrett`, `plan_params`

You can also build and run manually with CMake:

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Benchmark -DACTIVE_CONFIG=CONFIG_N2048_K1_COMP
make && ./Onion-PIR --test pir
```



### Tips

- Currently, most of the parameters can be adjusted in `src/includes/database_constants.h`. 
- You can use `clangd` when reading the code. The `compile_commands.json` file will be automatically generated after cmake.
- You can install the [Better Comments](https://marketplace.visualstudio.com/items?itemName=aaron-bond.better-comments) extension to highlight the TODO or remarked comments.
- The code also runs for clang, but we use GCC unroll in some places. Please change those lines if you want to test optimal throughput.
