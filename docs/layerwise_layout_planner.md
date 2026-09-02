# Runtime-aware layout planner for the Merkle layerwise baseline

The layerwise baseline answers one PIR query per tree level, each over that
level's own database. For a level with `target_num_pt` plaintexts, several
OnionPIRv2 layouts are legal: every expansion height `h` up to the reference's
gives a first dimension `N0 = 2^(h - ...)` and `Nrest = ceil(target / N0)`
remaining candidates, all scheme-compatible and all served by the same helper
keys. The legacy planner (`plan_layer_layouts(H, 96, reference)`) picks the
layout with the fewest padded plaintexts. That choice minimises storage but
not time: a larger `N0` halves the encrypted candidates the first dimension
produces (and with them the CRT compositions, inverse NTTs and CMux nodes) at
the price of more expansion substitutions and a few more padded plaintexts.

## Policies

- `legacy` (default): unchanged padding-first planner; bit-identical layouts.
- `profiled`: select, per level, the fastest *measured* legal layout under a
  global padded-storage budget (default 1.01x the legacy padded total). The
  measurements come from an offline machine profile; no benchmarking and no
  secret-dependent decision happens during a live query. Layout choice depends
  only on the public workload, the public scheme parameters and the profile.

Planning is split into three layers (`src/layer_layout_planner.{h,cpp}`):

1. **Legal enumeration**: for `h = 0..reference.expansion_height`, build
   `reference.with_layout({target_num_pt, h, pow2})`, keep layouts that are
   scheme-compatible and use at most the reference's remaining-dimension
   count.
2. **Exact features and Pareto filter**: per candidate, the public work
   counters (pruned expansion substitutions from the same tree geometry as
   `fast_expand_qry`, first-dimension query NTTs, selector rows to complete,
   CRT coefficients to compose, inverse NTTs, CMux count, padded/physical
   bytes). The Pareto frontier over the six work axes is what the sweep times;
   padding is enforced as a budget, never used for domination.
3. **Selection**: a dynamic programme over levels and excess padded plaintexts
   minimises the sum of per-level median server times. Medians within 2% are
   ordered by (physical scan bytes, expansion substitutions, inverse NTTs,
   expansion height) so noise cannot buy negligible speed with storage. Levels
   that fit one plaintext are returned in the clear (see the direct-return
   change) and keep their legacy layout.

## Reproducing

```bash
# 1. Offline profile on the target machine (one PirServer alive at a time,
#    shared helper keys, identical leaf samples, make_query time only, every
#    measured response decoded and checked).
./Onion-PIR --test layer_layout_sweep --leaf-count 16777216 \
  --warmup 2 --experiments 7 --trial-seed 5723628103747520850 \
  --layer-padding-budget 1.01 \
  --layout-profile-json outputs/merkle_baselines/layer-layout-profile-1gb.json
#    add --layout-sweep-all to also time Pareto-dominated candidates.

# 2. Benchmark with the profile (repeat --layer-layout-profile once per tree
#    height: the optional 4 GB tier is H = 26).
./Onion-PIR --test merkle_benchmarks --benchmark-case merkle_layerwise \
  --leaf-count 16777216 --warmup 3 --experiments 64 \
  --trial-seed 5723628103747520850 \
  --layer-layout-policy profiled \
  --layer-layout-profile outputs/merkle_baselines/layer-layout-profile-1gb.json \
  --benchmark-json outputs/merkle_baselines/layerwise-profiled-64.json

# 3. Attribution.
scripts/summarize_layer_layout_profile.py PROFILE.json LEGACY.json PROFILED.json
```

A profile is rejected unless its scheme fields (n, log q, log t, log q',
L_EP, L_KEY, L_KS, composite first dimension), nodes per plaintext, tree
height, architecture, CPU model, compiler and HEXL version match the running
process; `--allow-layout-profile-fallback` turns a mismatch into the legacy
plan instead of an error. The layerwise case records the policy, every
level's layout (`layers[]`) and the exact `make_query_profiled` stage sums
(`pipeline_profile_ms`) in the benchmark JSON so gains can be attributed.

## Results so far

Apple M4 (x86_64 under Rosetta 2, AVX2), 2^22 leaves, layerwise only,
3 warm-ups + 16 trials, legacy and profiled interleaved twice
(`outputs/perf/m4_layout_planner_256mb/`):

| round | legacy mean / median | profiled mean / median | median gain | padded pt | online bytes |
|---|---|---|---|---|---|
| 1 | 836.9 / 828.4 ms | 797.0 / 778.3 ms | +6.1% | 87612 -> 87668 | unchanged (422,336) |
| 2 | 827.0 / 822.8 ms | 812.2 / 785.6 ms | +4.5% | 87612 -> 87668 | unchanged |

The profile (2 + 7 trials) predicted +5.3%. Where the time went, level by
level: the planner raised the expansion height at levels 13, 17 and 18
(candidates 11 -> 3, 86 -> 22, 171 -> 43; inverse NTTs and CMux nodes shrink
by the same factors; expansion substitutions grow 31 -> 45, 59 -> 95,
63 -> 102; +8, +32, +16 padded plaintexts). The phase split confirms the
mechanism: `other_dim` fell 274 -> 243 ms and `first_dim_finalize`
80 -> 70 ms while `expand` rose 128 -> 142 ms. At 2^22 the reference
expansion height is 7, so levels 19-22 have a single legal layout; the 1 GB
tier (reference height 10) exposes the h=9 vs h=10 frontier at level 24
(683 vs 342 candidates), which is where the larger gain is expected.

## Promotion gate

`legacy` stays the default. `profiled` is promoted only when the 1 GB,
64-trial run on the target machine shows 64/64 correctness, unchanged
communication, padded bytes <= 1.01x legacy, and at least 5% median and mean
improvement, with the 4 GB tier not regressing by more than 1%. The node0
(CloudLab sm110p) run of that gate is pending: the node stopped accepting the
account's SSH keys after the experiment window, so the 1 GB/4 GB profiles and
the factorial comparison still have to be produced there.

## Deviations from the implementation plan

- The policy-aware `plan_layer_layouts` overload is declared in
  `layer_layout_planner.h` (the planner needs `LayerLayout`, so
  `merkle_baseline.h` cannot include it back); the legacy overload is untouched.
- The tight-budget selection test uses a budget of exactly 1.0 (zero extra
  plaintexts) rather than 0.1%: at H = 24 a 0.1% budget is 349 plaintexts,
  which would still admit the 256-plaintext h=10 layout.
- One profile per tree height: `--layer-layout-profile` is repeatable and the
  suite picks the profile whose `tree_height` matches each workload.
- Levels returned in the clear (single-plaintext levels) are excluded from
  the sweep and the selection; the layerwise communication accounting is the
  direct-return one, identical for both policies.
