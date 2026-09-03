#!/usr/bin/env bash
# One-shot regression run: every asserting PirTest through `--test all`, then
# the CLI paths that no in-process test can reach (layer_layout_sweep writing
# a profile, merkle_benchmarks consuming it under both planner policies, the
# fallback flag and the mismatch rejection). Exits non-zero on any failure.
#
#   scripts/run_regression.sh [path/to/Onion-PIR ...]
#
# With no argument the binary is build-x86_64-benchmark/Onion-PIR (the Rosetta
# x86_64 Benchmark build documented in CLAUDE.md). Several binaries, one per
# ACTIVE_CONFIG, form a configuration matrix: `--test all` runs on each and
# prints the tests that do not apply to that parameter point (the Merkle
# baselines and the ring switch need CONFIG_N2048_K1_COMP resp. K = 1); the
# CLI section runs only on binaries where the Merkle suite applies.
set -euo pipefail

BINS=("$@")
[[ ${#BINS[@]} -eq 0 ]] && BINS=(build-x86_64-benchmark/Onion-PIR)
for BIN in "${BINS[@]}"; do
  if [[ ! -x "$BIN" ]]; then
    echo "error: binary not found or not executable: $BIN" >&2
    exit 2
  fi
done
WORK="$(mktemp -d "${TMPDIR:-/tmp}/onionpir-regression.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

step() { printf '\n==> %s\n' "$*"; }

run_suite() {  # run_suite <binary>
  local BIN="$1"
  local TAG; TAG="$(basename "$(dirname "$BIN")")"
  local W="$WORK/$TAG"; mkdir -p "$W"

  step "[$TAG] in-process regression suite (--test all)"
  "$BIN" --test all --experiments 3 --warmup 1 > "$W/all.log" 2>&1 || {
    tail -n 40 "$W/all.log"; echo "FAILED: --test all ($BIN)" >&2; exit 1; }
  grep -q "Regression suite: .* tests passed" "$W/all.log"
  sed -n '/^Regression suite:/,$p' "$W/all.log"
  if grep -q "^NOT APPLICABLE merkle_integration" "$W/all.log"; then
    echo "[$TAG] Merkle suite not applicable to this build; CLI section skipped"
    return 0
  fi

  # CLI end to end at 2^8 leaves (H = 8): the sweep writes a profile file,
  # the suite loads it from disk and reports the profiled policy in its JSON.
  local PROFILE="$W/profile-h8.json"
  step "[$TAG] layer_layout_sweep -> $PROFILE"
  "$BIN" --test layer_layout_sweep --leaf-count 256 --warmup 1 --experiments 2 \
    --trial-seed 7 --layer-padding-budget 1.01 \
    --layout-profile-json "$PROFILE" > "$W/sweep.log" 2>&1
  grep -q '"schema_version": "layer-layout-profile-v1"' "$PROFILE"
  grep -q '"tree_height": 8' "$PROFILE"

  step "[$TAG] merkle_benchmarks --layer-layout-policy profiled (profile from disk)"
  "$BIN" --test merkle_benchmarks --benchmark-case merkle_layerwise \
    --leaf-count 256 --warmup 0 --experiments 1 --trial-seed 7 \
    --layer-layout-policy profiled --layer-layout-profile "$PROFILE" \
    --benchmark-json "$W/profiled.json" > "$W/profiled.log" 2>&1
  grep -q '"layer_layout_policy": "profiled"' "$W/profiled.json"
  grep -q '"correctness_passed": true' "$W/profiled.json"

  step "[$TAG] merkle_benchmarks --layer-layout-policy legacy (all three cases)"
  "$BIN" --test merkle_benchmarks --benchmark-case all \
    --leaf-count 256 --warmup 0 --experiments 1 --trial-seed 7 \
    --benchmark-json "$W/legacy.json" > "$W/legacy.log" 2>&1
  grep -q '"layer_layout_policy": "legacy"' "$W/legacy.json"
  [[ "$(grep -c '"correctness_passed": true' "$W/legacy.json")" == 3 ]]

  step "[$TAG] profiled policy with a mismatched tree height is rejected"
  if "$BIN" --test merkle_benchmarks --benchmark-case merkle_layerwise \
       --leaf-count 512 --warmup 0 --experiments 1 \
       --layer-layout-policy profiled --layer-layout-profile "$PROFILE" \
       > "$W/mismatch.log" 2>&1; then
    echo "FAILED: mismatched profile was accepted" >&2; exit 1
  fi
  grep -q "tree_height mismatch" "$W/mismatch.log"

  step "[$TAG] --allow-layout-profile-fallback turns the mismatch into the legacy plan"
  "$BIN" --test merkle_benchmarks --benchmark-case merkle_layerwise \
    --leaf-count 512 --warmup 0 --experiments 1 \
    --layer-layout-policy profiled --layer-layout-profile "$PROFILE" \
    --allow-layout-profile-fallback \
    --benchmark-json "$W/fallback.json" > "$W/fallback.log" 2>&1
  grep -q '"layer_layout_policy": "legacy"' "$W/fallback.json"

  step "[$TAG] a profile whose median disagrees with its samples is rejected"
  sed 's/"median_server_ms": [0-9.e+-]*/"median_server_ms": -1.0/' "$PROFILE" \
    > "$W/profile-drifted.json"
  if "$BIN" --test merkle_benchmarks --benchmark-case merkle_layerwise \
       --leaf-count 256 --warmup 0 --experiments 1 \
       --layer-layout-policy profiled \
       --layer-layout-profile "$W/profile-drifted.json" \
       > "$W/drifted.log" 2>&1; then
    echo "FAILED: drifted profile median was accepted" >&2; exit 1
  fi
  grep -q "does not match" "$W/drifted.log"

  step "[$TAG] argument validation"
  if "$BIN" --test merkle_benchmarks --layer-layout-policy profiled \
       --leaf-count 256 --warmup 0 --experiments 1 > "$W/noprof.log" 2>&1; then
    echo "FAILED: profiled policy without a profile was accepted" >&2; exit 1
  fi
  grep -q "requires" "$W/noprof.log"
  if "$BIN" --test layer_layout_sweep --leaf-count 256 > "$W/nojson.log" 2>&1; then
    echo "FAILED: sweep without --layout-profile-json was accepted" >&2; exit 1
  fi
  if "$BIN" --test pir --bogus-flag > "$W/bogus.log" 2>&1; then
    echo "FAILED: unknown option was accepted" >&2; exit 1
  fi
  grep -q "Unknown option" "$W/bogus.log"
  if "$BIN" --test tree_bench --leaf-count 1000 > "$W/badleaf.log" 2>&1; then
    echo "FAILED: non-power-of-two --leaf-count was accepted" >&2; exit 1
  fi
  grep -q "power of two" "$W/badleaf.log"
}

for BIN in "${BINS[@]}"; do
  run_suite "$BIN"
done

echo
echo "regression OK"
