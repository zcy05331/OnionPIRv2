#!/usr/bin/env bash
# One-shot regression run: every asserting PirTest through `--test all`, then
# the CLI paths that no in-process test can reach (layer_layout_sweep writing
# a profile, merkle_benchmarks consuming it under both planner policies, the
# fallback flag and the mismatch rejection). Exits non-zero on any failure.
#
#   scripts/run_regression.sh [path/to/Onion-PIR]
#
# The binary defaults to build-x86_64-benchmark/Onion-PIR (the Rosetta x86_64
# Benchmark build documented in CLAUDE.md); it must be built with
# CONFIG_N2048_K1_COMP, which the Merkle suite requires.
set -euo pipefail

BIN="${1:-build-x86_64-benchmark/Onion-PIR}"
if [[ ! -x "$BIN" ]]; then
  echo "error: binary not found or not executable: $BIN" >&2
  exit 2
fi
WORK="$(mktemp -d "${TMPDIR:-/tmp}/onionpir-regression.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

step() { printf '\n==> %s\n' "$*"; }

step "in-process regression suite (--test all)"
"$BIN" --test all --experiments 3 --warmup 1 > "$WORK/all.log" 2>&1 || {
  tail -n 40 "$WORK/all.log"; echo "FAILED: --test all" >&2; exit 1; }
grep -q "Regression suite: .* tests passed" "$WORK/all.log"
tail -n 1 "$WORK/all.log"

# CLI end to end at 2^8 leaves (H = 8): the sweep writes a profile file, the
# suite loads it from disk and reports the profiled policy in its JSON.
PROFILE="$WORK/profile-h8.json"
step "layer_layout_sweep -> $PROFILE"
"$BIN" --test layer_layout_sweep --leaf-count 256 --warmup 1 --experiments 2 \
  --trial-seed 7 --layer-padding-budget 1.01 \
  --layout-profile-json "$PROFILE" > "$WORK/sweep.log" 2>&1
grep -q '"schema_version": "layer-layout-profile-v1"' "$PROFILE"
grep -q '"tree_height": 8' "$PROFILE"

step "merkle_benchmarks --layer-layout-policy profiled (profile from disk)"
"$BIN" --test merkle_benchmarks --benchmark-case merkle_layerwise \
  --leaf-count 256 --warmup 0 --experiments 1 --trial-seed 7 \
  --layer-layout-policy profiled --layer-layout-profile "$PROFILE" \
  --benchmark-json "$WORK/profiled.json" > "$WORK/profiled.log" 2>&1
grep -q '"layer_layout_policy": "profiled"' "$WORK/profiled.json"
grep -q '"correctness_passed": true' "$WORK/profiled.json"

step "merkle_benchmarks --layer-layout-policy legacy (all three cases)"
"$BIN" --test merkle_benchmarks --benchmark-case all \
  --leaf-count 256 --warmup 0 --experiments 1 --trial-seed 7 \
  --benchmark-json "$WORK/legacy.json" > "$WORK/legacy.log" 2>&1
grep -q '"layer_layout_policy": "legacy"' "$WORK/legacy.json"
[[ "$(grep -c '"correctness_passed": true' "$WORK/legacy.json")" == 3 ]]

step "profiled policy with a mismatched tree height is rejected"
if "$BIN" --test merkle_benchmarks --benchmark-case merkle_layerwise \
     --leaf-count 512 --warmup 0 --experiments 1 \
     --layer-layout-policy profiled --layer-layout-profile "$PROFILE" \
     > "$WORK/mismatch.log" 2>&1; then
  echo "FAILED: mismatched profile was accepted" >&2; exit 1
fi
grep -q "tree_height mismatch" "$WORK/mismatch.log"

step "--allow-layout-profile-fallback turns the mismatch into the legacy plan"
"$BIN" --test merkle_benchmarks --benchmark-case merkle_layerwise \
  --leaf-count 512 --warmup 0 --experiments 1 \
  --layer-layout-policy profiled --layer-layout-profile "$PROFILE" \
  --allow-layout-profile-fallback \
  --benchmark-json "$WORK/fallback.json" > "$WORK/fallback.log" 2>&1
grep -q '"layer_layout_policy": "legacy"' "$WORK/fallback.json"

step "argument validation"
if "$BIN" --test merkle_benchmarks --layer-layout-policy profiled \
     --leaf-count 256 --warmup 0 --experiments 1 > "$WORK/noprof.log" 2>&1; then
  echo "FAILED: profiled policy without a profile was accepted" >&2; exit 1
fi
grep -q "requires" "$WORK/noprof.log"
if "$BIN" --test layer_layout_sweep --leaf-count 256 > "$WORK/nojson.log" 2>&1; then
  echo "FAILED: sweep without --layout-profile-json was accepted" >&2; exit 1
fi
if "$BIN" --test pir --bogus-flag > "$WORK/bogus.log" 2>&1; then
  echo "FAILED: unknown option was accepted" >&2; exit 1
fi
grep -q "Unknown option" "$WORK/bogus.log"

echo
echo "regression OK"
