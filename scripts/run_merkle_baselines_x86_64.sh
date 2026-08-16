#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/build-x86_64-benchmark"
OUTPUT_DIR="${PROJECT_DIR}/outputs/merkle_baselines"
HEXL_CMAKE_DIR="${HEXL_CMAKE_DIR:-${PROJECT_DIR}/hexl_install/lib64/cmake/hexl-1.2.6}"
HEXL_ARCHIVE="${PROJECT_DIR}/hexl_install/lib64/libhexl.a"
JOBS="${JOBS:-2}"
LEAF_COUNT="${LEAF_COUNT:-16777216}"
WARMUPS="${WARMUPS:-3}"
EXPERIMENTS="${EXPERIMENTS:-5}"
TRIAL_SEED="${TRIAL_SEED:-5723628103747520850}"
RUN_OPTIONAL_8GB="${RUN_OPTIONAL_8GB:-0}"

COMMIT="$(git -C "${PROJECT_DIR}" rev-parse HEAD)"
SHORT_COMMIT="$(git -C "${PROJECT_DIR}" rev-parse --short=12 HEAD)"
BRANCH="$(git -C "${PROJECT_DIR}" branch --show-current)"
RESULT_STEM="${RESULT_STEM:-${SHORT_COMMIT}-m4-rosetta-v2}"
RESULT_JSON="${RESULT_JSON:-${OUTPUT_DIR}/${RESULT_STEM}.json}"
RESULT_TEXT="${RESULT_TEXT:-${OUTPUT_DIR}/${RESULT_STEM}.txt}"

mkdir -p "${OUTPUT_DIR}"

# Homebrew CMake is arm64-only on this host. Keep configure/build native and
# execute every compiler invocation through Rosetta instead.
cmake --fresh -S "${PROJECT_DIR}" -B "${BUILD_DIR}" \
  -DCMAKE_OSX_ARCHITECTURES=x86_64 \
  '-DCMAKE_CXX_COMPILER=/usr/bin/arch;-x86_64;/usr/bin/clang++' \
  -DCMAKE_BUILD_TYPE=Benchmark \
  -DACTIVE_CONFIG=CONFIG_N2048_K1_COMP \
  -DUSE_HEXL=ON \
  -DHEXL_DIR="${HEXL_CMAKE_DIR}"
cmake --build "${BUILD_DIR}" --clean-first -j"${JOBS}"

BINARY="${BUILD_DIR}/Onion-PIR"
file "${BINARY}" | grep -q 'Mach-O 64-bit executable x86_64'
lipo -info "${HEXL_ARCHIVE}" | grep -q 'architecture: x86_64'
PROCESS_ARCH="$(/usr/bin/arch -x86_64 /usr/bin/uname -m)"
test "${PROCESS_ARCH}" = "x86_64"
ROSETTA_FLAG="$(/usr/bin/arch -x86_64 /usr/sbin/sysctl -in sysctl.proc_translated 2>/dev/null || true)"
test "${ROSETTA_FLAG}" = "1"

OS_METADATA="$(sw_vers | tr '\n' ';' | sed 's/;$/;/')"
CPU_METADATA="$(sysctl -n machdep.cpu.brand_string)"
COMPILER_METADATA="$(/usr/bin/arch -x86_64 /usr/bin/clang++ --version | sed -n '1p')"
CMAKE_METADATA="$(cmake --version | sed -n '1p')"

RUN_ARGS=(
  --test merkle_benchmarks
  --leaf-count "${LEAF_COUNT}"
  --warmup "${WARMUPS}"
  --experiments "${EXPERIMENTS}"
  --trial-seed "${TRIAL_SEED}"
  --benchmark-json "${RESULT_JSON}"
)
if [[ "${RUN_OPTIONAL_8GB}" == "1" ]]; then
  RUN_ARGS+=(--run-optional-8gb)
elif [[ "${RUN_OPTIONAL_8GB}" != "0" ]]; then
  echo "RUN_OPTIONAL_8GB must be 0 or 1" >&2
  exit 2
fi

ONIONPIR_BENCH_COMMIT="${COMMIT}" \
ONIONPIR_BENCH_BRANCH="${BRANCH}" \
ONIONPIR_BENCH_PROCESS_ARCH="${PROCESS_ARCH}" \
ONIONPIR_BENCH_OS="${OS_METADATA}" \
ONIONPIR_BENCH_CPU="${CPU_METADATA}" \
ONIONPIR_BENCH_COMPILER="${COMPILER_METADATA}" \
ONIONPIR_BENCH_CMAKE="${CMAKE_METADATA}" \
ONIONPIR_BENCH_HEXL_PATH="${HEXL_CMAKE_DIR}" \
  /usr/bin/arch -x86_64 "${BINARY}" "${RUN_ARGS[@]}" | tee "${RESULT_TEXT}"

python3 -m json.tool "${RESULT_JSON}" >/dev/null
echo "Validated JSON: ${RESULT_JSON}"
echo "Human-readable log: ${RESULT_TEXT}"
