#!/bin/bash
# =============================================================================
# run_perf_suite.sh — 一键式全协议性能测试: 每种协议 x {1GB, 8GB} DB x 64 次
#
# 一键跑全部(默认即此, 无需参数):
#   scripts/run_perf_suite.sh
#
# 覆盖的协议模式("每一种"):
#   merkle    merkle_benchmarks 套件: standard OnionPIR + flat + layerwise。
#             一次调用同时产出 1GB(2^24 叶, 主档)与 8GB(2^27 叶,
#             --run-optional-8gb, 套件自带 物理内存+2GB 安全门)两档,
#             次数吃 --experiments。
#   tree      tree_bench_g32: Tree PIR MVP, 32 字节节点。L/次数是编译期常量,
#             本脚本按档补丁 L(1GB->L=24, 8GB->L=27)与 kTrials 后重建再跑
#             (与 run_all_combos.sh 修改 database_constants.h 的先例一致)。
#   tree-g1   tree_bench: g=1 标量 MVP(诊断性基准, 叶数与各档对齐,
#             但每节点只有 12bit, 载荷字节数不等于 1GB/8GB, 报告里注意)。
#   compress  tree_compress: M7 小环压缩门(固定小形状, 无 DB 档位, 只跑一次)。
#   cuckoo    cuckoo_bench: cuckoo batch baseline。仅当检出含该测试
#             (codex/cuckoo-batch-baseline 分支)时自动加入, 同样按档补丁。
#
# 旋钮(环境变量):
#   EXPERIMENTS=64  每种的测量次数        WARMUPS=3
#   SCALES="1gb 8gb"  只想跑一档可设 SCALES=1gb
#   TRIAL_SEED=5723628103747520850(与已提交结果同种子)
#   JOBS=<nproc>    NOAVX512=OFF    SKIP_BUILD=0(=1 时不重建, 仅单档可用)
#
# 异机准备:
#   1) git clone <repo> && cd OnionPIRv2 && git checkout <分支/commit>
#   2) 需要 cmake>=3.13、C++20 编译器(gcc>=13 / 近年 clang)、git、perl;
#      HEXL 依赖自动 clone(intel/hexl v1.2.6)装进 hexl_install/(gitignored;
#      无外网可从同 OS+同架构机器拷贝该目录, 已存在即跳过)
#   3) 内存: 8GB 档的 flat 基线与 tree MVP 峰值都远超 8GB(系数展开 ~5-16x),
#      merkle 套件自带内存门, tree/cuckoo 由本脚本粗估门控, 不够则记 skip;
#      tree 8GB 档(L=27)粗估需 ~130GB, 请在大内存服务器上跑
#   4) 时长量级(参考 M4): flat 1GB 档 ~80s/次 x 67 ≈ 1.5h, 8GB 档再 ~8x;
#      预留过夜时间, 建议 nohup/tmux 里跑
#
# 架构(强制 HEXL): Linux/macOS x86_64 原生; Apple Silicon 走 Rosetta;
#   其他架构直接报错(HEXL 是 x86 intrinsics 库, 无法给出可比数字)。
#
# 产出: outputs/perf/<机器>_<短commit>_<UTC>/
#   00_meta.txt 00_cpu.txt cpu_info.txt
#   merkle.txt merkle.json(内含 1GB 与 8GB 两档 case)
#   tree_g32_{1gb,8gb}.txt tree_g1_{1gb,8gb}.txt cuckoo_{1gb,8gb}.txt
#   compress.txt
# =============================================================================
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_DIR}"

# ---------------- 旋钮 ----------------
EXPERIMENTS="${EXPERIMENTS:-64}"
WARMUPS="${WARMUPS:-3}"
TRIAL_SEED="${TRIAL_SEED:-5723628103747520850}"
BENCHMARK_CASE="${BENCHMARK_CASE:-all}"
SCALES="${SCALES:-1gb 8gb}"
NOAVX512="${NOAVX512:-OFF}"
SKIP_BUILD="${SKIP_BUILD:-0}"
ACTIVE_CONFIG="${ACTIVE_CONFIG:-CONFIG_N2048_K1_COMP}"
HEXL_VERSION="1.2.6"

scale_leaf_pow() {  # 档位 -> log2(叶数): 与套件的 paper_row 标签一致
  case "$1" in
    1gb) echo 24 ;;
    8gb) echo 27 ;;
    *) echo "未知档位 $1(可选 1gb 8gb)" >&2; exit 2 ;;
  esac
}

# ---------------- 平台探测(强制 HEXL, 非 x86_64 只认 Rosetta) ----------------
OS="$(uname -s)"
ARCH="$(uname -m)"
ROSETTA=0
CXX_LAUNCH=()
CMAKE_ARCH_FLAGS=()
if [[ "${OS}" == "Darwin" && "${ARCH}" == "arm64" ]]; then
  ROSETTA=1
  CXX_LAUNCH=(/usr/bin/arch -x86_64)
  CMAKE_ARCH_FLAGS=(
    -DCMAKE_OSX_ARCHITECTURES=x86_64
    '-DCMAKE_CXX_COMPILER=/usr/bin/arch;-x86_64;/usr/bin/clang++'
  )
elif [[ "${ARCH}" != "x86_64" ]]; then
  echo "错误: 本套件要求启用 HEXL, 而 HEXL 只支持 x86_64(当前 ${OS}/${ARCH})." >&2
  echo "请换用 x86_64 机器, 或 Apple Silicon Mac(自动走 Rosetta)." >&2
  exit 1
fi

if [[ "${OS}" == "Linux" ]]; then
  DEFAULT_JOBS="$(nproc 2>/dev/null || echo 4)"
  MEM_BYTES="$(awk '/^MemTotal/{print $2*1024}' /proc/meminfo 2>/dev/null || echo 0)"
else
  DEFAULT_JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"
  MEM_BYTES="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
fi
JOBS="${JOBS:-${DEFAULT_JOBS}}"

# ---------------- 依赖: Intel HEXL(仓库本地安装, gitignored) ----------------
HEXL_PREFIX="${PROJECT_DIR}/hexl_install"
HEXL_CMAKE_DIR="${HEXL_PREFIX}/lib64/cmake/hexl-${HEXL_VERSION}"
if [[ ! -d "${HEXL_CMAKE_DIR}" ]]; then
  echo "==> 未找到 hexl_install/, 自动构建 Intel HEXL v${HEXL_VERSION}"
  HEXL_SRC="${PROJECT_DIR}/.deps/hexl-src"
  if [[ ! -d "${HEXL_SRC}" ]]; then
    mkdir -p "${PROJECT_DIR}/.deps"
    git clone --depth 1 -b "v${HEXL_VERSION}" \
        https://github.com/intel/hexl.git "${HEXL_SRC}" \
      || git clone --depth 1 -b "${HEXL_VERSION}" \
        https://github.com/intel/hexl.git "${HEXL_SRC}"
  fi
  cmake -S "${HEXL_SRC}" -B "${PROJECT_DIR}/.deps/hexl-build" \
    ${CMAKE_ARCH_FLAGS[@]+"${CMAKE_ARCH_FLAGS[@]}"} \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${HEXL_PREFIX}" \
    -DCMAKE_INSTALL_LIBDIR=lib64 \
    -DHEXL_BENCHMARK=OFF -DHEXL_TESTING=OFF
  cmake --build "${PROJECT_DIR}/.deps/hexl-build" -j"${JOBS}"
  cmake --install "${PROJECT_DIR}/.deps/hexl-build"
  test -d "${HEXL_CMAKE_DIR}" || {
    echo "HEXL 安装后未见 ${HEXL_CMAKE_DIR}" >&2; exit 1; }
fi

# ---------------- 编译期规模常量的补丁机制 ----------------
# tree 系基准的 L 与 kTrials/kWarmups 是编译期常量; 逐档 perl 补丁 + 重建,
# 退出时(含 Ctrl-C/出错)从备份恢复原文件。锚定完整语句, 不碰其他代码。
PATCH_FILES=(src/tests/test_tree_benchmark_g32.cpp src/tests/test_tree_benchmark.cpp)
[[ -f src/tests/test_cuckoo_batch.cpp ]] && PATCH_FILES+=(src/tests/test_cuckoo_batch.cpp)
BACKUP_DIR="${PROJECT_DIR}/.perf-suite-backup"
rm -rf "${BACKUP_DIR}" && mkdir -p "${BACKUP_DIR}"
for f in "${PATCH_FILES[@]}"; do
  cp "${f}" "${BACKUP_DIR}/$(basename "${f}")"
done
restore_patches() {
  for f in "${PATCH_FILES[@]}"; do
    cp "${BACKUP_DIR}/$(basename "${f}")" "${f}"
  done
  echo "[restore] 已恢复补丁前的测试源文件"
}
trap 'restore_patches; rm -rf "${BACKUP_DIR}"' EXIT

apply_scale_patch() {  # apply_scale_patch <L>
  local L="$1"
  restore_patches >/dev/null   # 先恢复再补丁, 保证幂等
  # L: tree 测试里对 make_tree_pir_params_for_scheme 的首个实参就是层数
  perl -pi -e "s/make_tree_pir_params_for_scheme\(\s*\d+,/make_tree_pir_params_for_scheme(${L},/g;
               s/constexpr size_t kTrials = \d+;/constexpr size_t kTrials = ${EXPERIMENTS};/;
               s/constexpr size_t kWarmups = \d+;/constexpr size_t kWarmups = ${WARMUPS};/" \
    src/tests/test_tree_benchmark_g32.cpp src/tests/test_tree_benchmark.cpp
  if [[ -f src/tests/test_cuckoo_batch.cpp ]]; then
    # 区段守卫: 只改 test_cuckoo_benchmark 函数之后的常量,
    # 避免误伤同文件里正确性测试(test_cuckoo_batch)的小规模 tree_height
    perl -pi -e '$bench = 1 if /test_cuckoo_benchmark/;
                 if ($bench) {
                   s/const size_t tree_height = \d+;/const size_t tree_height = '"${L}"';/;
                   s/constexpr size_t kTrials = \d+;/constexpr size_t kTrials = '"${EXPERIMENTS}"';/;
                   s/constexpr size_t kWarmups = \d+;/constexpr size_t kWarmups = '"${WARMUPS}"';/;
                 }' src/tests/test_cuckoo_batch.cpp
  fi
}

# 粗估内存门(单位: 字节)。tree MVP: canonical u64 系数 + m32 视图合计约
# 2^(L+10)(L=22 实测 ~4GB 量级外推); cuckoo: 3 hash 复制 + 稠密打包同量级。
# 不够(含 2GB 余量)则跳过该档并记录原因, 避免过夜 OOM 白跑。
mem_gate() {  # mem_gate <名字> <所需字节> -> 0 通过
  local name="$1" need="$2"
  local margin=$((2 << 30))
  if [[ "${MEM_BYTES}" -gt 0 && $((need + margin)) -gt "${MEM_BYTES}" ]]; then
    echo "[skip] ${name}: 粗估峰值 ${need}B + 2GB 余量 > 物理内存 ${MEM_BYTES}B" >&2
    return 1
  fi
  return 0
}

# ---------------- 构建 ----------------
BUILD_DIR="${PROJECT_DIR}/build-perf-suite"
BINARY="${BUILD_DIR}/Onion-PIR"
CONFIGURED=0
build_binary() {
  [[ "${SKIP_BUILD}" == "1" ]] && return 0
  if [[ "${CONFIGURED}" == "0" ]]; then
    local args=(
      -S "${PROJECT_DIR}" -B "${BUILD_DIR}"
      -DCMAKE_BUILD_TYPE=Benchmark
      -DACTIVE_CONFIG="${ACTIVE_CONFIG}"
      -DUSE_HEXL=ON
      -DHEXL_DIR="${HEXL_CMAKE_DIR}"
      -DNOAVX512="${NOAVX512}"
    )
    if [[ ${#CMAKE_ARCH_FLAGS[@]} -gt 0 ]]; then
      args+=("${CMAKE_ARCH_FLAGS[@]}")
    fi
    # --fresh 防旧缓存; cmake<3.24 无此旗标则清缓存重试
    cmake --fresh "${args[@]}" 2>/dev/null \
      || { rm -rf "${BUILD_DIR}/CMakeCache.txt" "${BUILD_DIR}/CMakeFiles"; \
           cmake "${args[@]}"; }
    CONFIGURED=1
  fi
  cmake --build "${BUILD_DIR}" -j"${JOBS}"
}

# ---------------- 结果目录与机器元数据 ----------------
COMMIT="$(git rev-parse HEAD)"
SHORT_COMMIT="$(git rev-parse --short=12 HEAD)"
BRANCH="$(git branch --show-current || echo detached)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
HOST_TAG="$(hostname -s | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9\n' '-')"
OUT_DIR="${PROJECT_DIR}/outputs/perf/${HOST_TAG}_${SHORT_COMMIT}_${STAMP}"
mkdir -p "${OUT_DIR}"

if [[ "${OS}" == "Linux" ]]; then
  CPU_METADATA="$(awk -F': *' '/^model name/{print $2; exit}' /proc/cpuinfo)"
  lscpu > "${OUT_DIR}/00_cpu.txt" 2>&1 || true
  OS_METADATA="$(uname -a)"
else
  CPU_METADATA="$(sysctl -n machdep.cpu.brand_string)"
  sysctl machdep.cpu hw.ncpu hw.memsize > "${OUT_DIR}/00_cpu.txt" 2>&1 || true
  OS_METADATA="$(sw_vers | tr '\n' ';')"
fi
COMPILER_METADATA="$(${CXX_LAUNCH[@]+"${CXX_LAUNCH[@]}"} \
  "${CXX:-c++}" --version 2>/dev/null | sed -n 1p || echo unknown)"
CMAKE_METADATA="$(cmake --version | sed -n 1p)"

{
  echo "commit:      ${COMMIT} (${BRANCH})"
  echo "utc:         ${STAMP}"
  echo "os:          ${OS_METADATA}"
  echo "cpu:         ${CPU_METADATA}  mem=${MEM_BYTES}B"
  echo "arch:        ${ARCH} rosetta=${ROSETTA}"
  echo "compiler:    ${COMPILER_METADATA}"
  echo "cmake:       ${CMAKE_METADATA}"
  echo "hexl:        ${HEXL_CMAKE_DIR} NOAVX512=${NOAVX512}"
  echo "config:      ${ACTIVE_CONFIG}"
  echo "knobs:       trials=${EXPERIMENTS} warmup=${WARMUPS}" \
       "seed=${TRIAL_SEED} scales='${SCALES}' case=${BENCHMARK_CASE}"
  git status --short
} > "${OUT_DIR}/00_meta.txt"

run_bin() {  # run_bin <日志名> <参数...>; 单模式失败不终止整个套件
  local log="${OUT_DIR}/$1"; shift
  echo "==> $* | tee ${log}"
  if ! ${CXX_LAUNCH[@]+"${CXX_LAUNCH[@]}"} "${BINARY}" "$@" 2>&1 | tee "${log}"; then
    echo "[fail] 该模式退出非零, 详见 ${log}(套件继续)" >&2
  fi
}

# ---------------- 模式选择 ----------------
MODES=("$@")
if [[ ${#MODES[@]} -eq 0 ]]; then
  MODES=(merkle tree tree-g1 compress)
  if grep -q 'cuckoo_bench' src/tests/run_test.cpp 2>/dev/null; then
    MODES+=(cuckoo)
  else
    echo "[info] 当前检出无 cuckoo_bench(在 codex/cuckoo-batch-baseline 分支), 跳过"
  fi
fi
has_mode() { local m; for m in "${MODES[@]}"; do [[ "$m" == "$1" ]] && return 0; done; return 1; }
for MODE in "${MODES[@]}"; do
  case "${MODE}" in merkle|tree|tree-g1|compress|cuckoo) ;;
    *) echo "未知模式: ${MODE}(可选 merkle tree tree-g1 compress cuckoo)" >&2; exit 2 ;;
  esac
done

# ---------------- 执行: 逐档补丁->重建->跑 ----------------
FIRST_SCALE=1
for SCALE in ${SCALES}; do
  LEAF_POW="$(scale_leaf_pow "${SCALE}")"
  echo "=================== 档位 ${SCALE}(L=${LEAF_POW}) ==================="
  apply_scale_patch "${LEAF_POW}"
  build_binary
  test -x "${BINARY}" || { echo "缺少 ${BINARY}" >&2; exit 1; }
  if [[ "${ROSETTA}" == "1" ]]; then
    file "${BINARY}" | grep -q 'x86_64' || { echo "二进制不是 x86_64" >&2; exit 1; }
  fi

  if [[ "${FIRST_SCALE}" == "1" ]]; then
    run_bin cpu_info.txt --test cpu_info

    # merkle 套件一次调用覆盖两档: 主档 2^24(1GB), SCALES 含 8gb 时加
    # --run-optional-8gb 让同一进程完整测量 2^27(内存不够则套件自记 skip)
    if has_mode merkle; then
      MERKLE_ARGS=(--test merkle_benchmarks
        --leaf-count $((1 << 24)) --warmup "${WARMUPS}"
        --experiments "${EXPERIMENTS}" --trial-seed "${TRIAL_SEED}"
        --benchmark-case "${BENCHMARK_CASE}"
        --benchmark-json "${OUT_DIR}/merkle.json")
      case " ${SCALES} " in *" 8gb "*) MERKLE_ARGS+=(--run-optional-8gb) ;; esac
      ONIONPIR_BENCH_COMMIT="${COMMIT}" \
      ONIONPIR_BENCH_BRANCH="${BRANCH}" \
      ONIONPIR_BENCH_PROCESS_ARCH="${ARCH}" \
      ONIONPIR_BENCH_OS="${OS_METADATA}" \
      ONIONPIR_BENCH_CPU="${CPU_METADATA}" \
      ONIONPIR_BENCH_COMPILER="${COMPILER_METADATA}" \
      ONIONPIR_BENCH_CMAKE="${CMAKE_METADATA}" \
      ONIONPIR_BENCH_HEXL_PATH="${HEXL_CMAKE_DIR}" \
      run_bin merkle.txt "${MERKLE_ARGS[@]}"
      command -v python3 >/dev/null && [[ -f "${OUT_DIR}/merkle.json" ]] \
        && python3 -m json.tool "${OUT_DIR}/merkle.json" >/dev/null \
        && echo "JSON validated: ${OUT_DIR}/merkle.json"
    fi

    # 压缩门无 DB 档位, 只随首个构建跑一次
    if has_mode compress; then
      run_bin compress.txt --test tree_compress
    fi
  fi

  if has_mode tree; then
    if mem_gate "tree_g32_${SCALE}" $((1 << (LEAF_POW + 10))); then
      run_bin "tree_g32_${SCALE}.txt" --test tree_bench_g32
    fi
  fi
  if has_mode tree-g1; then
    run_bin "tree_g1_${SCALE}.txt" --test tree_bench
  fi
  if has_mode cuckoo; then
    if grep -q 'cuckoo_bench' src/tests/run_test.cpp 2>/dev/null; then
      if mem_gate "cuckoo_${SCALE}" $((1 << (LEAF_POW + 10))); then
        run_bin "cuckoo_${SCALE}.txt" --test cuckoo_bench
      fi
    else
      echo "[skip] cuckoo_bench 未注册; 请 git checkout codex/cuckoo-batch-baseline 后重跑" >&2
    fi
  fi
  FIRST_SCALE=0
done

echo
echo "==> 完成. 结果目录: ${OUT_DIR}"
ls -1 "${OUT_DIR}"
