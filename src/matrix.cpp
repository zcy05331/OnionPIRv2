#include "matrix.h"
#include "utils.h"
#include <algorithm>
#include <cstring>
#include <type_traits>

typedef unsigned __int128 uint128_t;

// Forward declaration for the AVX-512 production fast path used by level_mat_mat.
#if defined(__AVX512F__)
static void level_mat_mat_avx512_safe(const uint32_t *A_data,
                                      const uint32_t *B_data,
                                      uint64_t *out_data, size_t m, size_t n,
                                      size_t levels, const uint64_t *level_qs);
#endif

// delayed reduction 的核心不改变标准矩阵乘法，只改变何时做 mod q：每个
// output cell 先在 accumulator 可承受的 chunk 内累加若干 A[i,k]*B[k,j]，
// chunk 结束后再 reduce。因为前一段会留下 acc < q，下一段最坏界为
//     acc + chunk · q² < q + chunk · q²,
// 所以 chunk ≤ (MAX_ACC - q) / q²。这里按 inter_coeff_t 的真实宽度保守
// 推导；不同 kernel 可能用 uint64、uint128 或 SIMD lane accumulator，不能
// 把它们笼统说成同一个 accumulator。
static inline size_t pick_chunk(uint64_t q, size_t cols) {
  if (q == 0) return cols;
  const inter_coeff_t MAX_ACC = ~static_cast<inter_coeff_t>(0);
  const inter_coeff_t qi = static_cast<inter_coeff_t>(q);
  const inter_coeff_t q2 = qi * qi;
  if (q2 == 0) return cols;
  const inter_coeff_t r = (MAX_ACC - qi) / q2;
  if (r == 0) return 1;
  if (r >= static_cast<inter_coeff_t>(cols)) return cols;
  return static_cast<size_t>(r);
}

void mat_mat(const db_coeff_t *__restrict A, const db_coeff_t *__restrict B,
  inter_coeff_t *__restrict out, const size_t rows, const size_t cols,
  const uint64_t q) {

  const size_t chunk = pick_chunk(q, cols);

  if (chunk >= cols) {
    // Single-pass scalar path：pick_chunk 证明整个 inner dimension 可在
    // inter_coeff_t 内完成；q==0 是 debug/no-mod 入口，否则每个 C[i,0/1]
    // 在写出前 reduce 到 < q，inter_to_cts 依赖这个 invariant。
    const inter_coeff_t qi = static_cast<inter_coeff_t>(q);
    for (size_t i = 0; i < rows; i++) {
      inter_coeff_t t0 = 0, t1 = 0;
      const size_t offset = i * cols;
      #pragma GCC unroll 32
      for (size_t k = 0; k < cols; k++) {
        t0 += (inter_coeff_t)A[offset + k] * B[2 * k];
        t1 += (inter_coeff_t)A[offset + k] * B[2 * k + 1];
      }
      out[2 * i]     = q ? (t0 % qi) : t0;
      out[2 * i + 1] = q ? (t1 % qi) : t1;
    }
    return;
  }

  // Chunked scalar path：每段只累加不会 overflow 的 products，段间 mod q。
  // For uint64 accumulators (K=2 cell), Barrett-u64 is ~1.7× faster than `% q`.
  // For uint128 accumulators (K=1 cell), the compiler's __umodti3 / built-in
  // uint128 mod already beats Barrett-u128 in this loop, so keep `%`.
  if constexpr (std::is_same_v<inter_coeff_t, uint64_t>) {
    const auto bar = utils::barrett_u64_setup(q);
    for (size_t i = 0; i < rows; i++) {
      const size_t offset = i * cols;
      inter_coeff_t acc0 = 0, acc1 = 0;
      for (size_t base = 0; base < cols; base += chunk) {
        const size_t end = std::min(base + chunk, cols);
        inter_coeff_t t0 = 0, t1 = 0;
        #pragma GCC unroll 16
        for (size_t k = base; k < end; k++) {
          t0 += (inter_coeff_t)A[offset + k] * B[2 * k];
          t1 += (inter_coeff_t)A[offset + k] * B[2 * k + 1];
        }
        acc0 = utils::barrett_reduce_u64(acc0 + t0, bar);
        acc1 = utils::barrett_reduce_u64(acc1 + t1, bar);
      }
      out[2 * i] = acc0;
      out[2 * i + 1] = acc1;
    }
  } else {
    const inter_coeff_t qi = static_cast<inter_coeff_t>(q);
    for (size_t i = 0; i < rows; i++) {
      const size_t offset = i * cols;
      inter_coeff_t acc0 = 0, acc1 = 0;
      for (size_t base = 0; base < cols; base += chunk) {
        const size_t end = std::min(base + chunk, cols);
        inter_coeff_t t0 = 0, t1 = 0;
        #pragma GCC unroll 16
        for (size_t k = base; k < end; k++) {
          t0 += (inter_coeff_t)A[offset + k] * B[2 * k];
          t1 += (inter_coeff_t)A[offset + k] * B[2 * k + 1];
        }
        acc0 = (acc0 + t0) % qi;
        acc1 = (acc1 + t1) % qi;
      }
      out[2 * i] = acc0;
      out[2 * i + 1] = acc1;
    }
  }
}

void level_mat_mat(db_matrix_t *A, db_matrix_t *B, inter_matrix_t *out,
                   const uint64_t *level_qs) {
  const size_t m = A->rows;
  const size_t n = A->cols;
  const size_t levels = A->levels;

#if defined(__AVX512F__)
  // 每个 level 是 Algorithm 4 首维的一张小矩阵：
  //   A[level] = DB[Nrest x N0],
  //   B[level] = query selection vector[N0 x 2] (BFV c0/c1),
  //   out[level] = encrypted candidates[Nrest x 2].
  // level-major 把 NTT coefficients 视作互不相干的小矩阵；outer loop 只是在
  // limb/coefficient 维度上重复同一个 standard matrix multiplication。
  //
  // AVX-512 32->64 fast path. Triggers when db_coeff_t = uint32_t and
  // inter_coeff_t = uint64_t (max_ct_mod_width() ≤ 32, the K=2 28-29-bit cell).
  // Inputs are NTT outputs already reduced mod q. Per-lane bound:
  //   ⌈n/16⌉ · 2^(2·max_ct_mod_width()) ≤ 2⁶⁴
  // i.e. n ≤ 16 · 2^(64 - 2·width). For width=29 → n ≤ 1024 (matches our
  // shapes); for width=28 → n ≤ 4096. Falls back to scalar mat_mat if n
  // exceeds the bound (defensive — shouldn't trigger for current configs).
  if constexpr (std::is_same_v<db_coeff_t, uint32_t> &&
                std::is_same_v<inter_coeff_t, uint64_t>) {
    constexpr size_t W = DBConsts::max_ct_mod_width();
    constexpr size_t avx_n_bound = (W * 2 < 64) ? (size_t(16) << (64 - 2 * W)) : 0;
    if (n <= avx_n_bound) {
      level_mat_mat_avx512_safe(reinterpret_cast<const uint32_t*>(A->data),
                                reinterpret_cast<const uint32_t*>(B->data),
                                reinterpret_cast<uint64_t*>(out->data),
                                m, n, levels, level_qs);
      return;
    }
  }
#endif

  const db_coeff_t *A_data = A->data;
  const db_coeff_t *B_data = B->data;
  inter_coeff_t *out_data = out->data;

  for (size_t level = 0; level < levels; ++level) {
    const db_coeff_t *A_ptr = A_data + level * (m * n);
    const db_coeff_t *B_ptr = B_data + level * (n * 2);
    inter_coeff_t *C_ptr = out_data + level * (m * 2);
    mat_mat(A_ptr, B_ptr, C_ptr, m, n, level_qs[level]);
  }
}

// Same shape as mat_mat but with a wide uint128 accumulator and a single
// reduction per output column (no chunked mid-loop reduction). Inputs are
// loaded as uint64; accumulator is uint128 so it can hold n·q² without
// overflow for any (q, n) we use here. Useful for isolating the cost of
// the chunked path's mid-loop `% q`.
void mat_mat_nochunk(const db_coeff_t *__restrict A,
                     const db_coeff_t *__restrict B,
                     inter_coeff_t *__restrict out, const size_t rows,
                     const size_t cols, const uint64_t q) {
  const uint128_t qi = static_cast<uint128_t>(q);
  for (size_t i = 0; i < rows; ++i) {
    const size_t offset = i * cols;
    uint128_t t0 = 0, t1 = 0;
    #pragma GCC unroll 32
    for (size_t k = 0; k < cols; ++k) {
      const uint128_t a = A[offset + k];
      t0 += a * B[2 * k];
      t1 += a * B[2 * k + 1];
    }
    out[2 * i]     = static_cast<inter_coeff_t>(q ? (t0 % qi) : t0);
    out[2 * i + 1] = static_cast<inter_coeff_t>(q ? (t1 % qi) : t1);
  }
}

void level_mat_mat_nochunk(db_matrix_t *A, db_matrix_t *B, inter_matrix_t *out,
                           const uint64_t *level_qs) {
  const size_t m = A->rows;
  const size_t n = A->cols;
  const size_t levels = A->levels;
  for (size_t level = 0; level < levels; ++level) {
    const db_coeff_t *A_ptr = A->data + level * (m * n);
    const db_coeff_t *B_ptr = B->data + level * (n * 2);
    inter_coeff_t *C_ptr = out->data + level * (m * 2);
    mat_mat_nochunk(A_ptr, B_ptr, C_ptr, m, n, level_qs[level]);
  }
}

// Diagnostic: uint64 accumulator, no chunking, single reduction at the end.
// Will WRAP on overflow when n·q² > 2^64 (e.g. K=2 with n=512, q=2^29 hits
// ~2^67) — output values are NOT correct mod q in that case. Only meaningful
// for measuring the upper bound on throughput when the accumulator stays in
// uint64. q == 0 disables the final reduction.
void mat_mat_nochunk_u64(const uint32_t *__restrict A,
                         const uint32_t *__restrict B,
                         uint64_t *__restrict out, const size_t rows,
                         const size_t cols, const uint64_t q) {
  for (size_t i = 0; i < rows; ++i) {
    const size_t offset = i * cols;
    uint64_t t0 = 0, t1 = 0;
    #pragma GCC unroll 32
    for (size_t k = 0; k < cols; ++k) {
      const uint64_t a = A[offset + k];
      t0 += a * B[2 * k];
      t1 += a * B[2 * k + 1];
    }
    out[2 * i]     = q ? (t0 % q) : t0;
    out[2 * i + 1] = q ? (t1 % q) : t1;
  }
}

void level_mat_mat_nochunk_u64(const uint32_t *A_data, const uint32_t *B_data,
                               uint64_t *out_data, size_t m, size_t n,
                               size_t levels, const uint64_t *level_qs) {
  for (size_t level = 0; level < levels; ++level) {
    const uint32_t *A_ptr = A_data + level * (m * n);
    const uint32_t *B_ptr = B_data + level * (n * 2);
    uint64_t       *C_ptr = out_data + level * (m * 2);
    mat_mat_nochunk_u64(A_ptr, B_ptr, C_ptr, m, n, level_qs[level]);
  }
}

#if defined(__AVX512F__)
#include <immintrin.h>

// AVX-512 32->64 mat-mat。它与 scalar mat_mat 计算同一个 C[level][row][0/1]，
// 但 delayed reduction 的 accumulator 形态不同：每个 SIMD lane 只累加
// ⌈n/16⌉ 个 32x32 products 到 uint64，要求 ⌈n/16⌉ · q² < 2^64；水平求和时
// 再 widen 到 uint128 并 Barrett reduce。Inputs MUST be reduced mod q on entry.
// See level_mat_mat dispatch for the bound check.
static inline uint64_t hsum_to_u128_mod(__m512i v, const utils::BarrettU128 &b) {
  alignas(64) uint64_t buf[8];
  _mm512_store_si512((__m512i*)buf, v);
  uint128_t s = 0;
  for (int i = 0; i < 8; ++i) s += buf[i];
  return utils::barrett_reduce_u128(s, b);
}

static inline void mat_mat_avx512_safe(const uint32_t *__restrict A,
                                       const uint32_t *__restrict B0,
                                       const uint32_t *__restrict B1,
                                       uint64_t *__restrict out,
                                       const size_t rows, const size_t cols,
                                       const utils::BarrettU128 &b128) {
  const size_t simd_end = cols & ~size_t(15);
  for (size_t i = 0; i < rows; ++i) {
    const uint32_t *Ar = A + i * cols;
    __m512i acc0_e = _mm512_setzero_si512();
    __m512i acc0_o = _mm512_setzero_si512();
    __m512i acc1_e = _mm512_setzero_si512();
    __m512i acc1_o = _mm512_setzero_si512();
    for (size_t k = 0; k < simd_end; k += 16) {
      __m512i a  = _mm512_loadu_si512((const __m512i*)(Ar + k));
      __m512i b0 = _mm512_loadu_si512((const __m512i*)(B0 + k));
      __m512i b1 = _mm512_loadu_si512((const __m512i*)(B1 + k));
      __m512i a_hi  = _mm512_srli_epi64(a, 32);
      __m512i b0_hi = _mm512_srli_epi64(b0, 32);
      __m512i b1_hi = _mm512_srli_epi64(b1, 32);
      acc0_e = _mm512_add_epi64(acc0_e, _mm512_mul_epu32(a, b0));
      acc0_o = _mm512_add_epi64(acc0_o, _mm512_mul_epu32(a_hi, b0_hi));
      acc1_e = _mm512_add_epi64(acc1_e, _mm512_mul_epu32(a, b1));
      acc1_o = _mm512_add_epi64(acc1_o, _mm512_mul_epu32(a_hi, b1_hi));
    }
    uint64_t t0 = hsum_to_u128_mod(_mm512_add_epi64(acc0_e, acc0_o), b128);
    uint64_t t1 = hsum_to_u128_mod(_mm512_add_epi64(acc1_e, acc1_o), b128);
    for (size_t k = simd_end; k < cols; ++k) {
      const uint128_t a = Ar[k];
      t0 = utils::barrett_reduce_u128(t0 + a * B0[k], b128);
      t1 = utils::barrett_reduce_u128(t1 + a * B1[k], b128);
    }
    out[2 * i]     = t0;
    out[2 * i + 1] = t1;
  }
}

// Per-level wrapper: deinterleaves B once (cheap vs full matmul), then runs
// the AVX-512 mat-mat per level. B 的原 layout 是 [c0,c1] interleaved；这里
// 分成 B0/B1 只是为了 SIMD load，数学上仍是 B[N0 x 2]。
static void level_mat_mat_avx512_safe(const uint32_t *A_data,
                                      const uint32_t *B_data,
                                      uint64_t *out_data, size_t m, size_t n,
                                      size_t levels, const uint64_t *level_qs) {
  std::vector<uint32_t> B0(n), B1(n);
  for (size_t level = 0; level < levels; ++level) {
    const uint32_t *B_ptr = B_data + level * (n * 2);
    for (size_t k = 0; k < n; ++k) { B0[k] = B_ptr[2*k]; B1[k] = B_ptr[2*k+1]; }
    const uint32_t *A_ptr = A_data + level * (m * n);
    uint64_t       *C_ptr = out_data + level * (m * 2);
    const auto b128 = utils::barrett_u128_setup(level_qs[level]);
    mat_mat_avx512_safe(A_ptr, B0.data(), B1.data(), C_ptr, m, n, b128);
  }
}
#endif // __AVX512F__

// Pure A-stream baseline: same access pattern as the matmul (read each
// A[level][i][k]) but no multiplies and no B/output writes. Measures the
// single-thread memory-read ceiling for this exact data layout. The XOR
// reduction prevents the compiler from optimizing the loop away.
uint32_t level_mat_mat_stream_only(const uint32_t *A_data, size_t m,
                                   size_t n, size_t levels) {
  uint32_t sink = 0;
  for (size_t level = 0; level < levels; ++level) {
    const uint32_t *A_ptr = A_data + level * (m * n);
    for (size_t i = 0; i < m; ++i) {
      const uint32_t *Ar = A_ptr + i * n;
      uint32_t s = 0;
      for (size_t k = 0; k < n; ++k) s ^= Ar[k];
      sink ^= s;
    }
  }
  return sink;
}

void level_mat_mat_32(const uint32_t *A_data, const uint32_t *B_data,
                      uint64_t *out_data, size_t m, size_t n, size_t levels,
                      uint64_t q) {
#if defined(__AVX512F__)
  // Composite first-dim 的每个 limb 复用同一 32x32->64 kernel，uniform q 是
  // q1 或 q2。Safety condition: ⌈n/16⌉ · q² < 2^64; current composite
  // params satisfy it. With q ~ 2^29 and n=512, that's
  // 32 · 2^58 = 2^63 < 2^64.
  std::vector<uint64_t> level_qs(levels, q);
  level_mat_mat_avx512_safe(A_data, B_data, out_data, m, n, levels,
                            level_qs.data());
  return;
#else
  // Scalar fallback。数学输出与 AVX-512 path 相同；这里只是不使用 SIMD lane
  // 拆分，直接在 uint64 accumulator 中累加整条 inner dimension，再做一次
  // per-output Barrett reduce。当前 composite 参数使 n · q² < 2^64。
  const auto b64 = utils::barrett_u64_setup(q);
  for (size_t level = 0; level < levels; ++level) {
    const uint32_t *A_ptr = A_data + level * (m * n);
    const uint32_t *B_ptr = B_data + level * (n * 2);
    uint64_t       *C_ptr = out_data + level * (m * 2);
    for (size_t i = 0; i < m; ++i) {
      const uint32_t *Ar = A_ptr + i * n;
      uint64_t t0 = 0, t1 = 0;
      for (size_t k = 0; k < n; ++k) {
        const uint64_t a = Ar[k];
        t0 += a * static_cast<uint64_t>(B_ptr[2 * k]);
        t1 += a * static_cast<uint64_t>(B_ptr[2 * k + 1]);
      }
      C_ptr[2 * i]     = utils::barrett_reduce_u64(t0, b64);
      C_ptr[2 * i + 1] = utils::barrett_reduce_u64(t1, b64);
    }
  }
#endif
}
