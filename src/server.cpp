#include "server.h"
#include "gsw.h"
#include "rlwe.h"
#include "utils.h"
#include "matrix.h"
#include "hexl/hexl.hpp"
#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <random>
#include <bit>
#include <cstdint>
#include <unordered_set>

#if defined(__AVX512F__)
    #include <immintrin.h>
#elif defined(__AVX2__)
    #include <immintrin.h>
#endif

#ifdef _DEBUG
#include <bitset>
#endif

// client_bv_galois_keys_, client_gsw_keys_, and db_ are not set yet.
PirServer::PirServer(const PirParams &pir_params)
    : pir_params_(pir_params),
      num_pt_(pir_params.get_num_pt()),
      key_gsw_(pir_params, pir_params.get_l_key(), pir_params.get_base_log2_key()),
      data_gsw_(pir_params, pir_params.get_l(), pir_params.get_base_log2()) {
  const size_t db_elem_cnt = num_pt_ * pir_params_.get_coeff_val_cnt();
  if (pir_params_.get_composite_rns().enabled) {
    // Composite path: two u32 arrays (mod q1 and mod q2) with the same
    // coeff-major layout. Bytes match the u64 DB on the standard path.
    db_lo_ = make_unique_aligned<uint32_t, 64>(db_elem_cnt);
    db_hi_ = make_unique_aligned<uint32_t, 64>(db_elem_cnt);
  } else {
    // after NTT, each database polynomial coefficient will be in mod q. Hence,
    // each pt coefficient is represented by K many uint64_t, same as the ciphertext.
    db_aligned_ = make_unique_aligned<db_coeff_t, 64>(db_elem_cnt);
  }
  fill_inter_res();
}

PirServer::~PirServer() {
}

// Preserve the original random database API, but make it use the same
// validated preprocessing path as deterministic benchmark inputs.
void PirServer::gen_data(const std::vector<size_t>& record_indices) {
  BENCH_PRINT("Generating random data for the server database...");
  std::mt19937_64 rng(std::random_device{}());
  const uint64_t plain_mod = pir_params_.get_plain_mod();
  const size_t coeff_count = pir_params_.get_poly_degree();
  PlaintextSource random_source =
      [&rng, plain_mod, coeff_count](size_t, RlwePt &out) {
        out.data.resize(coeff_count);
        for (uint64_t &coefficient : out.data) {
          coefficient = rng() % plain_mod;
        }
      };
  load_data(num_pt_, random_source, record_indices);
}

// Offline DB preprocessing 对应 2025 Algorithm 4 的 A 矩阵准备：每个 plaintext
// polynomial 先变成 NTT form，然后从 plaintext-major [pt][coeff] 转成
// coefficient-major [limb/NTT coefficient][pt]。这样在固定 (limb, NTT
// coefficient) 下，所有 DB entries 按 first dimension 连续存放，首维 kernel
// 做 linear scan 时 A[row][k] 是顺序访问。
// Streams plaintexts in tiles: for each tile the callback generates logical
// plaintexts and the loader zeroes rounded shape padding. It records tagged
// entries for verification, applies NTT under each q_k, and transpose-scatters
// into coefficient-major DB buffers — standard path writes db_aligned_, while
// composite path writes db_lo_/db_hi_. Then it drops the tile buffer. Tile staging
// 只保留少量 pre-NTT plaintexts，避免同时持有整份 pre-NTT DB 和重排后的 DB。
// record_indices: indices of plaintexts to save (pre-NTT) for test verification.
void PirServer::load_data(size_t logical_num_pt, const PlaintextSource &source,
                          const std::vector<size_t>& record_indices) {
  if (!source) {
    throw std::invalid_argument("PirServer::load_data requires a source");
  }
  if (logical_num_pt > num_pt_) {
    throw std::invalid_argument(
        "PirServer::load_data logical plaintext count exceeds its layout");
  }
  for (size_t index : record_indices) {
    if (index >= num_pt_) {
      throw std::invalid_argument(
          "PirServer::load_data record index exceeds its layout");
    }
  }

  recorded_pts_.clear();
  recorded_pts_.reserve(record_indices.size());
  // O(1) lookup per plaintext (the linear find scaled poorly at 8 GB DB sizes).
  std::unordered_set<size_t> record_set(record_indices.begin(),
                                        record_indices.end());

  const size_t coeff_count = DBConsts::PolyDegree;
  const uint64_t plain_mod = pir_params_.get_plain_mod();
  const auto &rns_mods = pir_params_.get_rns_mods();
  const size_t K = rns_mods.size();
  const auto &crt = pir_params_.get_composite_rns();

  TIME_ONCE_START("DB gen+NTT+realign");

  constexpr size_t TILE = 8;
  // Per-tile pre-NTT buffer: TILE plaintexts, each coeff_count uint64. Lives
  // for the tile only; total scratch ≈ TILE·N·8 bytes (e.g. 128 KB at N=2048).
  std::vector<uint64_t> tile_pt(TILE * coeff_count);
  // Per-tile NTT staging: K limbs × TILE × coeff_count. For the composite
  // path K=1 (NTT runs under the composite Q before splitting).
  std::vector<uint64_t> stage(K * TILE * coeff_count);

  for (size_t pb = 0; pb < num_pt_; pb += TILE) {
    const size_t bs = std::min(TILE, num_pt_ - pb);

    // Pass 1 (per tile): source fill or shape-padding zero, then record tagged
    // entries before any NTT transformation.
    for (size_t p = 0; p < bs; ++p) {
      uint64_t *dst = tile_pt.data() + p * coeff_count;
      const size_t poly_id = pb + p;
      if (poly_id < logical_num_pt) {
        RlwePt plaintext;
        source(poly_id, plaintext);
        if (plaintext.data.size() != coeff_count) {
          throw std::invalid_argument(
              "Plaintext source returned the wrong coefficient count");
        }
        for (size_t i = 0; i < coeff_count; ++i) {
          if (plaintext.data[i] >= plain_mod) {
            throw std::invalid_argument(
                "Plaintext source coefficient exceeds the plaintext modulus");
          }
          dst[i] = plaintext.data[i];
        }
      } else {
        std::fill(dst, dst + coeff_count, 0);
      }
      if (record_set.count(poly_id)) {
        RlwePt pt;
        pt.data.assign(dst, dst + coeff_count);
        recorded_pts_[poly_id] = std::move(pt);
      }
    }

    if (crt.enabled) {
      // Composite path: NTT under Q = q1*q2 per plaintext, then transpose-write
      // into db_lo_/db_hi_ in coeff-outer / pt-inner order. The naive per-pt
      // scatter (writing all 2048 coeffs of one pt before moving on) hits a
      // fresh cache line per write at stride num_pt_*4 B; tile-transposing here
      // matches the standard path and keeps the writes cache-friendly.
      const uint64_t Q  = rns_mods[0];
      const uint64_t q1 = crt.q1;
      const uint64_t q2 = crt.q2;
      for (size_t p = 0; p < bs; ++p) {
        utils::ntt_fwd(tile_pt.data() + p * coeff_count, coeff_count, Q);
      }
      for (size_t coeff_idx = 0; coeff_idx < coeff_count; ++coeff_idx) {
        uint32_t *out_lo = db_lo_.get() + coeff_idx * num_pt_ + pb;
        uint32_t *out_hi = db_hi_.get() + coeff_idx * num_pt_ + pb;
        for (size_t p = 0; p < bs; ++p) {
          const uint64_t c = tile_pt[p * coeff_count + coeff_idx];
          out_lo[p] = static_cast<uint32_t>(c % q1);
          out_hi[p] = static_cast<uint32_t>(c % q2);
        }
      }
      continue;
    }

    // Standard path: NTT each plaintext under each q_k into stage, then
    // tile-transpose-write into db_aligned_. Layout matches the matmul:
    // db_aligned_[level * num_pt_ + poly_id], level = k*N + coeff_idx.
    // evaluate_first_dim later views one level slice as A[Nrest x N0], where
    // consecutive poly_id values are the N0 scan dimension for a fixed candidate
    // row and fixed NTT coefficient.
    for (size_t k = 0; k < K; ++k) {
      const uint64_t qk = rns_mods[k];
      uint64_t *limb_base = stage.data() + k * TILE * coeff_count;
      for (size_t p = 0; p < bs; ++p) {
        uint64_t *dst = limb_base + p * coeff_count;
        const uint64_t *src = tile_pt.data() + p * coeff_count;
        for (size_t i = 0; i < coeff_count; ++i) dst[i] = src[i] % qk;
        utils::ntt_fwd(dst, coeff_count, qk);
      }
    }
    for (size_t k = 0; k < K; ++k) {
      uint64_t *limb_base = stage.data() + k * TILE * coeff_count;
      for (size_t coeff_idx = 0; coeff_idx < coeff_count; ++coeff_idx) {
        db_coeff_t *out = db_aligned_.get() +
                          (k * coeff_count + coeff_idx) * num_pt_ + pb;
        for (size_t p = 0; p < bs; ++p) {
          out[p] = static_cast<db_coeff_t>(limb_base[p * coeff_count + coeff_idx]);
        }
      }
    }
  }
  TIME_ONCE_END("DB gen+NTT+realign");
  PRINT_ONCE("DB gen+NTT+realign");
}

void PirServer::prep_query(std::vector<RlweCt> &fst_dim_query,
                           std::vector<db_coeff_t> &query_data) {
  const size_t fst_dim_sz = pir_params_.get_fst_dim_sz();       // 256
  const size_t coeff_val_cnt = pir_params_.get_coeff_val_cnt(); // 4096
  const size_t slice_sz = fst_dim_sz * 2;
  const auto &rns_mods = pir_params_.get_rns_mods();
  const size_t K = rns_mods.size();
  constexpr size_t N = DBConsts::PolyDegree;
 
  // prep_query 把 ciphertext-major query 转成 first-dim kernel layout。输入是
  // fst_dim_query[i].c0/c1，每个 i 是 selection vector 的一个 BFV ciphertext；
  // 先对每个 RNS limb 做 NTT，然后按 level-major 写成
  //   query_data[level][i][0/1] = B[i][c0/c1].
  // 因而每个 NTT level 的标准矩阵乘法都是
  //   A[Nrest x N0] * B[N0 x 2] -> C[Nrest x 2].
  // 若 K>1，level = limb*N + coeff；这是 per-limb/per-level 视图。
  for (size_t i = 0; i < fst_dim_query.size(); i++) {
    RlweCt &ct = fst_dim_query[i];
    for (size_t mod_id = 0; mod_id < K; mod_id++) {
      utils::ntt_fwd(ct.c0.data() + mod_id * N, N, rns_mods[mod_id]);
      utils::ntt_fwd(ct.c1.data() + mod_id * N, N, rns_mods[mod_id]);
    }
    ct.ntt_form = true;
  }
 
  // Pre-fetch the data pointers to avoid repeated indirect access
  std::vector<const uint64_t *> data0_ptrs(fst_dim_sz);
  std::vector<const uint64_t *> data1_ptrs(fst_dim_sz);

  // Prefetch all pointers
  for (size_t i = 0; i < fst_dim_sz; ++i) {
    data0_ptrs[i] = fst_dim_query[i].c0.data();
    data1_ptrs[i] = fst_dim_query[i].c1.data();
  }

  // Process in blocks to improve cache locality
  const size_t BLOCK_SIZE = 8;
  // Fallback to scalar implementation if no SIMD is available
  for (size_t slice_block = 0; slice_block < coeff_val_cnt;
       slice_block += BLOCK_SIZE) {
    const size_t slice_block_end =
        std::min(slice_block + BLOCK_SIZE, coeff_val_cnt);

    for (size_t i = 0; i < fst_dim_sz; ++i) {
      const uint64_t *p0 = data0_ptrs[i];
      const uint64_t *p1 = data1_ptrs[i];

      // Process a block of slices for the same i value (improves temporal
      // locality)
      for (size_t slice_id = slice_block; slice_id < slice_block_end;
           ++slice_id) {
        const size_t idx = slice_id * slice_sz + i * 2;
        query_data[idx] = static_cast<db_coeff_t>(p0[slice_id]);
        query_data[idx + 1] = static_cast<db_coeff_t>(p1[slice_id]);
      }
    }
  }
}

void PirServer::prep_query_composite(const std::vector<RlweCt> &fst_dim_query,
                                     uint32_t *query_lo, uint32_t *query_hi) {
  const size_t fst_dim_sz = pir_params_.get_fst_dim_sz();
  const size_t coeff_val_cnt = pir_params_.get_coeff_val_cnt();
  const size_t slice_sz = fst_dim_sz * 2;
  const auto &crt = pir_params_.get_composite_rns();
  const uint64_t q1 = crt.q1;
  const uint64_t q2 = crt.q2;

  // Composite query 已在 evaluate_first_dim 中按 logical q=q1*q2 进入 NTT。
  // 这里只做首维 kernel 需要的投影：同一 B[N0 x 2] 分别取 mod q1/q2，写入
  // 两组 uint32 level-major buffers。后续两个 32x32->64 kernels 的输出会在
  // inter_to_cts_composite 里 CRT-compose 回 logical mod q。
  std::vector<const uint64_t *> data0_ptrs(fst_dim_sz);
  std::vector<const uint64_t *> data1_ptrs(fst_dim_sz);
  for (size_t i = 0; i < fst_dim_sz; ++i) {
    data0_ptrs[i] = fst_dim_query[i].c0.data();
    data1_ptrs[i] = fst_dim_query[i].c1.data();
  }

  constexpr size_t BLOCK_SIZE = 8;
  for (size_t slice_block = 0; slice_block < coeff_val_cnt;
       slice_block += BLOCK_SIZE) {
    const size_t slice_block_end =
        std::min(slice_block + BLOCK_SIZE, coeff_val_cnt);
    for (size_t i = 0; i < fst_dim_sz; ++i) {
      const uint64_t *p0 = data0_ptrs[i];
      const uint64_t *p1 = data1_ptrs[i];
      for (size_t slice_id = slice_block; slice_id < slice_block_end;
           ++slice_id) {
        const size_t idx = slice_id * slice_sz + i * 2;
        const uint64_t v0 = p0[slice_id];
        const uint64_t v1 = p1[slice_id];
        query_lo[idx]     = static_cast<uint32_t>(v0 % q1);
        query_lo[idx + 1] = static_cast<uint32_t>(v1 % q1);
        query_hi[idx]     = static_cast<uint32_t>(v0 % q2);
        query_hi[idx + 1] = static_cast<uint32_t>(v1 % q2);
      }
    }
  }
}

// Computes Algorithm 4 first dimension as batched standard matrix
// multiplication over NTT levels. For each limb/coefficient level:
//   A = DB values with shape [other_dim_sz x fst_dim_sz],
//   B = BFV selection vector columns [fst_dim_sz x 2] (c0/c1),
//   C = encrypted candidates [other_dim_sz x 2].
// delayed modulus optimization lives inside the matmul kernels: they accumulate
// only as far as the accumulator width allows, then reduce mod q.
std::vector<RlweCt>
PirServer::evaluate_first_dim(std::vector<RlweCt> &fst_dim_query) {
  const size_t fst_dim_sz = pir_params_.get_fst_dim_sz();  // number of plaintexts in the first dimension
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();  // number of plaintexts in the other dimensions
  const size_t K = pir_params_.K();
  const size_t coeff_val_cnt = pir_params_.get_coeff_val_cnt(); // polydegree * RNS moduli count
  const size_t one_ct_sz = 2 * coeff_val_cnt; // Ciphertext has two polynomials
  const auto &rns_mods = pir_params_.get_rns_mods();
  constexpr size_t N = DBConsts::PolyDegree;

  const auto &crt = pir_params_.get_composite_rns();
  if (crt.enabled) {
    // Composite path: logical ciphertext modulus q=q1*q2 has pipeline K()==1, so
    // queries are NTTed once under q. Only the first-dim kernel splits DB/query
    // NTT values into two uint32 projections (mod q1 and mod q2), then runs
    // the same 32x32->64 kernel under q1 and q2 to compute residue outputs.
    // inter_to_cts_composite CRT-composes those residues back to logical mod q
    // before INTT. Later PIR stages still see K=1 ciphertexts.
    const uint64_t q = rns_mods[0];
    for (size_t i = 0; i < fst_dim_query.size(); ++i) {
      RlweCt &ct = fst_dim_query[i];
      utils::ntt_fwd(ct.c0.data(), N, q);
      utils::ntt_fwd(ct.c1.data(), N, q);
      ct.ntt_form = true;
    }

    std::fill(inter_res_lo_.begin(), inter_res_lo_.end(), 0);
    std::fill(inter_res_hi_.begin(), inter_res_hi_.end(), 0);

    TIME_START(FST_DIM_PREP);
    std::vector<uint32_t> query_lo(fst_dim_sz * one_ct_sz);
    std::vector<uint32_t> query_hi(fst_dim_sz * one_ct_sz);
    prep_query_composite(fst_dim_query, query_lo.data(), query_hi.data());
    TIME_END(FST_DIM_PREP);

    TIME_START(CORE_TIME);
    level_mat_mat_32(db_lo_.get(), query_lo.data(), inter_res_lo_.data(),
                     other_dim_sz, fst_dim_sz, coeff_val_cnt, crt.q1);
    level_mat_mat_32(db_hi_.get(), query_hi.data(), inter_res_hi_.data(),
                     other_dim_sz, fst_dim_sz, coeff_val_cnt, crt.q2);
    TIME_END(CORE_TIME);

    TIME_START(FST_INTER_TO_CTS_TIME);
    std::vector<RlweCt> result;
    result.reserve(other_dim_sz);
    inter_to_cts_composite(result, inter_res_lo_.data(), inter_res_hi_.data());
    TIME_END(FST_INTER_TO_CTS_TIME);
    return result;
  }

  // fill the intermediate result with zeros
  std::fill(inter_res_.begin(), inter_res_.end(), 0);

  // reallocate the query data to a continuous memory
  TIME_START(FST_DIM_PREP);
  std::vector<db_coeff_t> query_data(fst_dim_sz * one_ct_sz);
  prep_query(fst_dim_query, query_data);
  TIME_END(FST_DIM_PREP);

  /*
  Standard path for 2025 Algorithm 4: instead of treating each DB matrix entry
  as a vector and doing component-wise vector products, we peel off the vector
  dimension. For every NTT level independently:
      db_mat[level]    = A[other_dim_sz x fst_dim_sz]
      query_mat[level] = B[fst_dim_sz x 2]  (BFV c0/c1 selection vector)
      inter_res[level] = C[other_dim_sz x 2]
  This is why the first PIR dimension is exactly a standard matrix
  multiplication kernel; coefficient-major DB preprocessing makes the inner
  fst_dim_sz scan contiguous.
  */
  // prepare the matrices
  db_matrix_t db_mat { db_aligned_.get(), other_dim_sz, fst_dim_sz, coeff_val_cnt };
  db_matrix_t query_mat { query_data.data(), fst_dim_sz, 2, coeff_val_cnt };
  inter_matrix_t inter_res_mat { inter_res_.data(), other_dim_sz, 2, coeff_val_cnt };

  // Per-level modulus: level lvl spans coefficients of limb (lvl / N).
  std::vector<uint64_t> level_qs(coeff_val_cnt);
  for (size_t k = 0; k < K; ++k) {
    std::fill(level_qs.begin() + k * N, level_qs.begin() + (k + 1) * N, rns_mods[k]);
  }
  TIME_START(CORE_TIME);
  level_mat_mat(&db_mat, &query_mat, &inter_res_mat, level_qs.data());
  TIME_END(CORE_TIME);

  // ========== transform the intermediate to coefficient form. Delay the modulus operation ==========
  TIME_START(FST_INTER_TO_CTS_TIME);
  std::vector<RlweCt> result; // output vector
  result.reserve(other_dim_sz);
  inter_to_cts(result, inter_res_.data());
  TIME_END(FST_INTER_TO_CTS_TIME);

  return result;
}


void PirServer::inter_to_cts(std::vector<RlweCt> &result, const inter_coeff_t *__restrict inter_res) {
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();
  const size_t K = pir_params_.K();
  constexpr size_t coeff_count = DBConsts::PolyDegree;
  const auto &rns_mods = pir_params_.get_rns_mods();
  const size_t coeff_val_cnt = coeff_count * K;
  const size_t inter_padding = other_dim_sz * 2;  // distance between coefficients in inter_res

  // inter_res 的实际 stride 是 C[level][candidate][poly]，也就是
  // level-major 后接 candidate，再接 c0/c1 两列：
  //   inter_res[level * other_dim_sz * 2 + candidate * 2 + poly].
  // inter_to_cts 做的是 transpose/gather，把它变成
  //   RlweCt[candidate].c{0,1}[level].
  // gather 后每个 ciphertext 仍在 NTT form，随后逐 limb INTT 回 coefficient form。
  //
  // We need to unroll the loop to process multiple ciphertexts at once.
  // Otherwise, this function is basically reading the intermediate result
  // with a stride of inter_padding, which causes many cache misses.
  constexpr size_t unroll_factor = 16;

  // Process ciphertexts in blocks of unroll_factor for the main part
  const size_t main_blocks = other_dim_sz / unroll_factor;
  for (size_t block = 0; block < main_blocks; block++) {
    const size_t j = block * unroll_factor;

    // Create an array of ciphertexts.
    std::array<RlweCt, unroll_factor> cts;
    for (size_t idx = 0; idx < unroll_factor; idx++) {
      cts[idx].c0.assign(coeff_val_cnt, 0);
      cts[idx].c1.assign(coeff_val_cnt, 0);
    }

    // Compute the base indices for each ciphertext's two intermediate parts.
    // For ciphertext idx, poly0 uses base index: j*2 + 2*idx and poly1 uses j*2 + 2*idx + 1.
    std::array<size_t, unroll_factor> base0, base1;
    for (size_t idx = 0; idx < unroll_factor; idx++) {
      base0[idx] = j * 2 + 2 * idx;
      base1[idx] = j * 2 + 2 * idx + 1;
    }

    // Initialize intermediate indices and ciphertext write indices.
    std::array<size_t, unroll_factor> inter_idx0 = {0};  // for poly0 of each ciphertext
    std::array<size_t, unroll_factor> inter_idx1 = {0};  // for poly1 of each ciphertext
    std::array<size_t, unroll_factor> ct_idx0    = {0};  // write index for poly0
    std::array<size_t, unroll_factor> ct_idx1    = {0};  // write index for poly1

    // Process each modulus and coefficient. The `% q` is mathematically
    // redundant (mat_mat already reduces per output write)
    for (size_t mod_id = 0; mod_id < K; mod_id++) {
      // const uint64_t q = rns_mods[mod_id];
      for (size_t coeff_id = 0; coeff_id < coeff_count; coeff_id++) {
        #pragma unroll
        for (size_t idx = 0; idx < unroll_factor; idx++) {
          inter_coeff_t x0 = inter_res[ base0[idx] + inter_idx0[idx] * inter_padding ];
          // cts[idx].c0[ ct_idx0[idx]++ ] = static_cast<uint64_t>(x0 % q);
          cts[idx].c0[ ct_idx0[idx]++ ] = static_cast<uint64_t>(x0);

          inter_coeff_t x1 = inter_res[ base1[idx] + inter_idx1[idx] * inter_padding ];
          cts[idx].c1[ ct_idx1[idx]++ ] = static_cast<uint64_t>(x1);

          inter_idx0[idx]++;
          inter_idx1[idx]++;
        }
      }
    }

    // Mark each ciphertext as being in NTT form and then transform back.
    #pragma unroll
    for (size_t idx = 0; idx < unroll_factor; idx++) {
      for (size_t mod_id = 0; mod_id < K; mod_id++) {
        utils::ntt_inv(cts[idx].c0.data() + mod_id * coeff_count, coeff_count, rns_mods[mod_id]);
        utils::ntt_inv(cts[idx].c1.data() + mod_id * coeff_count, coeff_count, rns_mods[mod_id]);
      }
      cts[idx].ntt_form = false;
      result.emplace_back(std::move(cts[idx]));
    }
  }

  // Handle remaining ciphertexts individually for edge cases
  const size_t remaining_start = main_blocks * unroll_factor;
  for (size_t j = remaining_start; j < other_dim_sz; j++) {
    // Create a single ciphertext
    RlweCt ct;
    ct.c0.assign(coeff_val_cnt, 0);
    ct.c1.assign(coeff_val_cnt, 0);

    // Compute the base indices for this ciphertext's two intermediate parts
    const size_t base0 = j * 2;
    const size_t base1 = j * 2 + 1;

    // Initialize intermediate indices and ciphertext write indices
    size_t inter_idx0 = 0;  // for poly0
    size_t inter_idx1 = 0;  // for poly1
    size_t ct_idx0 = 0;     // write index for poly0
    size_t ct_idx1 = 0;     // write index for poly1

    // Edge-case loop (other_dim_sz % unroll_factor != 0). Same gather-and-cast
    // as the unrolled block above; mat_mat already produced values < q.
    for (size_t mod_id = 0; mod_id < K; mod_id++) {
      for (size_t coeff_id = 0; coeff_id < coeff_count; coeff_id++) {
        inter_coeff_t x0 = inter_res[base0 + inter_idx0 * inter_padding];
        ct.c0[ct_idx0++] = static_cast<uint64_t>(x0);

        inter_coeff_t x1 = inter_res[base1 + inter_idx1 * inter_padding];
        ct.c1[ct_idx1++] = static_cast<uint64_t>(x1);

        inter_idx0++;
        inter_idx1++;
      }
    }

    // Mark ciphertext as being in NTT form and then transform back
    for (size_t mod_id = 0; mod_id < K; mod_id++) {
      utils::ntt_inv(ct.c0.data() + mod_id * coeff_count, coeff_count, rns_mods[mod_id]);
      utils::ntt_inv(ct.c1.data() + mod_id * coeff_count, coeff_count, rns_mods[mod_id]);
    }
    ct.ntt_form = false;
    result.emplace_back(std::move(ct));
  }
}

void PirServer::inter_to_cts_composite(std::vector<RlweCt> &result,
                                       const uint64_t *inter_lo,
                                       const uint64_t *inter_hi) {
  const auto &crt = pir_params_.get_composite_rns();
  const uint64_t q1 = crt.q1;
  const uint64_t q2 = crt.q2;
  const uint64_t q1_inv_mod_q2 = crt.q1_inv_mod_q2;
  const uint64_t q = q1 * q2;
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();
  constexpr size_t coeff_count = DBConsts::PolyDegree;
  const size_t inter_padding = other_dim_sz * 2;

  // Composite inter_res_lo/hi 使用同样的 C[level][candidate][poly] stride；
  // logical K=1，所以 level 就是 NTT coefficient。这里先把 lo/hi 两个 limb 做
  // CRT-compose 得到 mod q 的 RlweCt[candidate].c{0,1}[coeff_id]，再 INTT
  // 回 coefficient form。split 和 compose 都只包围首维 matmul。
  //
  // Garner CRT compose: (lo, hi) → lo + q1 * ((hi − lo) · q1_inv mod q2).
  // Since q1, q2 < 2^29, diff·q1_inv stays under 2^58 — no 128-bit mul.
  auto compose = [q1, q2, q1_inv_mod_q2](uint64_t lo, uint64_t hi) -> uint64_t {
    const uint64_t lo_mod_q2 = lo % q2;
    const uint64_t diff = (hi + q2 - lo_mod_q2) % q2;
    const uint64_t k = (diff * q1_inv_mod_q2) % q2;
    return lo + q1 * k;
  };

  constexpr size_t unroll_factor = 16;
  const size_t main_blocks = other_dim_sz / unroll_factor;
  for (size_t block = 0; block < main_blocks; block++) {
    const size_t j = block * unroll_factor;
    std::array<RlweCt, unroll_factor> cts;
    for (size_t idx = 0; idx < unroll_factor; idx++) {
      cts[idx].c0.assign(coeff_count, 0);
      cts[idx].c1.assign(coeff_count, 0);
    }
    for (size_t coeff_id = 0; coeff_id < coeff_count; coeff_id++) {
      const size_t row = coeff_id * inter_padding;
      #pragma unroll
      for (size_t idx = 0; idx < unroll_factor; idx++) {
        const size_t b0 = row + j * 2 + 2 * idx;
        const size_t b1 = b0 + 1;
        cts[idx].c0[coeff_id] = compose(inter_lo[b0], inter_hi[b0]);
        cts[idx].c1[coeff_id] = compose(inter_lo[b1], inter_hi[b1]);
      }
    }
    for (size_t idx = 0; idx < unroll_factor; idx++) {
      utils::ntt_inv(cts[idx].c0.data(), coeff_count, q);
      utils::ntt_inv(cts[idx].c1.data(), coeff_count, q);
      cts[idx].ntt_form = false;
      result.emplace_back(std::move(cts[idx]));
    }
  }

  for (size_t j = main_blocks * unroll_factor; j < other_dim_sz; j++) {
    RlweCt ct;
    ct.c0.assign(coeff_count, 0);
    ct.c1.assign(coeff_count, 0);
    for (size_t coeff_id = 0; coeff_id < coeff_count; coeff_id++) {
      const size_t b0 = coeff_id * inter_padding + j * 2;
      const size_t b1 = b0 + 1;
      ct.c0[coeff_id] = compose(inter_lo[b0], inter_hi[b0]);
      ct.c1[coeff_id] = compose(inter_lo[b1], inter_hi[b1]);
    }
    utils::ntt_inv(ct.c0.data(), coeff_count, q);
    utils::ntt_inv(ct.c1.data(), coeff_count, q);
    ct.ntt_form = false;
    result.emplace_back(std::move(ct));
  }
}

RlweCt PirServer::evaluate_other_dim(std::vector<RlweCt> &mid_db, std::vector<GSWCt> &selectors) {
  // 对应 Algorithm 4 lines 7-14。mid_db 起始保存 first dimension 之后的
  // Nrest encrypted candidates，其 layout 是 leaf order。selectors[0] 在 deepest
  // remaining tree level 被消费；后续 selector 逐层向 root 归约，每层通过 MUX
  // 前/后半 candidates 把 active candidate count 减半。
  if (pir_params_.get_num_dims() == 1) {
    // 没有 high-dimensional selectors；Algorithm 4 在 lines 4-6 后结束。
    return mid_db[0];
  }
  
  size_t h = pir_params_.get_num_dims() - 1;
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();
  // `other_dim_sz` 不一定是 perfect power of two。virtual selector tree 高度是 h；
  // `perfect_size` 是 ragged leaves 上方第一个 complete level 的大小。
  const size_t perfect_size = (1 << (h - 1)); // second to last level size

  // Complete-tree layouts always satisfy other_dim_sz >= 2^(h-1); anything
  // smaller (e.g. an expansion-only with_query_shape view) would underflow
  // last_level_sz below and corrupt mid_db, so fail loudly instead.
  if (other_dim_sz < perfect_size) {
    throw std::invalid_argument(
        "evaluate_other_dim: layout has fewer candidates than its selector "
        "tree; query-shape views cannot answer make_query");
  }
  
  // 在 deepest/ragged level，`last_level_sz` 是 virtual tree 中真实拥有 sibling 的
  // leaves 数量；`offset` 之前的 leaves 在这一层没有 sibling，会原位保留。
  // 这里的 pairing 从 corrected_idx 开始，并把 parent 写回同一 logical level range。
  const size_t last_level_sz = 2 * other_dim_sz - (1 << h);
  const size_t offset = other_dim_sz - last_level_sz;
  
  for (size_t i = 0; i < last_level_sz; i += 2) { // i is the index within the last level.
    size_t corrected_idx = i + offset;  // index in the database.
    auto &x = mid_db[corrected_idx];
    auto &y = mid_db[corrected_idx + 1];
    ext_prod_mux(x, y, selectors[0], mid_db[i / 2 + offset]);
  }
  
  for (size_t a = 1; a < selectors.size(); a++) { // starting from the second to the last level
    const size_t level_sz = (1 << (h - a));
    const size_t half = level_sz >> 1;
    for (size_t i = 0; i < half; i++) {
      // 这里的 perfect levels 是 dense 的：candidate i 与 i+half 配对，对应
      // Algorithm 4 中 selector bit b 的规则：b=0 取前半，b=1 取后半。
      auto &x = mid_db[i];
      auto &y = mid_db[i + half];
      ext_prod_mux(x, y, selectors[a], mid_db[i]);
    }
  }
  return mid_db[0];
}


void PirServer::ext_prod_mux(RlweCt &x, RlweCt &y, GSWCt &selection_cipher, RlweCt &result) {
    constexpr size_t N = DBConsts::PolyDegree;
    const auto &qs = pir_params_.get_rns_mods();
    const size_t K = qs.size();

    auto sub_k = [&](RlweCt &a, const RlweCt &b) {
      for (size_t k = 0; k < K; ++k) {
        intel::hexl::EltwiseSubMod(a.c0.data() + k * N, a.c0.data() + k * N,
                                   b.c0.data() + k * N, N, qs[k]);
        intel::hexl::EltwiseSubMod(a.c1.data() + k * N, a.c1.data() + k * N,
                                   b.c1.data() + k * N, N, qs[k]);
      }
    };
    auto add_inplace_k = [&](RlweCt &a, const RlweCt &b) {
      for (size_t k = 0; k < K; ++k) {
        intel::hexl::EltwiseAddMod(a.c0.data() + k * N, a.c0.data() + k * N,
                                   b.c0.data() + k * N, N, qs[k]);
        intel::hexl::EltwiseAddMod(a.c1.data() + k * N, a.c1.data() + k * N,
                                   b.c1.data() + k * N, N, qs[k]);
      }
    };
    auto add_k = [&](const RlweCt &a, const RlweCt &b, RlweCt &c) {
      c.c0.resize(K * N);
      c.c1.resize(K * N);
      c.ntt_form = a.ntt_form;
      for (size_t k = 0; k < K; ++k) {
        intel::hexl::EltwiseAddMod(c.c0.data() + k * N, a.c0.data() + k * N,
                                   b.c0.data() + k * N, N, qs[k]);
        intel::hexl::EltwiseAddMod(c.c1.data() + k * N, a.c1.data() + k * N,
                                   b.c1.data() + k * N, N, qs[k]);
      }
    };
    auto intt_k = [&](RlweCt &ct) {
      for (size_t k = 0; k < K; ++k) {
        utils::ntt_inv(ct.c0.data() + k * N, N, qs[k]);
        utils::ntt_inv(ct.c1.data() + k * N, N, qs[k]);
      }
      ct.ntt_form = false;
    };

    // 这里使用 MUX identity：select(b, x_orig, y_orig) = x_orig + b*(y_orig-x_orig)。
    // 本函数会有意改写参数 `y`：这一步之后它不再是 y_orig，而是每个 full-q
    // RNS limb 下 coefficient-form 的差值 y_orig-x_orig。
    TIME_START(OTHER_DIM_ADD_SUB);
    sub_k(y, x);
    TIME_END(OTHER_DIM_ADD_SUB);

    // 复用 `y` 作为 external-product scratch/output。GSW bit b 是 encrypted：
    // b=0 得到 zero 的 encryption，最终加回后保留 x_orig；b=1 得到
    // y_orig-x_orig，最终加回后选择 y_orig。external_product 的 RLWE output
    // 是 NTT form。
    TIME_START(OTHER_DIM_MUX_EXTERN);
    data_gsw_.external_product(selection_cipher, y, y, LogContext::OTHER_DIM_MUX);
    TIME_END(OTHER_DIM_MUX_EXTERN);

    // external-product output 要先转回 coefficient form，才能加到仍保持
    // coefficient-form 的 x 上。
    TIME_START(OTHER_DIM_INTT);
    intt_k(y);
    TIME_END(OTHER_DIM_INTT);

    // result 可能 alias x（常见的 reduction-in-place 路径）。y 是 scratch 且已经
    // 被破坏；x 在这次 final add 前仍是 x_orig。
    TIME_START(OTHER_DIM_ADD_SUB);
    if (&result == &x) {
      add_inplace_k(x, y);
    } else {
      add_k(x, y, result);
    }
    TIME_END(OTHER_DIM_ADD_SUB);
}

// Algorithm 2 ExpandBFV，按单次 level-order heap walk 实现（root index = 1）。
// 输入是一条 coefficient-form、K-limb、full-q packed BFV query。输出前
// u = N0 + L_EP * (d - 1) 个 constant BFV ciphertexts：先是 N0 个 first-dim
// one-hot slots，再是每个高维 selector 对应的 L_EP rows。client-side BitRev
// packing 与这里的 leaf order 配套，因此 leaf i 解密到 BitRev(i) 处写入的
// constant。位于 u 右侧的 internal nodes 在 Subs 前被 pruned，因为它们只会
// 生成未使用的 zero leaves。
std::vector<RlweCt>
PirServer::fast_expand_qry(std::size_t client_id, RlweCt &ciphertext) const {
  // ============== parameters
  const size_t useful_cnt = pir_params_.get_fst_dim_sz() +
                            pir_params_.get_l() *
                                (pir_params_.get_num_dims() - 1); // u
  const size_t expan_height = pir_params_.get_expan_height(); // h
  const size_t capacity = size_t{1} << expan_height;          // 2^h
  const auto session_it = client_sessions_.find(client_id);
  const bvks::BvGaloisKeys &bv_galois_key =
      session_it != client_sessions_.end()
          ? session_it->second->bv_galois_keys
          : client_bv_galois_keys_.at(client_id);
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs = pir_params_.get_rns_mods();
  const size_t K = qs.size();

  // K-aware per-limb helpers. All ciphertexts in this routine are coefficient
  // form, K-limb, with c0/c1 each holding K*N uint64_t.
  auto rlwe_add_k = [&](const RlweCt &a, const RlweCt &b, RlweCt &c) {
    c.c0.resize(K * N);
    c.c1.resize(K * N);
    c.ntt_form = a.ntt_form;
    for (size_t k = 0; k < K; ++k) {
      intel::hexl::EltwiseAddMod(c.c0.data() + k * N, a.c0.data() + k * N,
                                 b.c0.data() + k * N, N, qs[k]);
      intel::hexl::EltwiseAddMod(c.c1.data() + k * N, a.c1.data() + k * N,
                                 b.c1.data() + k * N, N, qs[k]);
    }
  };
  auto rlwe_sub_inplace_k = [&](RlweCt &a, const RlweCt &b) {
    for (size_t k = 0; k < K; ++k) {
      intel::hexl::EltwiseSubMod(a.c0.data() + k * N, a.c0.data() + k * N,
                                 b.c0.data() + k * N, N, qs[k]);
      intel::hexl::EltwiseSubMod(a.c1.data() + k * N, a.c1.data() + k * N,
                                 b.c1.data() + k * N, N, qs[k]);
    }
  };
  auto rlwe_shift_k = [&](const RlweCt &src, RlweCt &dst, size_t index) {
    dst.c0.resize(K * N);
    dst.c1.resize(K * N);
    dst.ntt_form = src.ntt_form;
    for (size_t k = 0; k < K; ++k) {
      utils::negacyclic_shift_poly_coeffmod(src.c0.data() + k * N, N, index,
                                            qs[k], dst.c0.data() + k * N);
      utils::negacyclic_shift_poly_coeffmod(src.c1.data() + k * N, N, index,
                                            qs[k], dst.c1.data() + k * N);
    }
  };

  // ============== storage   – index 0 is *unused*, root is slot 1
  std::vector<RlweCt> cts(2 * capacity); // slots 0 … 2*capacity-1
  cts[1] = ciphertext;

  // ============== level-order walk, skip right-of-u sub-trees
  for (size_t i = 1; i < capacity; ++i) { // internal nodes only
    const int k = int{1} << (std::bit_width(i) - 1); // k = 2^{⌊log i⌋}   (span of this sub-tree)

    // 当前 heap subtree 覆盖的第一个 returned leaf；>= u 时整棵 subtree 可跳过。
    const size_t left_leaf = i * capacity / k - capacity;
    if (left_leaf >= useful_cnt)
      continue;

    RlweCt c_prime = cts[i];
    // σ_{N/k+1}: 当前 split level 对应的 Algorithm 2 automorphism。
    const uint32_t galois_k = DBConsts::PolyDegree / k + 1;
    TIME_START(APPLY_GALOIS);
    bvks::bv_apply_galois_inplace(c_prime, galois_k,
                                  bv_galois_key.get(galois_k),
                                  pir_params_);
    TIME_END(APPLY_GALOIS);
    TIME_START("add_sub");
    rlwe_add_k(cts[i], c_prime, cts[2 * i]);
    rlwe_sub_inplace_k(cts[i], c_prime);
    TIME_END("add_sub");

    TIME_START("shift polynomial");
    rlwe_shift_k(cts[i], cts[2 * i + 1], static_cast<size_t>(-k));
    TIME_END("shift polynomial");
  }

  // ============== return useful leaf slice: heap slots capacity … capacity+u−1
  return std::vector<RlweCt>(
      std::make_move_iterator(cts.begin() + capacity),
      std::make_move_iterator(cts.begin() + capacity + useful_cnt));
}

std::vector<RlweCt> PirServer::expand_query(size_t client_id,
                                            RlweCt &query) const {
  return fast_expand_qry(client_id, query);
}

void PirServer::set_client_bv_galois_key(const size_t client_id, bvks::BvGaloisKeys bv_keys) {
  client_bv_galois_keys_[client_id] = std::move(bv_keys);
}

void PirServer::set_client_gsw_key(const size_t client_id, GSWCt gsw_key) {
  client_gsw_keys_[client_id] = std::move(gsw_key);
}

void PirServer::set_client_session_keys(size_t client_id,
                                        SharedPirSessionKeys keys) {
  if (!keys) {
    throw std::invalid_argument("PirServer session key bundle cannot be null");
  }
  if (keys->bv_galois_keys.keys.size() < pir_params_.get_expan_height()) {
    throw std::invalid_argument(
        "PirServer session lacks keys for its expansion height");
  }
  client_sessions_[client_id] = std::move(keys);
}

SharedPirSessionKeys PirServer::client_session_keys(size_t client_id) const {
  return client_sessions_.at(client_id);
}


// 仅 test oracle：这里通过 direct DB lookup 返回记录的 pre-NTT plaintext，
// 因此会向 server 暴露 requested index。它只用于测试中对比 decrypt_mod_q
// output，不属于 PIR protocol。
RlwePt PirServer::direct_get_original_plaintext(const size_t plaintext_idx) const {
  auto it = recorded_pts_.find(plaintext_idx);
  if (it == recorded_pts_.end()) {
    throw std::invalid_argument("Plaintext index " + std::to_string(plaintext_idx) +
                                " was not recorded during database loading");
  }
  return it->second;
}


RlweCt PirServer::make_query(const size_t client_id, RlweCt &query) {
  // 这是 Algorithm 4 executable skeleton。Function boundary：
  //   entry 前外部负责：client key setup 与 packed query transport
  //   本函数内部负责：Algorithm 2 expansion、Algorithm 3 completion、lines 4-15 eval
  //   return 后外部负责：save_resp_to_stream 做 response serialization

  // ========================== Expansion & conversion ==========================
  // 阶段 1 / Algorithm 2 ExpandBFV：把一条 full-q packed BFV query unpack 成
  // 得到 N0 个 first-dim BFV constants，加上每个 remaining selector 的 L_EP rows。
  TIME_START(EXPAND_TIME);
  std::vector<RlweCt> query_vector = fast_expand_qry(client_id, query);
  TIME_END(EXPAND_TIME);

  // 阶段 2 / Algorithm 3 completion：把 expanded BFV selector rows 转成完整
  // RGSW ciphertexts；bottom half 由已注册到 server 的 client RGSW(s) key 补齐。
  // Reconstruct Algorithm 3 / QueryUnpack RGSW selectors from the expanded BFV
  // stream. fast_expand_qry returns:
  //   [0, N0)                         first-dimension BFV vector
  //   [N0 + (i-1)*L_EP, N0 + i*L_EP) selector top half for that later dim
  // Each later dimension contributes exactly L_EP BFV ciphertexts, already
  // aligned with the MSB-first gadget rows used by QueryPack/RGSW layout.
  TIME_START(CONVERT_TIME);
  const size_t l_ep = pir_params_.get_l();
  std::vector<GSWCt> gsw_vec(pir_params_.get_num_dims() - 1); // GSWCt containers；prose 语义是 RGSW selectors
  if (pir_params_.get_num_dims() != 1) {  // if we do need futher dimensions
    const auto session_it = client_sessions_.find(client_id);
    const GSWCt &completion_key =
        session_it != client_sessions_.end()
            ? session_it->second->gsw_key
            : client_gsw_keys_.at(client_id);
    for (size_t i = 1; i < pir_params_.get_num_dims(); i++) {
      // Copy the selector's top L_EP rows out of the expanded vector. The
      // completion key stored in client_gsw_keys_ is RGSW(s) and was generated
      // with L_KEY; query_to_gsw uses it only to derive the bottom half. The
      // resulting selector consumed by data external products has 2*L_EP rows.
      std::vector<RlweCt> lwe_vector;
      lwe_vector.reserve(l_ep);
      for (size_t k = 0; k < l_ep; ++k) {
        auto ptr = pir_params_.get_fst_dim_sz() + (i - 1) * l_ep + k;
        lwe_vector.push_back(query_vector[ptr]);
      }
      // 用 expanded BFV top rows completion 成完整 RGSW selector ciphertext。
      key_gsw_.query_to_gsw(lwe_vector, completion_key, gsw_vec[i - 1]);
    }
  }
  TIME_END(CONVERT_TIME);

  // ========================== Evaluations ==========================
  // 阶段 3 / Algorithm 4 lines 4-6：只取前 N0 个 expanded BFV ciphertexts
  // 做 database matrix-vector product。result vector 是 Nrest encrypted
  // 这些 candidates 每个对应一个 remaining-dimensional position。
  TIME_START(FST_DIM_TIME);
  query_vector.resize(pir_params_.get_fst_dim_sz());
  std::vector<RlweCt> mid_db = evaluate_first_dim(query_vector);
  TIME_END(FST_DIM_TIME);

  // 阶段 4 / Algorithm 4 lines 7-14：每个 RGSW selector bit 驱动一层 MUX，
  // 在 remaining encrypted candidates 上持续归约，直到只剩一条 ciphertext。
  TIME_START(OTHER_DIM_TIME);
  RlweCt result = evaluate_other_dim(mid_db, gsw_vec);
  TIME_END(OTHER_DIM_TIME);

  // ========================== Post-processing ==========================
  TIME_START(MOD_SWITCH);
  // 阶段 5 / Algorithm 4 line 15：所有 homomorphic operation 完成后，才把
  // full-q ciphertext 转到 single-limb small-q response modulus。提前 switching
  // 会损失 noise headroom，并破坏与 first-dim matmul、RGSW external products、
  // Galois-key material 的 parameter agreement。
  if (DBConsts::SmallQWidth < DBConsts::RnsMods[0]) {
    DEBUG_PRINT("Modulus switching for a single modulus...");
    const uint64_t small_q = pir_params_.get_small_q();
    mod_switch_inplace(result, small_q);
  }

  TIME_END(MOD_SWITCH);
  DEBUG_PRINT("Modulus switching done.");

  return result;
}


size_t PirServer::save_resp_to_stream(const RlweCt &response,
                                      std::stringstream &stream) {
  // 这里是 post-ModSwitch ciphertext 的 response codec。这里序列化 tests/prototype
  // transport 实际使用的 wire bytes：先 c0 后 c1；每个 coefficient 精确使用
  // small_q_width 个 low bits，并以 LSB-first 写入 byte stream。query/key bytes
  // 不在这里建模；make_query 直接接收 in-memory objects。
  //
  // 在 trust boundary 上，这个 research prototype format 不做 authentication
  // 或 integrity protection；对应 reader side 不检查 payload 后 trailing
  // bytes/padding。

  // --- 1.  Runtime parameters ------------------------------------------------
  const size_t small_q = pir_params_.get_small_q();
  const size_t small_q_width =
      static_cast<size_t>(std::ceil(std::log2(small_q)));
  constexpr size_t coeff_count = DBConsts::PolyDegree;

  // --- 2.  Bit-packing state -------------------------------------------------
  uint8_t byte_buf = 0;   // currently accumulated bits (LSB-first)
  size_t bits_filled = 0; // number of valid bits in byte_buf
  size_t total_bytes = 0; // bytes written so far

  auto flush_byte = [&]() {
    stream.put(static_cast<char>(byte_buf));
    ++total_bytes;
    byte_buf = 0;
    bits_filled = 0;
  };

  // --- 3.  Write every coefficient of the two polynomials -------------------
  for (size_t poly_id = 0; poly_id < 2; ++poly_id) {
    const uint64_t *data = response.data(poly_id);

    for (size_t i = 0; i < coeff_count; ++i) {
      uint64_t coeff = data[i] & ((1ULL << small_q_width) - 1); // keep LS bits only
      size_t bits_written = 0;

      while (bits_written < small_q_width) {
        const size_t room = 8 - bits_filled; // free bits in buffer
        const size_t bits_to_take = std::min(room, small_q_width - bits_written);

        const uint8_t chunk = static_cast<uint8_t>(
            (coeff >> bits_written) & ((1ULL << bits_to_take) - 1));

        byte_buf |= static_cast<uint8_t>(chunk << bits_filled);
        bits_filled += bits_to_take;
        bits_written += bits_to_take;

        if (bits_filled == 8)
          flush_byte();
      }
    }
  }

  // --- 4.  Flush padding byte (if any) --------------------------------------
  if (bits_filled != 0)
    flush_byte();

  return total_bytes;
}



void PirServer::fill_inter_res() {
  const size_t K = pir_params_.K();
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();
  const size_t elem_cnt = other_dim_sz * DBConsts::PolyDegree * K * 2;
  if (pir_params_.get_composite_rns().enabled) {
    inter_res_lo_.resize(elem_cnt);
    inter_res_hi_.resize(elem_cnt);
  } else {
    inter_res_.resize(elem_cnt);
  }
}

void PirServer::mod_switch_inplace(RlweCt &ciphertext, const uint64_t q) {
  // 所有 homomorphic work 完成后才做 full-q -> small-q centered rescale。
  // 输入是 DBConsts::RnsMods 下的 coefficient-form response data；输出是 `q`
  // 下的 single-limb coefficient-form ciphertext，供 response codec 使用。
  // 不要把它移到 evaluation 前：early switching 会消耗 noise headroom，并让
  // ciphertext 与 full-q MUX/eval path 不兼容。
  constexpr size_t coeff_count = DBConsts::PolyDegree;
  constexpr size_t K = DBConsts::RnsMods.size();
  const auto &qs = pir_params_.get_rns_mods();

  if constexpr (K == 1) {
    // 在 logical K=1 path 中，每个 coefficient 直接 centered-rescale q_full -> q。
    const uint64_t Q = qs[0];
    uint64_t *data0 = ciphertext.c0.data();
    uint64_t *data1 = ciphertext.c1.data();
    for (size_t i = 0; i < coeff_count; i++) {
      data0[i] = utils::rescale(data0[i], Q, q);
      data1[i] = utils::rescale(data1[i], Q, q);
    }
  } else {
    // 在 actual K=2 path 中，先把 high limb q1 rounded-drop 到 q0，再复用 single-limb
    // centered rescale q0 -> q。这不是 composite first-dim q1*q2 helper path；
    // 它操作的是 logical two-RNS-limb response ciphertext，最终收缩成一个
    // small-q limb。
    const uint64_t q0 = qs[0];
    const uint64_t q1 = qs[1];
    const uint64_t q0_inv_mod_q1 = pir_params_.get_rns_tables().q0_inv_mod_q1;

    auto drop_q1 = [&](uint64_t r0, uint64_t r1) -> uint64_t {
      const uint64_t r0_mod_q1 = r0 % q1;
      const uint64_t diff = (r1 + q1 - r0_mod_q1) % q1;
      const uint64_t s = static_cast<uint64_t>(
          (static_cast<uint128_t>(diff) * q0_inv_mod_q1) % q1);
      const uint128_t x = static_cast<uint128_t>(q0) * s + r0;
      uint64_t out = static_cast<uint64_t>((x + (static_cast<uint128_t>(q1) >> 1)) / q1);
      return (out >= q0) ? (out - q0) : out;
    };

    uint64_t *c0_lo = ciphertext.c0.data();
    uint64_t *c0_hi = ciphertext.c0.data() + coeff_count;
    uint64_t *c1_lo = ciphertext.c1.data();
    uint64_t *c1_hi = ciphertext.c1.data() + coeff_count;
    for (size_t i = 0; i < coeff_count; ++i) {
      c0_lo[i] = utils::rescale(drop_q1(c0_lo[i], c0_hi[i]), q0, q);
      c1_lo[i] = utils::rescale(drop_q1(c1_lo[i], c1_hi[i]), q0, q);
    }
    // Output is single-limb under modulus q.
    ciphertext.c0.resize(coeff_count);
    ciphertext.c1.resize(coeff_count);
  }
}



