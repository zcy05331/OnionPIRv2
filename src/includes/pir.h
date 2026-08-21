#pragma once

#include "logging.h"
#include "database_constants.h"
#include <cstdint>
#include <vector>

// [运行期参数] DBConsts 只给 bit width 与策略；PirParams 负责生成实际
// NTT-friendly moduli、CRT tables、small_q、gadget base 和数据库 shape。
// logical DB size、physical NTT storage 和 modeled communication bytes 是
// 三种不同口径，不能用同一个 size getter 替代。
//
// Precomputed constants used by the K=2 CRT compose/decompose helpers.
struct RnsTables {
  uint64_t q0_inv_mod_q1 = 0;
  std::vector<uint64_t> r64_mod_q;
};

// Constants for the composite-mod first-dim split. Only populated when the
// active config splits the (single, logical) ciphertext modulus q into two
// CRT limbs (q = q1*q2) for the first-dimension matmul. enabled = false
// otherwise; rest of the pipeline still sees a single-mod K=1 view.
struct CompositeRnsTables {
  bool enabled = false;
  uint64_t q1 = 0;              // first RNS limb (~29 bits)
  uint64_t q2 = 0;              // second RNS limb (~29 bits)
  uint64_t w1 = 0;              // primitive 2N-th root mod q1
  uint64_t w2 = 0;              // primitive 2N-th root mod q2
  uint64_t w_crt = 0;           // CRT-combined primitive 2N-th root mod q1*q2
  uint64_t q1_inv_mod_q2 = 0;   // for CRT-compose hot path
};

// Database-layout inputs that may vary between PIR calls while the underlying
// BFV/RGSW scheme parameters and helper keys remain unchanged.
struct PirLayoutConfig {
  size_t target_num_pt;
  size_t expansion_height;
  bool fst_dim_pow2;
};

// Direct packed-query shape: exactly fst_dim_sz first-dimension slots plus
// num_selector_bits gadget-row groups under a 2^expansion_height capacity.
// Unlike PirLayoutConfig this is not derived from a plaintext target, so
// shapes the database planner would never pick (e.g. the tree query's
// N0 + (b + r) * L_EP layout) can be expressed exactly.
struct PirQueryShapeConfig {
  size_t fst_dim_sz;
  size_t num_selector_bits;
  size_t expansion_height;
};

// ================== CLASS DEFINITIONS ==================
class PirParams {
public:
  PirParams();
  PirParams(const PirParams &pir_params) = default;

  PirParams with_layout(const PirLayoutConfig &layout) const;
  // Expansion-only view for packed-query processing: sets fst_dim_sz_,
  // num_dims_ = 1 + num_selector_bits and expansion_height_ verbatim while
  // keeping every scheme field. num_pt_ collapses to fst_dim_sz because this
  // view carries no database: it is valid for query packing, fast_expand_qry
  // and session-key checks, but must not be used to load a database or answer
  // make_query.
  PirParams with_query_shape(const PirQueryShapeConfig &shape) const;
  bool scheme_compatible(const PirParams &other) const;

  // ================== getters ==================
  // Getter group exposes derived runtime parameters. Treat get_DBSize_MB() as
  // logical plaintext payload, get_physical_storage_MB() as aligned NTT
  // coefficient storage, and get_BFV_size()/key helpers as communication-size
  // models; they intentionally answer different questions.
  const size_t get_ct_mod_width() const;

  inline const size_t get_uint_size() const { return sizeof(db_coeff_t); }
  inline const size_t get_num_bits_per_coeff() const { return DBConsts::PlainMod - 1; }
  inline size_t get_pt_size() const {
    return get_num_bits_per_coeff() * DBConsts::PolyDegree / 8;
  }
  inline double get_DBSize_MB() const {
    return static_cast<double>(num_pt_) * get_pt_size() / 1024 / 1024;
  }
  inline double get_physical_storage_MB() const {
    return static_cast<double>(get_coeff_val_cnt()) * num_pt_ * sizeof(db_coeff_t) / 1024 / 1024;
  }
  inline size_t get_num_pt() const { return num_pt_; }
  inline size_t get_target_num_pt() const { return target_num_pt_; }
  inline size_t get_num_dims() const { return num_dims_; }
  inline size_t get_l() const { return l_ep_; }
  inline size_t get_l_key() const { return l_key_; }
  inline size_t get_small_q() const { return small_q_; }
  inline size_t get_base_log2() const { return base_log2_; }
  inline size_t get_base_log2_key() const { return base_log2_key_; }
  inline size_t get_fst_dim_sz() const { return fst_dim_sz_; }
  inline size_t get_other_dim_sz() const { return num_pt_ / fst_dim_sz_; }
  // Number of RNS limbs (matches DBConsts::RnsMods.size()).
  inline size_t K() const { return rns_mods_.size(); }
  inline size_t get_coeff_val_cnt() const {
    return DBConsts::PolyDegree * K();
  }
  inline uint64_t get_plain_mod() const { return plain_mod_; }
  inline const std::vector<uint64_t> &get_rns_mods() const { return rns_mods_; }
  inline const std::vector<size_t> &get_rns_mod_bits() const { return rns_mod_bits_; }
  inline const RnsTables &get_rns_tables() const { return rns_tables_; }
  inline const CompositeRnsTables &get_composite_rns() const { return composite_rns_; }
  inline size_t get_poly_degree() const { return DBConsts::PolyDegree; }
  inline size_t get_expan_height() const { return expansion_height_; }
  inline bool get_fst_dim_pow2() const { return fst_dim_pow2_; }
  inline size_t get_num_other_dims() const { return num_dims_ - 1; }

  // Standard deviation σ of the Gaussian error distribution used during
  // encryption and key generation. Defined in DBConsts::NoiseStdDev.
  inline double get_noise_std_dev() const { return DBConsts::NoiseStdDev; }

  // Seed-compressed BFV communication model only. This is not an actual
  // query/key serializer and does not promise byte-for-byte wire layout.
  inline const size_t get_BFV_size(bool use_seed = true) const {
    const size_t per_poly_bits = DBConsts::PolyDegree * get_ct_mod_width();
    if (use_seed) {
      return 32 + (get_ct_mod_width() * DBConsts::PolyDegree) / 8; // assuming 32 bytes for the seed
    } else {
      return (get_ct_mod_width() * DBConsts::PolyDegree * 2) / 8; // two polynomials per ciphertext
    }
  }

  // Seed-compressed key-size models used for reporting communication bytes;
  // concrete key objects are built elsewhere and are not serialized here.
  inline const size_t get_gsw_key_size(bool use_seed = true) const {
    return 2 * l_key_ * get_BFV_size(use_seed);
  }

  inline const size_t get_bv_galois_key_size(bool use_seed = true) const {
    const size_t per_poly_bytes = (DBConsts::PolyDegree * get_ct_mod_width() + 7) / 8;
    const size_t num_keys = get_expan_height();
    const size_t rows_per_key = DBConsts::L_KS;
    return use_seed
      ? num_keys * rows_per_key * (per_poly_bytes + 32)
      : num_keys * rows_per_key * 2 * per_poly_bytes;
  }

  void print_params() const;

private:
  static constexpr size_t l_ep_ = DBConsts::L_EP;
  static constexpr size_t l_key_ = DBConsts::L_KEY;
  uint64_t small_q_ = 0;
  size_t base_log2_;
  size_t base_log2_key_;
  size_t target_num_pt_ = 0;
  size_t expansion_height_ = DBConsts::TREE_HEIGHT;
  bool fst_dim_pow2_ = DBConsts::FST_DIM_POW2;
  size_t num_pt_;
  size_t fst_dim_sz_;
  size_t num_dims_;
  uint64_t plain_mod_ = 0;
  std::vector<size_t> rns_mod_bits_;
  std::vector<uint64_t> rns_mods_;
  RnsTables rns_tables_;
  CompositeRnsTables composite_rns_;

  // [Composite NTT] 流水线把 q=q1*q2 当成一个 logical K=1 modulus；
  // 只有首维 matrix multiplication 临时把 coefficient 投影到 q1/q2，
  // 以使用 29-bit 的 32x32->64 kernel。w_crt 是在 composite q 下可用的
  // 2N-th root，必须注册给 NTT wrapper；它不是普通 prime-modulus root。
  void init_composite_rns();
  void apply_layout(const PirLayoutConfig &layout);
};
