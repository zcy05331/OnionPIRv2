#include "pir.h"
#include "database_constants.h"
#include "utils.h"
#include "hexl/hexl.hpp"

#include <cassert>
#include <bit>
#include <cmath>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

void PirParams::init_composite_rns() {
  // [Composite NTT] 流水线把 q=q1*q2 当成一个 logical K=1 modulus；
  // 只有首维 matrix multiplication 临时把 coefficient 投影到 q1/q2，
  // 以使用 29-bit 的 32x32->64 kernel。w_crt 是在 composite q 下可用的
  // 2N-th root，必须注册给 NTT wrapper；它不是普通 prime-modulus root。
  //
  // Generate two NTT-friendly primes from FirstDimRNSMods bit widths and
  // combine them: q = q1 * q2, single composite limb visible to the rest of
  // the pipeline. The first-dim matmul will split each NTT coefficient back
  // into (mod q1, mod q2) for 32x32->64 multiplies; everything else (decomp,
  // keyswitch, external product) sees a single ~58-bit modulus.
  std::vector<size_t> rns_bits(DBConsts::FirstDimRNSMods.begin(),
                               DBConsts::FirstDimRNSMods.end());
  auto rns_primes = utils::generate_ntt_friendly_primes(rns_bits,
                                                        DBConsts::PolyDegree);
  const uint64_t q1 = rns_primes[0];
  const uint64_t q2 = rns_primes[1];
  const uint64_t crt_mod = q1 * q2;
  const uint64_t w1 = intel::hexl::MinimalPrimitiveRoot(2 * DBConsts::PolyDegree, q1);
  const uint64_t w2 = intel::hexl::MinimalPrimitiveRoot(2 * DBConsts::PolyDegree, q2);
  const uint64_t w_crt = utils::crt_combine(w1, q1, w2, q2);
  utils::register_ntt_root(DBConsts::PolyDegree, crt_mod, w_crt);
  rns_mods_ = {crt_mod};
  composite_rns_.enabled = true;
  composite_rns_.q1 = q1;
  composite_rns_.q2 = q2;
  composite_rns_.w1 = w1;
  composite_rns_.w2 = w2;
  composite_rns_.w_crt = w_crt;
  uint64_t q1_inv;
  if (!utils::try_invert_uint_mod(q1 % q2, q2, q1_inv))
    throw std::runtime_error("PirParams: q1 and q2 must be coprime");
  composite_rns_.q1_inv_mod_q2 = q1_inv;
}

PirParams::PirParams()
    : rns_mod_bits_(DBConsts::RnsMods.begin(), DBConsts::RnsMods.end()) {
  if constexpr (DBConsts::CompositeFirstDim) {
    init_composite_rns();
  } else {
    rns_mods_ = utils::generate_ntt_friendly_primes(rns_mod_bits_,
                                                    DBConsts::PolyDegree);
  }

  // =============== Plaintext modulus ===============
  plain_mod_ = utils::generate_prime(DBConsts::PlainMod);

  // =============== Small modulus for mod-switch ===============
  small_q_ = utils::generate_ntt_friendly_primes(
                 {static_cast<int>(DBConsts::SmallQWidth)}, DBConsts::PolyDegree)[0];

  // ================== RNS tables (two-mod CRT constants; unused at rns_cnt=1) ==================
  const size_t rns_cnt = rns_mods_.size();
  rns_tables_.r64_mod_q.resize(rns_cnt);
  for (size_t i = 0; i < rns_cnt; i++) {
    rns_tables_.r64_mod_q[i] = static_cast<uint64_t>(
        (static_cast<uint128_t>(1) << 64) % rns_mods_[i]);
  }
  if (rns_cnt == 2) {
    if (!utils::try_invert_uint_mod(rns_mods_[0] % rns_mods_[1],
                                    rns_mods_[1],
                                    rns_tables_.q0_inv_mod_q1)) {
      throw std::runtime_error("PirParams: coeff moduli not coprime");
    }
  }

  // ================== GSW related parameters ==================
  size_t ct_mod_width = get_ct_mod_width();
  base_log2_ = (ct_mod_width + l_ep_ - 1) / l_ep_;
  base_log2_key_ = (ct_mod_width + l_key_ - 1) / l_key_;

  // =============== Database shape calculation ===============
  // N0 is fst_dim_sz_: the number of plaintext slots selected by the first
  // matrix-multiplication dimension. Nrest is get_other_dim_sz(): the remaining
  // logical rows packed behind N0, rounded up so num_pt_ covers the target DB.
  // num_dims_ counts the first dimension plus recursive expansion dimensions.
  // Expansion capacity is constrained by TREE_HEIGHT and L_EP because each
  // expansion level contributes selector capacity through the data gadget rows.
  const size_t target_num_pt =
      DBConsts::DB_SIZE_MB * 1024 * 1024 / get_pt_size();
  apply_layout(
      {target_num_pt, DBConsts::TREE_HEIGHT, DBConsts::FST_DIM_POW2});
  DEBUG_PRINT("target_num_pt: " << target_num_pt_);
  DEBUG_PRINT("fst_dim_sz: " << fst_dim_sz_ << ", num_dims: " << num_dims_);
}

void PirParams::apply_layout(const PirLayoutConfig &layout) {
  if (layout.target_num_pt == 0) {
    throw std::invalid_argument("PirParams: target_num_pt must be positive");
  }

  constexpr size_t max_expansion_height =
      std::bit_width(DBConsts::PolyDegree) - 1;
  if (layout.expansion_height > max_expansion_height ||
      layout.expansion_height >= std::numeric_limits<size_t>::digits) {
    throw std::invalid_argument(
        "PirParams: expansion_height exceeds the ring automorphism capacity");
  }

  const auto [fst_dim_sz, num_dims] = utils::calculate_db_shape(
      layout.target_num_pt, l_ep_, layout.expansion_height,
      layout.fst_dim_pow2);
  const size_t other_dim_sz =
      utils::roundup_div(layout.target_num_pt, fst_dim_sz);
  if (other_dim_sz > std::numeric_limits<size_t>::max() / fst_dim_sz) {
    throw std::overflow_error("PirParams: rounded database shape overflows");
  }

  target_num_pt_ = layout.target_num_pt;
  expansion_height_ = layout.expansion_height;
  fst_dim_pow2_ = layout.fst_dim_pow2;
  fst_dim_sz_ = fst_dim_sz;
  num_dims_ = num_dims;
  num_pt_ = fst_dim_sz * other_dim_sz;
}

PirParams PirParams::with_layout(const PirLayoutConfig &layout) const {
  PirParams result(*this);
  result.apply_layout(layout);
  return result;
}

// [Tree PIR 参数视图] 由显式查询形状派生"仅展开"的参数视图（手册 §1.4）。
// 动机：树查询的形状（fst = N₀、b + r 个 selector 组、高度 h_q）不可能由数据库规划器
// calculate_db_shape 从明文条数反推出来，所以这里绕开 apply_layout，把三个形状字段
// 按 shape 原样写入副本。视图保持全部 scheme 字段（模数、gadget、密钥参数）不变，
// 只用于 QueryPack 打包、fast_expand_qry 与会话密钥校验；它不承载数据库，不可用来
// 装载数据库或回答 make_query（evaluate_other_dim 对这类布局硬抛异常兜底）。
PirParams PirParams::with_query_shape(const PirQueryShapeConfig &shape) const {
  // 守卫：Subs 展开的容量上界是环自同构能支撑的 2^{log₂ N}；高度超界直接拒绝，
  // 防止后续按 2^h 分配/寻址时越出环的能力范围。
  constexpr size_t max_expansion_height =
      std::bit_width(DBConsts::PolyDegree) - 1;
  if (shape.expansion_height > max_expansion_height) {
    throw std::invalid_argument(
        "PirParams: query shape exceeds the ring automorphism capacity");
  }
  // 守卫：首维至少要有一个槽位（fst_dim_sz = 0 会让后续除法/取模失去意义）。
  if (shape.fst_dim_sz == 0) {
    throw std::invalid_argument(
        "PirParams: query shape needs a positive first dimension");
  }
  // 容量检查：需保证 fst_dim_sz + l_ep_·num_selector_bits ≤ capacity = 2^h。
  // 故意写成除法形式（num_selector_bits > (capacity − fst)/l_ep_），因为直接算乘积
  // l_ep_·num_selector_bits 可能在比较之前就发生 size_t 回绕、静默通过检查；
  // 除法形式对任意输入都不会溢出。
  const size_t capacity = size_t{1} << shape.expansion_height;
  if (shape.fst_dim_sz > capacity ||
      shape.num_selector_bits >
          (capacity - shape.fst_dim_sz) / l_ep_) {
    throw std::invalid_argument(
        "PirParams: query shape does not fit the expansion capacity");
  }

  // 拷贝整个 scheme 后覆写三个形状字段。num_dims = 1 + selector 数，沿用 flat 路径
  // "首维一维 + 每个高维 selector 各一维"的计数约定，使 complete_selectors 等
  // 下游代码无需区分视图来源。
  PirParams result(*this);
  result.fst_dim_sz_ = shape.fst_dim_sz;
  result.num_dims_ = 1 + shape.num_selector_bits;
  result.expansion_height_ = shape.expansion_height;
  // 视图背后没有数据库：num_pt 折叠为 fst_dim_sz。这样 (a) 误用该视图去构造
  // PirServer 时分配量保持最小；(b) get_other_dim_sz() = 1 成为"没有高维数据库"
  // 的显式信号，供守卫代码识别。
  result.num_pt_ = shape.fst_dim_sz;
  result.target_num_pt_ = shape.fst_dim_sz;
  return result;
}

bool PirParams::scheme_compatible(const PirParams &other) const {
  const bool same_composite =
      composite_rns_.enabled == other.composite_rns_.enabled &&
      composite_rns_.q1 == other.composite_rns_.q1 &&
      composite_rns_.q2 == other.composite_rns_.q2 &&
      composite_rns_.w1 == other.composite_rns_.w1 &&
      composite_rns_.w2 == other.composite_rns_.w2 &&
      composite_rns_.w_crt == other.composite_rns_.w_crt &&
      composite_rns_.q1_inv_mod_q2 == other.composite_rns_.q1_inv_mod_q2;
  return small_q_ == other.small_q_ && base_log2_ == other.base_log2_ &&
         base_log2_key_ == other.base_log2_key_ &&
         plain_mod_ == other.plain_mod_ &&
         rns_mod_bits_ == other.rns_mod_bits_ &&
         rns_mods_ == other.rns_mods_ &&
         rns_tables_.q0_inv_mod_q1 == other.rns_tables_.q0_inv_mod_q1 &&
         rns_tables_.r64_mod_q == other.rns_tables_.r64_mod_q &&
         same_composite;
}

const size_t PirParams::get_ct_mod_width() const {
  size_t ct_mod_width = 0;
  for (size_t i = 0; i < K(); ++i) {
    ct_mod_width += rns_mod_bits_[i];
  }
  return ct_mod_width;
}

void PirParams::print_params() const {
  PRINT_BAR;
  std::cout << "                       PIR PARAMETERS                         " << std::endl;
  PRINT_BAR;

  auto print_field = [](const std::string& label, const std::string& value, int label_width = 35) {
    std::string padded_label = label;
    padded_label.resize(label_width, ' ');
    std::cout << "  " << padded_label << "= " << value << std::endl;
  };

  auto print_field_num = [&print_field](const std::string& label, auto value) {
    print_field(label, std::to_string(value));
  };

  // ---- Database shape ----
  print_field_num("Database size (MB)", get_DBSize_MB());
  print_field_num("Physical storage (MB)", get_physical_storage_MB());
  print_field_num("Plaintext size (KB)", get_pt_size() / 1024);
  print_field_num("num_pt", num_pt_);
  print_field_num("fst_dim_sz", fst_dim_sz_);
  print_field_num("num_dims", num_dims_);
  print_field_num("expansion tree height", get_expan_height());

  // ---- Gadget / decomposition ----
  print_field_num("l_ep (data RGSW)",  l_ep_);
  print_field_num("l_key (key RGSW)",  l_key_);
  print_field_num("l_ks (BV keyswitch)", DBConsts::L_KS);
  // print_field_num("base_log2 (data)", base_log2_);
  // print_field_num("base_log2 (key)",  base_log2_key_);

  // ---- Ring / moduli ----
  print_field_num("poly_modulus_degree", DBConsts::PolyDegree);

  std::string bits_str = "[";
  std::string mods_str = "[";
  for (size_t i = 0; i < rns_mods_.size(); ++i) {
    bits_str += std::to_string(rns_mod_bits_[i]);
    mods_str += std::to_string(rns_mods_[i]);
    if (i + 1 < rns_mods_.size()) { bits_str += " + "; mods_str += " + "; }
  }
  bits_str += "] = " + std::to_string(get_ct_mod_width()) + " bits";
  mods_str += "]";
  print_field("rns_mods (bits)", bits_str, 40);
  print_field("rns_mods", mods_str, 40);

  print_field("plain_modulus",
              std::to_string(plain_mod_) + " (log_2 ≈ " +
                  std::to_string(static_cast<int>(std::ceil(std::log2(plain_mod_)))) +
                  ")", 40);

  if (K() == 1) {
    print_field("small_q (mod-switch)",
                std::to_string(small_q_) + " (log_2 ≈ " +
                    std::to_string(static_cast<int>(std::ceil(std::log2(small_q_)))) +
                    ")", 40);
  }

  // ---- Composite-mod first-dim (only when enabled) ----
  if (composite_rns_.enabled) {
    print_field("composite split q1*q2",
                std::to_string(composite_rns_.q1) + " * " +
                    std::to_string(composite_rns_.q2),
                40);
  }

  std::cout << "==============================================================" << std::endl;
}
