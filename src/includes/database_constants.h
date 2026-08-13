#pragma once
#include <cstddef>
#include <cstdint>
#include <array>

typedef unsigned __int128 uint128_t;

// ============================================================================
// Build-time configuration selector
// ============================================================================
// Override on the cmake/compile line with e.g.
//   -DACTIVE_CONFIG=CONFIG_N2048_K1
// ----------------------------------------------------------------------------
//
// [论文参数] 2025 论文评测使用 n=2048、log q≈58、log t=13、
// log q'=22、σ=2.55。run.py 默认选择 CONFIG_N2048_K1_COMP，
// 因而该 config 是阅读 Algorithm 1-4 时的主参考路径。
//
// Naming: CONFIG_N{poly_degree}_K{rns_limb_count}[_COMP]. Each config carries
// its own gadget lengths and PlainMod. Keep configs aligned with the run.py
// aliases.
//   CONFIG_N2048_K1        K=1, N=2048, log Q ≈ 60.
//   CONFIG_N2048_K1_COMP   K=1 composite split (q1*q2 ≈ 2^58, 29+29).
//   CONFIG_N2048_K2_MP     K=2, N=2048, log Q ≈ 58.
//   CONFIG_N4096_K2_MP     K=2, N=4096, log Q ≈ 120.
//
// 三个长度不能混用：
//   L_EP  : data selector 的 external-product gadget 行数；
//   L_KEY : 用 RGSW(s) 补全 selector 时的 key decomposition 行数；
//   L_KS  : ExpandBFV 中 BV key switching 的 decomposition 行数。
#define CONFIG_N2048_K1          0
#define CONFIG_N2048_K2_MP       1
#define CONFIG_N4096_K2_MP       2
// Composite first-dim split: q = q1*q2 (29+29). Pipeline sees a logical
// single-mod K=1 modulus, but the first-dim matmul splits each NTT coefficient
// into (mod q1, mod q2) for 32x32->64 multiplies.
#define CONFIG_N2048_K1_COMP     3
#ifndef ACTIVE_CONFIG
#define ACTIVE_CONFIG CONFIG_N2048_K1
#endif

namespace DBConsts {

  // ==========================================================================
  // Constants common to all configs
  // ==========================================================================
  constexpr size_t DB_SIZE_MB = 128;
  constexpr double NoiseStdDev = 2.55;  // matches Spiral & InsPIRe.

  // First-dimension shape policy. See utils::calculate_db_shape.
  //   true : fst_dim_sz = largest power of two ≤ slack (OnionPIRv1 hypercube).
  //   false: fst_dim_sz = slack (every leftover expansion slot; non-power-of-2).
  // Tight packing raises DB capacity at the same num_dims but ups first-dim
  // matmul work; pow-2 keeps matmul cheap at the cost of more dims.
  constexpr bool FST_DIM_POW2 = true;

  // ==========================================================================
  // Per-config constants
  // ==========================================================================

#if ACTIVE_CONFIG == CONFIG_N2048_K1
  // K=1 single-mod baseline: one actual NTT prime is generated near 2^60.
  // It reuses the single-limb pipeline but is not the paper-default
  // CONFIG_N2048_K1_COMP path, and PlainMod=14 means log t differs from the
  // 2025 evaluation cell.
  constexpr size_t PolyDegree   = 2048;
  constexpr size_t L_EP         = 5;
  constexpr size_t L_KEY        = 8;
  constexpr size_t L_KS         = 8;
  constexpr size_t TREE_HEIGHT  = 10;
  constexpr size_t PlainMod     = 14;
  constexpr size_t SmallQWidth  = 22;
  constexpr std::array<size_t, 1> RnsMods = {60};
  constexpr bool CompositeFirstDim = false;
  constexpr std::array<size_t, 2> FirstDimRNSMods = {0, 0};

#elif ACTIVE_CONFIG == CONFIG_N2048_K1_COMP
  // K=1 composite paper path: RnsMods describes one logical q≈2^58, while
  // FirstDimRNSMods supplies the real 29-bit CRT limbs used only inside the
  // first-dimension matmul. This keeps Algorithm 1-4 on the single-mod layout
  // and still lets the hot kernel use 32x32->64 arithmetic.
  constexpr size_t PolyDegree   = 2048;
  constexpr size_t L_EP         = 6;
  constexpr size_t L_KEY        = 10;
  constexpr size_t L_KS         = 8;
  constexpr size_t TREE_HEIGHT  = 10;
  constexpr size_t PlainMod     = 13;
  constexpr size_t SmallQWidth  = 22;
  // Logical (single) RNS view: rns_mods_ holds {q1*q2}, ~58 bits. The 58 here
  // is the bit width passed to inter_coeff_t / db_coeff_t selectors; actual
  // modulus is computed in PirParams::init_composite_rns.
  constexpr std::array<size_t, 1> RnsMods = {58};
  constexpr bool CompositeFirstDim = true;
  constexpr std::array<size_t, 2> FirstDimRNSMods = {29, 29};

#elif ACTIVE_CONFIG == CONFIG_N2048_K2_MP
  // K=2 MP comparison cell: two real NTT primes are generated from {29, 29}
  // and composed only where the MP gadget needs logical-q arithmetic. Unlike
  // CONFIG_N2048_K1_COMP, the whole ciphertext pipeline has two RNS limbs.
  constexpr size_t PolyDegree   = 2048;
  constexpr size_t L_EP         = 5;
  constexpr size_t L_KEY        = 8;
  constexpr size_t L_KS         = 8;
  constexpr size_t TREE_HEIGHT  = 10;
  constexpr size_t PlainMod     = 10;
  constexpr size_t SmallQWidth  = 22;
  constexpr std::array<size_t, 2> RnsMods = {29, 29};
  constexpr bool CompositeFirstDim = false;
  constexpr std::array<size_t, 2> FirstDimRNSMods = {0, 0};

#elif ACTIVE_CONFIG == CONFIG_N4096_K2_MP
  // K=2 at N=4096. Total log Q ≈ 120 - fits in uint128 (MP gadget). With
  // max_ct_mod_width = 60 the matmul takes the uint64→uint128 scalar path
  // (AVX-512 fast path requires uint32→uint64).
  constexpr size_t PolyDegree   = 4096;
  constexpr size_t L_EP         = 5;
  constexpr size_t L_KEY        = 8;
  constexpr size_t L_KS         = 8;
  constexpr size_t TREE_HEIGHT  = 10;
  constexpr size_t PlainMod     = 40;
  constexpr size_t SmallQWidth  = 50;
  constexpr std::array<size_t, 2> RnsMods = {60, 60};
  constexpr bool CompositeFirstDim = false;
  constexpr std::array<size_t, 2> FirstDimRNSMods = {0, 0};

#else
  #error "Unknown ACTIVE_CONFIG"
#endif


  // Max bit-width among ciphertext moduli.
  constexpr size_t max_ct_mod_width() {
    size_t w = 0;
    for (size_t i = 0; i < RnsMods.size(); i++)
      if (RnsMods[i] > w) w = RnsMods[i];
    return w;
  }

  // The MP gadget path uses 128-bit multi-precision integers per coefficient
  // (compose_rns_to_mp / decompose_mp_to_rns in gsw.cpp). That works for K ≤ 2
  // and total log Q ≤ 128 bits.
  static_assert(RnsMods.size() <= 2,
                "Only K ≤ 2 is supported by the MP gadget.");

  // Composite split is only meaningful for the single-mod (K=1) view.
  static_assert(!CompositeFirstDim || RnsMods.size() == 1,
                "CompositeFirstDim requires a single composite ct modulus");

} // namespace DBConsts

// ============================================================================
// Per-coefficient storage and accumulator types
// ============================================================================
// db_coeff_t: type for each NTT coefficient stored in the aligned database.
//   ≤32-bit moduli → uint32_t,  >32-bit → uint64_t.
using db_coeff_t = std::conditional_t<DBConsts::max_ct_mod_width() <= 32,
                                      uint32_t, uint64_t>;

// inter_coeff_t: accumulator for first-dimension matrix multiply & gadget
// arithmetic. Must be wide enough for fst_dim_sz × (db_coeff_t × db_coeff_t)
// sums.
//   ≤32-bit moduli → uint64_t,  >32-bit → uint128_t.
using inter_coeff_t = std::conditional_t<DBConsts::max_ct_mod_width() <= 32,
                                         uint64_t, uint128_t>;
