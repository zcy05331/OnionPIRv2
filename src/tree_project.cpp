#include "tree_project.h"

#include "tree_rotate.h"
#include "utils.h"

#include "hexl/hexl.hpp"

#include <bit>
#include <stdexcept>
#include <string>

RlweCt project_keep_stride(RlweCt ct, size_t depth,
                           const bvks::BvGaloisKeys &keys,
                           const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs = scheme.get_rns_mods();
  const size_t K = qs.size();
  if (ct.ntt_form || ct.c0.size() != K * N || ct.c1.size() != K * N) {
    throw std::invalid_argument(
        "tree_project: projection needs a coefficient-form full-q ciphertext");
  }
  const size_t max_depth = std::bit_width(N) - 1;
  if (depth > max_depth) {
    throw std::invalid_argument(
        "tree_project: depth exceeds log2 of the ring degree");
  }
  if (depth == 0) return ct;

  // Step 1-2: multiply both components by u_k = 2^{-depth} mod q_k so the
  // 2^depth growth of the substitution rounds cancels exactly.
  for (size_t k = 0; k < K; ++k) {
    uint64_t inv = 0;
    if (!utils::try_invert_uint_mod(uint64_t{1} << depth, qs[k], inv)) {
      throw std::invalid_argument(
          "tree_project: 2^depth is not invertible modulo a RNS limb");
    }
    intel::hexl::EltwiseFMAMod(ct.c0.data() + k * N, ct.c0.data() + k * N,
                               inv, nullptr, N, qs[k], 1);
    intel::hexl::EltwiseFMAMod(ct.c1.data() + k * N, ct.c1.data() + k * N,
                               inv, nullptr, N, qs[k], 1);
  }

  // Step 3: T <- T + Subs(T, eta_j) for j = 0..depth-1. Each round keeps only
  // the additive branch of the expansion machinery, halving the surviving
  // exponent set to multiples of 2^{j+1}.
  for (size_t j = 0; j < depth; ++j) {
    const uint32_t eta = static_cast<uint32_t>((N >> j) + 1);
    RlweCt tau = ct;
    bvks::bv_apply_galois_inplace(tau, eta, keys.get(eta), scheme);
    tree_ct_add_inplace(ct, tau, scheme);
  }
  return ct;
}
