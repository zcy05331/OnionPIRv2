#include "tree_rotate.h"

#include "utils.h"

#include "hexl/hexl.hpp"

#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const char *message) {
  if (!condition) {
    throw std::invalid_argument(std::string("tree_rotate: ") + message);
  }
}

}  // namespace

void tree_ct_add_inplace(RlweCt &acc, const RlweCt &x,
                         const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs = scheme.get_rns_mods();
  require(!acc.ntt_form && !x.ntt_form && acc.c0.size() == x.c0.size() &&
              acc.c0.size() == qs.size() * N,
          "ciphertext addition needs matching coefficient-form inputs");
  for (size_t k = 0; k < qs.size(); ++k) {
    intel::hexl::EltwiseAddMod(acc.c0.data() + k * N, acc.c0.data() + k * N,
                               x.c0.data() + k * N, N, qs[k]);
    intel::hexl::EltwiseAddMod(acc.c1.data() + k * N, acc.c1.data() + k * N,
                               x.c1.data() + k * N, N, qs[k]);
  }
}

RlweCt mul_x_pow(const RlweCt &ct, size_t exponent_mod_2n,
                 const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs = scheme.get_rns_mods();
  const size_t K = qs.size();
  require(!ct.ntt_form && ct.c0.size() == K * N && ct.c1.size() == K * N,
          "MulXPow needs a coefficient-form full-q ciphertext");
  require(exponent_mod_2n < 2 * N, "MulXPow exponent must be below 2n");

  RlweCt result;
  result.c0.assign(K * N, 0);
  result.c1.assign(K * N, 0);
  result.ntt_form = false;
  // The shared negacyclic shift interprets its shift mod 2n and applies the
  // X^n = -1 sign flip on wrapped coefficients, exactly the sec. 12.1 map.
  for (size_t k = 0; k < K; ++k) {
    utils::negacyclic_shift_poly_coeffmod(ct.c0.data() + k * N, N,
                                          exponent_mod_2n, qs[k],
                                          result.c0.data() + k * N);
    utils::negacyclic_shift_poly_coeffmod(ct.c1.data() + k * N, N,
                                          exponent_mod_2n, qs[k],
                                          result.c1.data() + k * N);
  }
  return result;
}

RlweCt rot_select(const RlweCt &ct, GSWCt &encrypted_bit, size_t shift,
                  PirServer &mux, const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  require(shift > 0 && shift < N, "RotSelect shift must be in (0, n)");

  // X^{-shift} = X^{2n - shift}; the CMux keeps the unrotated ciphertext for
  // an encrypted zero and the rotated one for an encrypted one.
  RlweCt unrotated = ct;
  RlweCt rotated = mul_x_pow(ct, 2 * N - shift, scheme);
  RlweCt result;
  result.c0.assign(ct.c0.size(), 0);
  result.c1.assign(ct.c1.size(), 0);
  mux.ext_prod_mux(unrotated, rotated, encrypted_bit, result);
  return result;
}

RlweCt private_rotate_level(RlweCt ct, const LevelPlan &plan,
                            std::span<GSWCt> gamma_selectors, PirServer &mux,
                            const PirParams &scheme) {
  require(plan.gamma_begin + plan.gamma_count <= gamma_selectors.size() ||
              plan.gamma_count == 0,
          "rotation needs a selector for every active gamma bit");
  // Algorithm 5: bit v of the (level-truncated) gamma contributes a private
  // multiplication by X^{-2^{v - gamma_begin}}, so the composition multiplies
  // by X^{-gamma_l} and the target lands on coefficient zero.
  for (size_t idx = 0; idx < plan.gamma_count; ++idx) {
    const size_t v = plan.gamma_begin + idx;
    ct = rot_select(ct, gamma_selectors[v], size_t{1} << idx, mux, scheme);
  }
  return ct;
}
