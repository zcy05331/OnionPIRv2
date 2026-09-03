#include "tests.h"

#include <bit>
#include "tree_index.h"
#include "tree_query.h"

#include <vector>

namespace {

template <typename Fn>
bool throws_invalid_argument(Fn &&fn) {
  try {
    fn();
  } catch (const std::invalid_argument &) {
    return true;
  }
  return false;
}

// Exhaust every (leaf, level) pair of one configuration against the direct
// tree walk. This is the blueprint sec. 21.2 layout gate: the cross-level
// identity j_l = gamma_l * R_l + p_l, the (alpha, beta) reconstruction of
// p_l, and the gamma-prefix rule above level r.
void exhaust_config(const TreePirParams &params) {
  const auto plans = build_level_plans(params);
  require_test(plans.size() == params.L + 1, "one plan per level");

  for (size_t leaf = 0; leaf < params.N; ++leaf) {
    const ClientCoordinates coords = client_index(leaf, params);
    const size_t gamma = leaf / params.P;
    const size_t beta = (leaf % params.P) % params.B;

    // Bits are little-endian encodings of the arithmetic coordinates, and the
    // coordinates reassemble the leaf exactly.
    size_t beta_bits = 0, gamma_bits = 0;
    for (size_t u = 0; u < params.b; ++u) {
      beta_bits |= static_cast<size_t>(coords.beta_bits_le[u]) << u;
    }
    for (size_t v = 0; v < params.r; ++v) {
      gamma_bits |= static_cast<size_t>(coords.gamma_bits_le[v]) << v;
    }
    require_test(beta_bits == beta, "beta bit encoding");
    require_test(gamma_bits == gamma, "gamma bit encoding");
    require_test(gamma * params.P + coords.alpha * params.B + beta == leaf,
                 "coordinate reconstruction of the leaf");

    for (size_t level = 0; level <= params.L; ++level) {
      const LevelOracle oracle =
          build_level_oracle_for_test(leaf, level, params);
      const LevelPlan &plan = plans[level];

      require_test(oracle.node_index == leaf >> (params.L - level),
                   "oracle ancestor index");
      require_test(oracle.node_index ==
                       oracle.record_position * plan.R +
                           oracle.packed_plaintext_index,
                   "invariant 1: j_l = gamma_l * R_l + p_l");
      require_test(oracle.packed_plaintext_index < plan.R,
                   "record index below R_l");

      if (level >= params.r) {
        require_test(oracle.record_position == gamma, "full gamma at depth");
        require_test(level_record_position_from_coordinates(
                         coords.alpha, beta, level, params) ==
                         oracle.packed_plaintext_index,
                     "invariant 2: p_l from (alpha, beta)");
      } else {
        require_test(oracle.packed_plaintext_index == 0,
                     "single plaintext above level r");
        require_test(oracle.record_position ==
                         gamma >> (params.r - level),
                     "gamma prefix above level r");
      }
    }
  }
}

// Plan-level checks that do not depend on a leaf: case boundaries, bit
// ranges, and projection depth per blueprint sec. 5.2-5.4.
void check_plans(const TreePirParams &params) {
  const auto plans = build_level_plans(params);
  for (size_t level = 0; level <= params.L; ++level) {
    const LevelPlan &plan = plans[level];
    require_test(plan.level == level, "plan level");
    const size_t expected_R =
        level >= params.r ? size_t{1} << (level - params.r) : size_t{1};
    require_test(plan.R == expected_R, "plan R");

    if (plan.R == 1) {
      require_test(plan.select_case == SelectCase::Single, "Single case");
      require_test(plan.coarsen_count == params.a, "Single pyramid depth");
      require_test(plan.beta_count == 0 && plan.beta_begin == params.b,
                   "Single has no beta bits");
    } else if (plan.R < params.N0) {
      require_test(plan.select_case == SelectCase::CoarsenedAlpha,
                   "CoarsenedAlpha case");
      require_test(plan.coarsen_count == params.a - (level - params.r),
                   "coarsen count");
      require_test(plan.beta_count == 0 && plan.beta_begin == params.b,
                   "CoarsenedAlpha has no beta bits");
    } else {
      require_test(plan.select_case == SelectCase::AlphaBeta,
                   "AlphaBeta case");
      require_test(plan.beta_begin == params.L - level, "beta begin");
      require_test(plan.beta_count == level - params.r - params.a,
                   "beta count d_l");
      require_test(plan.beta_begin + plan.beta_count == params.b,
                   "active beta bits reach bit b-1");
      if (level == params.r + params.a) {
        require_test(plan.beta_count == 0, "d_l = 0 boundary level");
      }
    }

    if (level >= params.r) {
      require_test(plan.gamma_begin == 0 && plan.gamma_count == params.r,
                   "full gamma schedule");
    } else {
      require_test(plan.gamma_begin == params.r - level &&
                       plan.gamma_count == level,
                   "gamma prefix schedule");
    }
    require_test(plan.projection_depth ==
                     (level < params.r ? level : params.r),
                 "projection depth min(r, level)");
  }
}

}  // namespace

void PirTest::test_tree_index() {
  print_func_name(__FUNCTION__);

  // Blueprint sec. 25 sanity configurations, exhausted leaf by leaf. Small
  // odd t and odd moduli stand in for the scheme's NTT primes; index math
  // never touches them beyond the invertibility gates.
  const std::vector<uint64_t> mods{577};
  exhaust_config(make_tree_pir_params(6, 1, 8, 1, 1, 17, mods));   // (64, 8, 2)
  exhaust_config(make_tree_pir_params(7, 1, 8, 1, 1, 17, mods));   // (128, 8, 2)
  exhaust_config(make_tree_pir_params(8, 2, 16, 1, 1, 17, mods));  // (256, 16, 4)
  check_plans(make_tree_pir_params(6, 1, 8, 1, 1, 17, mods));
  check_plans(make_tree_pir_params(7, 1, 8, 1, 1, 17, mods));
  check_plans(make_tree_pir_params(8, 2, 16, 1, 1, 17, mods));
  // b = 0 boundary: L = r + a exactly, every AlphaBeta level has d_l = 0.
  exhaust_config(make_tree_pir_params(5, 2, 8, 1, 1, 17, mods));
  check_plans(make_tree_pir_params(5, 2, 8, 1, 1, 17, mods));

  // Hard validation gates (sec. 21.1): no silent padding or fallback.
  require_test(throws_invalid_argument([&] {
                 (void)make_tree_pir_params(4, 2, 8, 1, 1, 17, mods);
               }),
               "accepted L below r + a");
  require_test(throws_invalid_argument([&] {
                 (void)make_tree_pir_params(6, 0, 8, 1, 1, 17, mods);
               }),
               "accepted N0 = 1");
  require_test(throws_invalid_argument([&] {
                 (void)make_tree_pir_params(6, 1, 6, 1, 1, 17, mods);
               }),
               "accepted a non-power-of-two ring degree");
  require_test(throws_invalid_argument([&] {
                 (void)make_tree_pir_params(0, 1, 8, 1, 1, 17, mods);
               }),
               "accepted a zero tree height");
  require_test(throws_invalid_argument([&] {
                 (void)make_tree_pir_params(6, 64, 8, 1, 1, 17, mods);
               }),
               "accepted an out-of-range first-dimension width");
  require_test(throws_invalid_argument([&] {
                 // w = 2 + 4*(b + r) > 8 forces W = 16 > n = 8.
                 (void)make_tree_pir_params(6, 1, 8, 4, 4, 17, mods);
               }),
               "accepted W above the ring degree");
  require_test(throws_invalid_argument([&] {
                 // ell*(b + r) = 16 * 2^60 wraps to 0 mod 2^64; unchecked
                 // arithmetic would fold w back to N0 and pass every gate.
                 (void)make_tree_pir_params(19, 3, 2048, size_t{1} << 60,
                                            size_t{1} << 60, 17, mods);
               }),
               "accepted a wrapping packed width");
  require_test(throws_invalid_argument([&] {
                 (void)make_tree_pir_params(6, 1, 8, 1, 1, 16, mods);
               }),
               "accepted even plaintext modulus");
  require_test(throws_invalid_argument([&] {
                 (void)make_tree_pir_params(6, 1, 8, 1, 1, 17, {578});
               }),
               "accepted even RNS modulus");
  require_test(throws_invalid_argument([&] {
                 TreePirParams broken =
                     make_tree_pir_params(6, 1, 8, 1, 1, 17, mods);
                 broken.w += 1;
                 validate_tree_params(broken);
               }),
               "accepted inconsistent w");
  require_test(throws_invalid_argument([&] {
                 TreePirParams broken =
                     make_tree_pir_params(6, 1, 8, 1, 1, 17, mods);
                 broken.response_moduli = {579};
                 validate_tree_params(broken);
               }),
               "accepted response moduli drift");
  require_test(throws_invalid_argument([&] {
                 (void)client_index(64, make_tree_pir_params(6, 1, 8, 1, 1,
                                                             17, mods));
               }),
               "accepted out-of-range leaf");

  // Scheme binding: n, t, moduli and both gadget lengths come from the live
  // PirParams. The frozen blueprint sec. 18 anchor applies to the L_EP = 6
  // paper configuration.
  // Every expectation is derived from the live scheme (n, L_EP), so the
  // check holds for any ring size; at n = 2048, L_EP = 6 it reproduces the
  // frozen blueprint anchor r = 11, b = 2, B = 4, w = 86, W = 128, h_q = 7.
  PirParams scheme;
  const TreePirParams bound = make_tree_pir_params_for_scheme(16, 3, scheme);
  const size_t log_n = std::bit_width(scheme.get_poly_degree()) - 1;
  require_test(bound.n == scheme.get_poly_degree() && bound.r == log_n,
               "scheme ring binding");
  require_test(bound.ell_beta == scheme.get_l() &&
                   bound.ell_gamma == scheme.get_l(),
               "scheme gadget binding");
  const size_t expected_b = 16 - log_n - 3;
  require_test(bound.N0 == 8 && bound.b == expected_b &&
                   bound.B == (size_t{1} << expected_b),
               "blueprint shape-test split");
  const size_t expected_w =
      8 + scheme.get_l() * (expected_b + log_n);
  require_test(bound.w == expected_w && bound.W == std::bit_ceil(expected_w) &&
                   bound.h_q == std::bit_width(bound.W) - 1,
               "blueprint shape-test packed width");
  if (scheme.get_poly_degree() == 2048 && scheme.get_l() == 6) {
    require_test(bound.r == 11 && bound.b == 2 && bound.w == 86 &&
                     bound.W == 128 && bound.h_q == 7,
                 "frozen blueprint sec. 18 anchor");
  }
  // Runtime capability bound: N0 = 2^10 gives w > 1024, so h_q = 11 stays
  // within W <= n yet exceeds the scheme's session-key expansion height (10).
  // The scheme-bound factory must reject it instead of letting the failure
  // surface later at set_client_session_keys.
  require_test(throws_invalid_argument([&] {
                 (void)make_tree_pir_params_for_scheme(bound.r + 10, 10,
                                                       scheme);
               }),
               "accepted an expansion height beyond the session keys");
  exhaust_config(make_tree_pir_params(13, 1, 2048, scheme.get_l(),
                                      scheme.get_l(), scheme.get_plain_mod(),
                                      {scheme.get_rns_mods()[0]}));
}
