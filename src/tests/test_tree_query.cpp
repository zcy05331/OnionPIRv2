#include "tests.h"
#include "tree_index.h"
#include "tree_query.h"
#include "rlwe.h"

#include "hexl/hexl.hpp"

#include <utility>
#include <vector>

namespace {

bool plaintext_is_zero(const RlwePt &pt) {
  for (uint64_t value : pt.data) {
    if (value != 0) return false;
  }
  return true;
}

uint64_t circular_distance(uint64_t x, uint64_t y, uint64_t q) {
  const uint64_t d = x >= y ? x - y : y - x;
  return d > q - d ? q - d : d;
}

size_t selector_bit(const ClientCoordinates &coords, const TreePirParams &tree,
                    size_t group) {
  return group < tree.b ? coords.beta_bits_le[group]
                        : coords.gamma_bits_le[group - tree.b];
}

}  // namespace

// Blueprint sec. 9.3 isolated gate: pack a tree query, expand it with the
// production ExpandBFV walk, verify the exact logical order and scales of all
// w recovered constants, then drive every selector through RGSW conversion
// and an isolated CMux. Runs before any tree database exists.
void PirTest::test_tree_query() {
  print_func_name(__FUNCTION__);
  constexpr size_t N = DBConsts::PolyDegree;

  PirParams scheme;
  PirClient client(scheme);
  SharedPirSessionKeys keys = client.create_session_keys();
  const size_t ell = scheme.get_l();
  const uint64_t t = scheme.get_plain_mod();
  const uint64_t q0 = scheme.get_rns_mods()[0];
  const std::vector<uint64_t> qs(scheme.get_rns_mods().begin(),
                                 scheme.get_rns_mods().end());
  const std::vector<std::vector<uint64_t>> gadget =
      utils::gsw_gadget(ell, scheme.get_base_log2(), qs);
  // The phase-scale gate below only fires for gadget rows above 2^29. Under a
  // single-limb config the top row must clear that floor, or the scale/order
  // check would silently become vacuous; multi-limb configs (29-bit limbs)
  // are known-vacuous there and rely on the CMux gate instead.
  require_test(qs.size() > 1 || gadget[0][0] >= (uint64_t{1} << 29),
               "phase-scale gate is vacuous under this config");

  // Phase of a coefficient-form ciphertext under the first limb:
  // c0 + c1 * s mod q0. Gadget rows are RLWE* constants without a Delta
  // factor, so their scale is only visible at phase level.
  auto phase_limb0 = [&](const RlweCt &ct) {
    std::vector<uint64_t> c1(ct.c1.begin(), ct.c1.begin() + N);
    std::vector<uint64_t> phase(N);
    utils::ntt_fwd(c1.data(), N, q0);
    intel::hexl::EltwiseMultMod(phase.data(), c1.data(),
                                client.rlwe_sk_.data.data(), N, q0, 1);
    utils::ntt_inv(phase.data(), N, q0);
    for (size_t i = 0; i < N; ++i) {
      phase[i] = (phase[i] + ct.c0[i] % q0) % q0;
    }
    return phase;
  };

  auto check_leaf = [&](PirServer &server, const TreePirParams &tree,
                        size_t leaf, bool run_cmux_gate) {
    const ClientCoordinates coords = client_index(leaf, tree);
    RlweCt query = make_tree_query(client, scheme, tree, leaf);

    // Packed-level bit reversal: before expansion the alpha slot holds the
    // BFV value W^-1 mod t at coefficient BitRev(alpha, h_q).
    {
      uint64_t w_inv_t = 0;
      require_test(utils::try_invert_uint_mod(tree.W, t, w_inv_t),
                   "W invertible mod t");
      RlwePt packed = client.decrypt_ct(query);
      require_test(packed.data[utils::bit_reverse(coords.alpha, tree.h_q)] ==
                       w_inv_t,
                   "packed alpha slot scale at BitRev(alpha)");
    }

    std::vector<RlweCt> expanded =
        server.expand_query(client.get_client_id(), query);
    require_test(expanded.size() == tree.w,
                 "expansion returns exactly w useful leaves");

    // Alpha range [0, N0): an exact BFV one-hot. Every polynomial must be
    // fully zero except constant coefficient 1 at slot alpha, which also
    // certifies useful-leaf pruning and the W / W^-1 cancellation.
    for (size_t j = 0; j < tree.N0; ++j) {
      RlwePt pt = client.decrypt_ct(expanded[j]);
      if (j == coords.alpha) {
        require_test(pt.data[0] == 1, "alpha slot decrypts to one");
        pt.data[0] = 0;
        require_test(plaintext_is_zero(pt), "alpha slot has no other message");
      } else {
        require_test(plaintext_is_zero(pt), "non-target alpha slot is zero");
      }
    }

    // Selector groups: beta groups first, gamma groups after (sec. 8.1).
    // Zero selectors decrypt to zero everywhere; one selectors carry the
    // MSB-first gadget rows, phase-checked where the gadget value clears the
    // expansion noise floor. (Low rows are validated by the CMux gate.)
    constexpr uint64_t kNoiseFloor = uint64_t{1} << 29;
    constexpr uint64_t kPhaseTolerance = uint64_t{1} << 27;
    for (size_t group = 0; group < tree.b + tree.r; ++group) {
      const size_t bit = selector_bit(coords, tree, group);
      for (size_t row = 0; row < ell; ++row) {
        const RlweCt &row_ct = expanded[tree.N0 + group * ell + row];
        if (bit == 0) {
          require_test(plaintext_is_zero(client.decrypt_ct(row_ct)),
                       "zero selector row decrypts to zero");
        } else if (gadget[0][row] >= kNoiseFloor) {
          const std::vector<uint64_t> phase = phase_limb0(row_ct);
          require_test(circular_distance(phase[0], gadget[0][row] % q0, q0) <
                           kPhaseTolerance,
                       "one selector row carries its exact gadget scale");
        }
      }
    }

    if (!run_cmux_gate) return;

    // Production unpack (sec. 9.1/9.2): expansion plus RGSW completion behind
    // one server-side entry point. The alpha range must survive as the same
    // BFV one-hot, and every converted selector must drive an isolated CMux:
    // CMux(sel, x, y) returns x for bit 0 and y for bit 1.
    ExpandedTreeQuery unpacked = unpack_tree_query(
        server, scheme, tree, client.get_client_id(), query);
    require_test(unpacked.alpha.size() == tree.N0 &&
                     unpacked.beta_selectors.size() == tree.b &&
                     unpacked.gamma_selectors.size() == tree.r,
                 "unpack returns N0 alpha ciphertexts and b + r selectors");
    {
      RlwePt pt = client.decrypt_ct(unpacked.alpha[coords.alpha]);
      require_test(pt.data[0] == 1, "unpacked alpha slot decrypts to one");
    }

    const double sigma = scheme.get_noise_std_dev();
    std::mt19937_64 rng(0x7472656551756572ULL);
    std::vector<uint64_t> x_msg(N, 0), y_msg(N, 0);
    x_msg[0] = 5; x_msg[1] = 7;
    y_msg[0] = 3; y_msg[1] = 9;

    for (size_t group = 0; group < tree.b + tree.r; ++group) {
      GSWCt &selector =
          group < tree.b ? unpacked.beta_selectors[group]
                         : unpacked.gamma_selectors[group - tree.b];
      RlweCt x_ct, y_ct;
      encrypt_bfv_rns(x_msg, client.rlwe_sk_, N, qs, t, sigma, rng, x_ct);
      encrypt_bfv_rns(y_msg, client.rlwe_sk_, N, qs, t, sigma, rng, y_ct);
      RlweCt muxed;
      muxed.c0.assign(N * qs.size(), 0);
      muxed.c1.assign(N * qs.size(), 0);
      server.ext_prod_mux(x_ct, y_ct, selector, muxed);

      const RlwePt out = client.decrypt_ct(muxed);
      const std::vector<uint64_t> &expect =
          selector_bit(coords, tree, group) == 1 ? y_msg : x_msg;
      require_test(out.data[0] == expect[0] && out.data[1] == expect[1],
                   "unpacked selector drives an isolated CMux correctly");
    }
  };

  // Shapes: the blueprint sec. 18 split (b = 2) and the b = 0 boundary.
  const std::vector<std::pair<size_t, size_t>> shapes = {{16, 3}, {13, 2}};
  for (const auto &[L, a] : shapes) {
    const TreePirParams tree = make_tree_pir_params_for_scheme(L, a, scheme);
    require_test(scheme.get_expan_height() >= tree.h_q,
                 "session keys must cover the tree expansion height");
    const PirParams qparams = tree_query_expansion_params(tree, scheme);
    require_test(qparams.get_fst_dim_sz() == tree.N0 &&
                     qparams.get_num_dims() == 1 + tree.b + tree.r &&
                     qparams.get_expan_height() == tree.h_q,
                 "expansion view mirrors the tree query shape");

    PirServer server(qparams);
    server.set_client_session_keys(client.get_client_id(), keys);

    // The mixed-bit leaf runs the full gate including RGSW conversion and
    // CMux; boundary leaves cover pure one-hot / zero-selector patterns.
    // Leaf 1 additionally pins the beta group <-> bit-index binding: its beta
    // pattern (01 when b = 2) is asymmetric under bit reversal, so a packing
    // layer that consumed beta bits in the wrong order would fail here, and
    // its all-zero gamma drives zero selectors through the CMux gate too.
    const size_t mixed_leaf = 0x2BADBEEFULL % tree.N;
    check_leaf(server, tree, mixed_leaf, /*run_cmux_gate=*/true);
    check_leaf(server, tree, 0, /*run_cmux_gate=*/false);
    check_leaf(server, tree, tree.N - 1, /*run_cmux_gate=*/false);
    check_leaf(server, tree, 1, /*run_cmux_gate=*/true);

    // Fresh query randomness (sec. 8.4): the same leaf packs to a different
    // ciphertext each call; the expansion checks above already pinned the
    // decrypted constants, so equality of c1 is the only remaining risk.
    RlweCt first = make_tree_query(client, scheme, tree, mixed_leaf);
    RlweCt second = make_tree_query(client, scheme, tree, mixed_leaf);
    require_test(first.c1 != second.c1,
                 "repeated queries use fresh encryption randomness");
  }

  // Unpack must reject a server whose layout is not this tree's query shape
  // before any homomorphic work (wrong expansion height here, so scales
  // would silently disagree if it were accepted).
  {
    const TreePirParams tree = make_tree_pir_params_for_scheme(16, 3, scheme);
    PirServer mismatched(scheme.with_query_shape(
        {tree.N0, tree.b + tree.r, tree.h_q + 1}));
    mismatched.set_client_session_keys(client.get_client_id(), keys);
    RlweCt query = make_tree_query(client, scheme, tree, 0);
    bool rejected_shape = false;
    try {
      (void)unpack_tree_query(mismatched, scheme, tree,
                              client.get_client_id(), query);
    } catch (const std::invalid_argument &) {
      rejected_shape = true;
    }
    require_test(rejected_shape,
                 "accepted a shape-mismatched server for unpack");
  }

  // The query-shape view refuses shapes that overflow capacity or the ring.
  bool rejected = false;
  try {
    (void)scheme.with_query_shape({DBConsts::PolyDegree, 1, 3});
  } catch (const std::invalid_argument &) {
    rejected = true;
  }
  require_test(rejected, "accepted a query shape beyond its capacity");
  rejected = false;
  try {
    (void)scheme.with_query_shape({2, 1, 63});
  } catch (const std::invalid_argument &) {
    rejected = true;
  }
  require_test(rejected, "accepted an expansion height beyond the ring");
}
