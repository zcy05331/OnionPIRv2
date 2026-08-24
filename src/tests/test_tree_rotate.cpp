#include "tests.h"
#include "rlwe.h"
#include "tree_index.h"
#include "tree_query.h"
#include "tree_rotate.h"
#include "tree_select.h"

#include <bit>
#include <utility>
#include <vector>

namespace {

// Plaintext negacyclic reference (blueprint sec. 12.4): multiply a Z_t
// polynomial by X^e with e taken mod 2n; wrapped coefficients flip sign.
std::vector<uint64_t> plain_mul_x_pow(const std::vector<uint64_t> &poly,
                                      size_t e, uint64_t t) {
  const size_t n = poly.size();
  std::vector<uint64_t> out(n, 0);
  for (size_t i = 0; i < n; ++i) {
    const size_t raw = (i + e) % (2 * n);
    const size_t idx = raw % n;
    if (raw < n || poly[i] == 0) {
      out[idx] = poly[i];
    } else {
      out[idx] = t - poly[i];
    }
  }
  return out;
}

}  // namespace

// Sec. 12 gates: MulXPow against the plaintext negacyclic oracle for every
// exponent in [0, 2n), RotSelect driven by real unpacked gamma selectors, and
// PrivateRotateLevel aligning the target record to coefficient zero.
void PirTest::test_tree_rotate() {
  print_func_name(__FUNCTION__);
  constexpr size_t N = DBConsts::PolyDegree;

  PirParams scheme;
  PirClient client(scheme);
  const uint64_t t = scheme.get_plain_mod();
  const std::vector<uint64_t> qs(scheme.get_rns_mods().begin(),
                                 scheme.get_rns_mods().end());
  const double sigma = scheme.get_noise_std_dev();
  std::mt19937_64 rng(0x726f74617465ULL);

  // ---- MulXPow oracle: every exponent, dense sign-sensitive payload ----
  std::vector<uint64_t> msg(N);
  for (size_t i = 0; i < N; ++i) msg[i] = (3 * i + 1) % t;
  RlweCt msg_ct;
  encrypt_bfv_rns(msg, client.rlwe_sk_, N, qs, t, sigma, rng, msg_ct);
  for (size_t e = 0; e < 2 * N; ++e) {
    const RlweCt shifted = mul_x_pow(msg_ct, e, scheme);
    RlwePt expected;
    expected.data = plain_mul_x_pow(msg, e, t);
    const RlwePt got = client.decrypt_ct(shifted);
    if (!utils::plaintext_is_equal(got, expected)) {
      require_test(false, "MulXPow disagrees with the negacyclic oracle");
    }
  }

  // ---- RotSelect and PrivateRotateLevel over a real query ----
  const TreePirParams tree = make_tree_pir_params_for_scheme(16, 3, scheme);
  SharedPirSessionKeys keys =
      client.create_session_keys(std::bit_width(N) - 1);
  const PirParams qparams = tree_query_expansion_params(tree, scheme);
  PirServer server(qparams);
  server.set_client_session_keys(client.get_client_id(), keys);

  const TreeNodeSource source = [&](size_t level, size_t index) {
    return synthetic_tree_node_value(level, index, t);
  };
  const std::vector<TreeLevelDatabase> levels =
      preprocess_tree_reference(tree, source);
  const std::vector<LevelPlan> plans = build_level_plans(tree);

  for (size_t leaf : {size_t{0x2BADBEEFULL % (size_t{1} << 16)},
                      (size_t{1} << 16) - 1}) {
    const ClientCoordinates coords = client_index(leaf, tree);
    RlweCt query = make_tree_query(client, scheme, tree, leaf);
    ExpandedTreeQuery unpacked = unpack_tree_query(
        server, scheme, tree, client.get_client_id(), query);
    const AlphaPyramid pyramid =
        build_alpha_pyramid(unpacked.alpha, tree, scheme);

    // RotSelect in isolation: bit 0 keeps the input, bit 1 multiplies by
    // X^{-shift}; both cases occur among this leaf's gamma bits.
    for (size_t v : {size_t{0}, size_t{5}, size_t{10}}) {
      const size_t shift = 7;  // arbitrary shift in (0, n)
      const RlweCt out = rot_select(msg_ct, unpacked.gamma_selectors[v],
                                    shift, server, scheme);
      RlwePt expected;
      expected.data = coords.gamma_bits_le[v] == 1
                          ? plain_mul_x_pow(msg, 2 * N - shift, t)
                          : msg;
      require_test(utils::plaintext_is_equal(client.decrypt_ct(out),
                                             expected),
                   "RotSelect must rotate exactly when the bit is one");
    }

    // Algorithm 5 gate on every level: the selected level ciphertext rotated
    // by X^{-gamma_l} equals the plaintext reference, and the target node
    // reaches coefficient zero.
    for (size_t level = 0; level <= tree.L; ++level) {
      RlweCt selected = select_level(
          levels[level], plans[level], pyramid,
          std::span<GSWCt>(unpacked.beta_selectors), server, tree, scheme);
      RlweCt rotated = private_rotate_level(
          std::move(selected), plans[level],
          std::span<GSWCt>(unpacked.gamma_selectors), server, scheme);
      const LevelOracle oracle =
          build_level_oracle_for_test(leaf, level, tree);
      RlwePt expected;
      expected.data = plain_mul_x_pow(
          levels[level].plaintexts[oracle.packed_plaintext_index],
          2 * N - oracle.record_position, t);
      const RlwePt got = client.decrypt_ct(rotated);
      require_test(utils::plaintext_is_equal(got, expected),
                   "PrivateRotateLevel disagrees with the rotated plaintext");
      require_test(got.data[0] == source(level, oracle.node_index),
                   "rotated target must sit at coefficient zero");
    }
  }
}
