#include "tests.h"
#include "tree_index.h"
#include "tree_query.h"
#include "tree_select.h"

#include <utility>
#include <vector>

namespace {

// Plaintext reference of the sec. 11.3 fold over an array in ordinary integer
// order: consume the target's bits MSB-first, keeping the lower half for bit 0
// and the upper half for bit 1.
uint64_t plain_fold(std::vector<uint64_t> values, size_t target, size_t bits,
                    bool msb_first) {
  for (size_t step = 0; step < bits; ++step) {
    const size_t bit_index = msb_first ? bits - 1 - step : step;
    const size_t bit = (target >> bit_index) & 1U;
    const size_t half = values.size() / 2;
    for (size_t j = 0; j < half; ++j) {
      values[j] = bit == 0 ? values[j] : values[j + half];
    }
    values.resize(half);
  }
  return values.front();
}

}  // namespace

// Milestone-2 gate (blueprint sec. 20): decrypted SelectLevel equals a direct
// D_l[p_l] lookup for every tested leaf and level, across all three plan
// cases, with the beta fold pinned MSB-first (sec. 21.5).
void PirTest::test_tree_select() {
  print_func_name(__FUNCTION__);

  // ---- Plaintext packing identity on a synthetic sec. 25 configuration ----
  {
    const TreePirParams small =
        make_tree_pir_params(6, 1, 8, 1, 1, 17, {577});
    const TreeNodeSource source = [&](size_t level, size_t index) {
      return synthetic_tree_node_value(level, index, small.t);
    };
    const std::vector<TreeLevelDatabase> levels =
        preprocess_tree_reference(small, source);
    require_test(levels.size() == small.L + 1, "one database per level");
    for (size_t level = 0; level <= small.L; ++level) {
      const TreeLevelDatabase &db = levels[level];
      const size_t node_count = size_t{1} << level;
      // Forward direction: every node lands at D_l[j mod R][j div R].
      for (size_t j = 0; j < node_count; ++j) {
        require_test(db.plaintexts[j % db.R][j / db.R] == source(level, j),
                     "packed node value");
      }
      // Zero fill beyond the occupied coefficients.
      for (size_t p = 0; p < db.R; ++p) {
        for (size_t u = 0; u < small.n; ++u) {
          if (p + u * db.R >= node_count) {
            require_test(db.plaintexts[p][u] == 0, "packed zero fill");
          }
        }
      }
    }
    // Oracle direction: the target node sits at coefficient gamma_l of
    // plaintext p_l for every leaf and level.
    for (size_t leaf = 0; leaf < small.N; ++leaf) {
      for (size_t level = 0; level <= small.L; ++level) {
        const LevelOracle oracle =
            build_level_oracle_for_test(leaf, level, small);
        require_test(
            levels[level].plaintexts[oracle.packed_plaintext_index]
                                    [oracle.record_position] ==
                source(level, oracle.node_index),
            "oracle coordinates address the packed node");
      }
    }
  }

  // ---- Plaintext fold reference: MSB-first indexes correctly, LSB-first
  // provably selects the wrong pairing for asymmetric targets ----
  for (size_t bits = 1; bits <= 3; ++bits) {
    const size_t count = size_t{1} << bits;
    std::vector<uint64_t> values(count);
    for (size_t i = 0; i < count; ++i) values[i] = 100 + i;
    bool lsb_differs_somewhere = false;
    for (size_t target = 0; target < count; ++target) {
      require_test(plain_fold(values, target, bits, true) == values[target],
                   "MSB-first fold equals direct indexing");
      if (plain_fold(values, target, bits, false) != values[target]) {
        lsb_differs_somewhere = true;
      }
    }
    require_test(bits < 2 || lsb_differs_somewhere,
                 "LSB-first fold must fail for some target");
  }

  // ---- Encrypted Milestone-2 gate over both tree shapes ----
  PirParams scheme;
  PirClient client(scheme);
  SharedPirSessionKeys keys = client.create_session_keys();
  const TreeNodeSource node_source = [&](size_t level, size_t index) {
    return synthetic_tree_node_value(level, index, scheme.get_plain_mod());
  };

  const std::vector<std::pair<size_t, size_t>> shapes = {{16, 3}, {13, 2}};
  for (const auto &[L, a] : shapes) {
    const TreePirParams tree = make_tree_pir_params_for_scheme(L, a, scheme);
    const PirParams qparams = tree_query_expansion_params(tree, scheme);
    PirServer server(qparams);
    server.set_client_session_keys(client.get_client_id(), keys);

    const std::vector<TreeLevelDatabase> levels =
        preprocess_tree_reference(tree, node_source);
    const std::vector<LevelPlan> plans = build_level_plans(tree);

    // Boundary leaves, a mixed-bit leaf, and a beta-asymmetric leaf
    // (gamma = 1, alpha = 1, beta = 1, i.e. beta bits 01) that distinguishes
    // the fold order at the deepest level.
    const std::vector<size_t> leaves = {
        0, tree.N - 1, 0x2BADBEEFULL % tree.N,
        tree.P + tree.B + (tree.b >= 2 ? 1 : 0)};
    for (size_t leaf : leaves) {
      const ClientCoordinates coords = client_index(leaf, tree);
      RlweCt query = make_tree_query(client, scheme, tree, leaf);
      ExpandedTreeQuery unpacked = unpack_tree_query(
          server, scheme, tree, client.get_client_id(), query);
      AlphaPyramid pyramid =
          build_alpha_pyramid(unpacked.alpha, tree, scheme);

      // Sec. 10 gate for every leaf (alpha = 0 for leaf 0, the maximal
      // alpha for the last leaf): pyramid level c one-hot-selects
      // floor(alpha / 2^c), and the apex encrypts the constant 1.
      for (size_t c = 0; c <= tree.a; ++c) {
        for (size_t j = 0; j < pyramid[c].size(); ++j) {
          RlwePt pt = client.decrypt_ct(pyramid[c][j]);
          const uint64_t expected = (coords.alpha >> c) == j ? 1 : 0;
          require_test(pt.data[0] == expected, "pyramid one-hot indicator");
          for (size_t i = 1; i < pt.data.size(); ++i) {
            require_test(pt.data[i] == 0, "pyramid slot is a constant");
          }
        }
      }

      // Milestone-2 gate: every level of the path decrypts to the exact
      // packed plaintext D_l[p_l].
      for (size_t level = 0; level <= tree.L; ++level) {
        RlweCt selected = select_level(
            levels[level], plans[level], pyramid,
            std::span<GSWCt>(unpacked.beta_selectors), server, tree, scheme);
        const LevelOracle oracle =
            build_level_oracle_for_test(leaf, level, tree);
        RlwePt expected;
        expected.data = levels[level].plaintexts[oracle.packed_plaintext_index];
        const RlwePt decrypted = client.decrypt_ct(selected);
        require_test(utils::plaintext_is_equal(decrypted, expected),
                     "SelectLevel equals the direct plaintext lookup");
      }

      // Sec. 21.5 regression at the encrypted layer: replaying the deepest
      // level's fold with the selector order reversed (an LSB-first
      // implementation) must select a different candidate for this
      // beta-asymmetric leaf.
      if (tree.b >= 2 && leaf == leaves.back()) {
        const LevelPlan &deepest = plans[tree.L];
        std::vector<RlweCt> candidates = evaluate_alpha_dimension(
            levels[tree.L], pyramid[0], deepest, tree, scheme);
        std::vector<GSWCt> reversed(unpacked.beta_selectors.rbegin(),
                                    unpacked.beta_selectors.rend());
        RlweCt wrong = fold_beta_dimension(std::move(candidates), deepest,
                                           std::span<GSWCt>(reversed), server);
        const LevelOracle oracle =
            build_level_oracle_for_test(leaf, tree.L, tree);
        RlwePt expected;
        expected.data =
            levels[tree.L].plaintexts[oracle.packed_plaintext_index];
        require_test(!utils::plaintext_is_equal(client.decrypt_ct(wrong),
                                                expected),
                     "LSB-first selector order must not reproduce D_l[p_l]");
      }
    }
  }
}
