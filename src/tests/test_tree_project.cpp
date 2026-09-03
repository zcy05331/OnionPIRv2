#include "tests.h"
#include "rlwe.h"
#include "tree_index.h"
#include "tree_project.h"
#include "tree_query.h"
#include "tree_rotate.h"
#include "tree_select.h"

#include <bit>
#include <utility>
#include <vector>

// Sec. 13 gates: the projection map itself for every depth 0..log2(n)
// (including the exact 2^{-d} scaling), then the Milestone-3 gate — after
// private rotation and projection the target value sits at coefficient zero
// and every other coefficient is zero — plus the full-depth vs min(r, level)
// equivalence above level r and the sec. 18 noise diagnostics.
void PirTest::test_tree_project() {
  print_func_name(__FUNCTION__);
  constexpr size_t N = DBConsts::PolyDegree;
  constexpr size_t kLogN = std::bit_width(N) - 1;

  PirParams scheme;
  PirClient client(scheme);
  const uint64_t t = scheme.get_plain_mod();
  const std::vector<uint64_t> qs(scheme.get_rns_mods().begin(),
                                 scheme.get_rns_mods().end());
  const double sigma = scheme.get_noise_std_dev();
  std::mt19937_64 rng(0x70726f6a656374ULL);
  SharedPirSessionKeys keys = client.create_session_keys(kLogN);

  // ---- Pure projection oracle: pi_d keeps exactly the stride-2^d
  // coefficients at their original scale ----
  std::vector<uint64_t> msg(N);
  for (size_t i = 0; i < N; ++i) msg[i] = (5 * i + 3) % t;
  for (size_t depth = 0; depth <= kLogN; ++depth) {
    RlweCt ct;
    encrypt_bfv_rns(msg, client.rlwe_sk_, N, qs, t, sigma, rng, ct);
    const RlweCt projected =
        project_keep_stride(std::move(ct), depth, keys->bv_galois_keys,
                            scheme);
    RlwePt expected;
    expected.data.assign(N, 0);
    for (size_t i = 0; i < N; i += size_t{1} << depth) {
      expected.data[i] = msg[i];
    }
    require_test(utils::plaintext_is_equal(client.decrypt_ct(projected),
                                           expected),
                 "projection must keep exactly the stride coefficients");
    if (depth == kLogN) {
      const int budget = client.noise_budget(projected);
      BENCH_PRINT("projection depth " << depth << " noise budget: "
                  << budget << " bits");
      // noise_budget is a first-limb diagnostic; multi-limb builds rely on
      // the coefficient checks above.
      if (scheme.K() == 1) {
        require_test(budget > 0,
                     "full-depth projection has no noise budget");
      }
    }
  }

  // ---- Milestone-3 gate over both tree shapes ----
  const TreeNodeSource source = [&](size_t level, size_t index) {
    return synthetic_tree_node_value(level, index, t);
  };
  const std::vector<std::pair<size_t, size_t>> shapes = {
      {tree_height_for(3, 2), 3}, {tree_height_for(2, 0), 2}};
  for (const auto &[L, a] : shapes) {
    const TreePirParams tree = make_tree_pir_params_for_scheme(L, a, scheme);
    const PirParams qparams = tree_query_expansion_params(tree, scheme);
    PirServer server(qparams);
    server.set_client_session_keys(client.get_client_id(), keys);
    const std::vector<TreeLevelDatabase> levels =
        preprocess_tree_reference(tree, source);
    const std::vector<LevelPlan> plans = build_level_plans(tree);

    for (size_t leaf : {size_t{0}, tree.N - 1,
                        static_cast<size_t>(0x2BADBEEFULL % tree.N)}) {
      RlweCt query = make_tree_query(client, scheme, tree, leaf);
      ExpandedTreeQuery unpacked = unpack_tree_query(
          server, scheme, tree, client.get_client_id(), query);
      const AlphaPyramid pyramid =
          build_alpha_pyramid(unpacked.alpha, tree, scheme);

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
        expected.data.assign(N, 0);
        expected.data[0] = source(level, oracle.node_index);

        const RlweCt projected = project_keep_stride(
            rotated, plans[level].projection_depth, keys->bv_galois_keys,
            scheme);
        require_test(utils::plaintext_is_equal(client.decrypt_ct(projected),
                                               expected),
                     "rotate + project must isolate the target node");

        // Sec. 21.7: above level r the reduced depth min(r, level) and the
        // full depth r agree on the valid packed layout.
        if (level < tree.r) {
          const RlweCt full_depth = project_keep_stride(
              rotated, tree.r, keys->bv_galois_keys, scheme);
          require_test(
              utils::plaintext_is_equal(client.decrypt_ct(full_depth),
                                        expected),
              "full-depth projection must agree above level r");
        }
        // Sec. 18: the remaining budget must stay positive at every level;
        // the deepest level is the tightest point of the path pipeline.
        const int budget = client.noise_budget(projected);
        if (scheme.K() == 1) {
          require_test(budget > 0,
                       "select/rotate/project exhausted the noise budget");
        }
        if (level == tree.L) {
          BENCH_PRINT("L=" << L << " leaf=" << leaf
                      << " deepest level noise budget after "
                      "select/rotate/project: " << budget << " bits");
        }
      }
    }
  }
}
