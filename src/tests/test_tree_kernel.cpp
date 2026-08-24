#include "tests.h"
#include "tree_index.h"
#include "tree_query.h"
#include "tree_select.h"

#include <bit>
#include <utility>
#include <vector>

// Milestone-6 gate (blueprint sec. 20): the optimized NTT-view first
// dimension must agree with the scalar reference kernel coefficient by
// coefficient. Both paths compute the identical mod-q ring expression, so
// the comparison is on raw ciphertext coefficients — bit equality, not
// merely equal decryptions.
void PirTest::test_tree_kernel() {
  print_func_name(__FUNCTION__);
  constexpr size_t N = DBConsts::PolyDegree;

  PirParams scheme;
  PirClient client(scheme);
  const uint64_t t = scheme.get_plain_mod();
  SharedPirSessionKeys keys =
      client.create_session_keys(std::bit_width(N) - 1);
  const TreeNodeSource source = [&](size_t level, size_t index) {
    return synthetic_tree_node_value(level, index, t);
  };

  const std::vector<std::pair<size_t, size_t>> shapes = {{16, 3}, {13, 2}};
  for (const auto &[L, a] : shapes) {
    const TreePirParams tree = make_tree_pir_params_for_scheme(L, a, scheme);
    const PirParams qparams = tree_query_expansion_params(tree, scheme);
    PirServer server(qparams);
    server.set_client_session_keys(client.get_client_id(), keys);
    const PreprocessedTree db = preprocess_tree_mvp(tree, source, scheme);

    for (size_t leaf : {size_t{0},
                        static_cast<size_t>(0x2BADBEEFULL % tree.N)}) {
      RlweCt query = make_tree_query(client, scheme, tree, leaf);
      ExpandedTreeQuery unpacked = unpack_tree_query(
          server, scheme, tree, client.get_client_id(), query);
      const AlphaPyramid pyramid =
          build_alpha_pyramid(unpacked.alpha, tree, scheme);
      const AlphaPyramid pyramid_ntt = pyramid_to_ntt(pyramid, scheme);

      AlphaPyramidM32 pyramid_m32;
      if (scheme.get_composite_rns().enabled) {
        pyramid_m32 = pyramid_to_m32(pyramid_ntt, scheme);
      }
      for (size_t level = 0; level <= tree.L; ++level) {
        const RlweCt scalar = select_level(
            db.canonical[level], db.plans[level], pyramid,
            std::span<GSWCt>(unpacked.beta_selectors), server, tree, scheme);
        const TreeLevelDatabaseNtt ntt_view =
            build_level_ntt_view(db.canonical[level], scheme);
        const RlweCt optimized = select_level_ntt(
            ntt_view, db.plans[level], pyramid_ntt,
            std::span<GSWCt>(unpacked.beta_selectors), server, tree, scheme);
        require_test(scalar.c0 == optimized.c0 &&
                         scalar.c1 == optimized.c1 &&
                         scalar.ntt_form == optimized.ntt_form,
                     "scalar and NTT kernels must agree bit for bit");
        if (scheme.get_composite_rns().enabled) {
          const RlweCt matmul = select_level_m32(
              db.m32[level], db.plans[level], pyramid_m32,
              std::span<GSWCt>(unpacked.beta_selectors), server, tree,
              scheme);
          require_test(scalar.c0 == matmul.c0 && scalar.c1 == matmul.c1 &&
                           scalar.ntt_form == matmul.ntt_form,
                       "scalar and m32 matmul kernels must agree bit for bit");
        }
      }
    }
  }
}
