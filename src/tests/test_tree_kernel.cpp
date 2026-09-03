#include "tests.h"
#include "tree_index.h"
#include "tree_query.h"
#include "tree_select.h"

#include <bit>
#include <utility>
#include <vector>

// Milestone-6 gate (blueprint sec. 20): the optimized NTT-view and m32
// first-dimension kernels must agree with the scalar reference kernel
// coefficient by coefficient (raw ciphertext bit equality, not merely equal
// decryptions), and the scalar reference itself must decrypt to the packed
// plaintext D_l[p_l] so a bug shared by all three kernels cannot hide. Runs
// on the scalar g = 1 shapes and on the 32-chunk g = 32 shape that the real
// node payload uses, for the first, last and an interior leaf.
void PirTest::test_tree_kernel() {
  print_func_name(__FUNCTION__);
  constexpr size_t N = DBConsts::PolyDegree;

  PirParams scheme;
  PirClient client(scheme);
  const uint64_t t = scheme.get_plain_mod();
  SharedPirSessionKeys keys =
      client.create_session_keys(std::bit_width(N) - 1);
  const TreeNodeSource scalar_source = [&](size_t level, size_t index) {
    return synthetic_tree_node_value(level, index, t);
  };
  const TreeNodeChunkSource chunk_source = [&](size_t level, size_t index,
                                               size_t chunk) {
    return synthetic_tree_node_bytes_chunk(level, index, chunk, t);
  };

  struct Shape { size_t L, a, g; };
  const std::vector<Shape> shapes = {{tree_height_for(3, 2), 3, 1},
                                     {tree_height_for(2, 0), 2, 1},
                                     {tree_height_for(3, 5, 32), 3, 32}};
  for (const Shape &shape : shapes) {
    const TreePirParams tree =
        make_tree_pir_params_for_scheme(shape.L, shape.a, shape.g, scheme);
    const PirParams qparams = tree_query_expansion_params(tree, scheme);
    PirServer server(qparams);
    server.set_client_session_keys(client.get_client_id(), keys);
    const PreprocessedTree db =
        shape.g == 1 ? preprocess_tree_mvp(tree, scalar_source, scheme)
                     : preprocess_tree_mvp(tree, chunk_source, scheme);

    for (size_t leaf : {size_t{0}, tree.N - 1,
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
        // Plaintext oracle for the reference kernel.
        const LevelOracle oracle =
            build_level_oracle_for_test(leaf, level, tree);
        RlwePt expected;
        expected.data =
            db.canonical[level].plaintexts[oracle.packed_plaintext_index];
        require_test(utils::plaintext_is_equal(client.decrypt_ct(scalar),
                                               expected),
                     "scalar kernel must select the packed plaintext D_l[p_l]");

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
