#include "tests.h"
#include "tree_index.h"
#include "tree_query.h"
#include "tree_response.h"
#include "tree_select.h"

#include <bit>
#include <chrono>
#include <utility>
#include <vector>

// Milestone-4 gate (blueprint sec. 20): every tested leaf recovers the
// complete root-to-leaf ancestor path through the full encrypted pipeline
// (pack, unpack, per-level select/rotate/project, same-ring packing, client
// decode), with the sec. 21.8 chunk-partition arithmetic unit-tested and
// fresh-seed repeatability asserted.
void PirTest::test_tree_e2e() {
  print_func_name(__FUNCTION__);
  constexpr size_t N = DBConsts::PolyDegree;

  // ---- Chunk partition arithmetic (sec. 21.8) with tiny capacities ----
  {
    const auto one = path_chunk_bounds(1, 4);
    require_test(one.size() == 1 && one[0] == std::make_pair(size_t{0},
                                                             size_t{1}),
                 "single-node chunking");
    const auto exact = path_chunk_bounds(4, 4);
    require_test(exact.size() == 1 && exact[0].second == 4,
                 "exactly one full chunk");
    const auto multi = path_chunk_bounds(6, 4);
    require_test(multi.size() == 2 &&
                     multi[0] == std::make_pair(size_t{0}, size_t{4}) &&
                     multi[1] == std::make_pair(size_t{4}, size_t{2}),
                 "multi-chunk partition without overlap or wrap");
    size_t covered = 0;
    for (const auto &[first, size] : multi) {
      require_test(first == covered && size <= 4, "chunk continuity");
      covered += size;
    }
    require_test(covered == 6, "chunks cover every level exactly once");
  }

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

    const std::vector<size_t> leaves = {
        0, tree.N - 1, 0x2BADBEEFULL % tree.N,
        tree.P + tree.B + (tree.b >= 2 ? 1 : 0)};
    for (size_t leaf : leaves) {
      RlweCt query = make_tree_query(client, scheme, tree, leaf);
      ExpandedTreeQuery unpacked = unpack_tree_query(
          server, scheme, tree, client.get_client_id(), query);

      const auto start = std::chrono::steady_clock::now();
      TreePathResponse response =
          answer_path_mvp(db, unpacked, server, client.get_client_id(), tree,
                          scheme);
      const double server_ms =
          std::chrono::duration<double, std::milli>(
              std::chrono::steady_clock::now() - start)
              .count();
      require_test(response.chunks.size() == 1,
                   "MVP path fits one main-ring ciphertext");

      const std::vector<uint64_t> path =
          extract_path_mvp(response, client, tree);
      require_test(path.size() == tree.L + 1, "path has L + 1 values");
      for (size_t level = 0; level <= tree.L; ++level) {
        const size_t node = leaf >> (tree.L - level);
        require_test(path[level] == source(level, node),
                     "extracted path value must match the tree node");
      }
      BENCH_PRINT("L=" << L << " leaf=" << leaf << " path server time "
                  << server_ms << " ms, small_q response: "
                  << (response.small_q ? "yes" : "no"));
    }

    // Fresh-seed repeatability (sec. 21.9): a second query for the same leaf
    // is a different ciphertext yet yields the identical plaintext path.
    const size_t leaf = leaves.back();
    RlweCt first_q = make_tree_query(client, scheme, tree, leaf);
    RlweCt second_q = make_tree_query(client, scheme, tree, leaf);
    require_test(first_q.c1 != second_q.c1,
                 "repeated path queries must use fresh randomness");
    ExpandedTreeQuery first_u = unpack_tree_query(
        server, scheme, tree, client.get_client_id(), first_q);
    ExpandedTreeQuery second_u = unpack_tree_query(
        server, scheme, tree, client.get_client_id(), second_q);
    TreePathResponse first_r = answer_path_mvp(
        db, first_u, server, client.get_client_id(), tree, scheme);
    TreePathResponse second_r = answer_path_mvp(
        db, second_u, server, client.get_client_id(), tree, scheme);
    require_test(extract_path_mvp(first_r, client, tree) ==
                     extract_path_mvp(second_r, client, tree),
                 "fresh-seed repetitions must decode the same path");
  }
}
