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
// decode). The sec. 21.8 chunk partition is unit-tested with tiny capacities
// and then exercised encrypted: the g = 128 shape has rho = 16 < L + 1, so
// its path spans two response ciphertexts. Fresh-seed repeatability is
// asserted on every shape.
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
  const TreeNodeSource scalar_source = [&](size_t level, size_t index) {
    return synthetic_tree_node_value(level, index, t);
  };
  const TreeNodeChunkSource chunk_source = [&](size_t level, size_t index,
                                               size_t chunk) {
    return synthetic_tree_node_bytes_chunk(level, index, chunk, t);
  };

  // g = 1: scalar MVP shapes, single response ciphertext.
  // g = n / 16: rho = 16 records per plaintext, so the 17-level path
  // of L = 16 needs two response ciphertexts (multi-chunk packing).
  struct Shape { size_t L, a, g, expected_chunks; };
  const std::vector<Shape> shapes = {
      {tree_height_for(3, 2), 3, 1, 1},
      {tree_height_for(2, 0), 2, 1, 1},
      {16, 3, N / 16, 2}};
  for (const Shape &shape : shapes) {
    const TreePirParams tree =
        make_tree_pir_params_for_scheme(shape.L, shape.a, shape.g, scheme);
    require_test(path_chunk_bounds(tree.L + 1, tree.rho).size() ==
                     shape.expected_chunks,
                 "shape does not produce the intended chunk count");
    const PirParams qparams = tree_query_expansion_params(tree, scheme);
    PirServer server(qparams);
    server.set_client_session_keys(client.get_client_id(), keys);
    const PreprocessedTree db =
        shape.g == 1 ? preprocess_tree_mvp(tree, scalar_source, scheme)
                     : preprocess_tree_mvp(tree, chunk_source, scheme);
    const auto expected_chunk = [&](size_t level, size_t node, size_t j) {
      return shape.g == 1 ? scalar_source(level, node)
                          : chunk_source(level, node, j);
    };

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
      require_test(response.chunks.size() == shape.expected_chunks,
                   "response ciphertext count");
      require_test(response.level_count == tree.L + 1 &&
                       response.level_offsets.size() == tree.L + 1,
                   "response placement map shape");
      for (size_t level = 0; level <= tree.L; ++level) {
        require_test(response.level_offsets[level] < tree.rho,
                     "level offset must stay inside one mod-rho period");
      }

      if (leaf == leaves.front()) {
        // Extraction refuses, before any decryption, a chunk count that
        // does not match the level partition, a response without its
        // placement map, and the flat extractor on multi-chunk nodes.
        const auto rejects = [](auto &&fn) {
          try {
            fn();
          } catch (const std::invalid_argument &) {
            return true;
          }
          return false;
        };
        TreePathResponse extra_chunk = response;
        extra_chunk.chunks.push_back(extra_chunk.chunks.back());
        require_test(rejects([&] {
                       (void)extract_path_chunks_mvp(extra_chunk, client,
                                                     tree);
                     }),
                     "extracted a response with a stray chunk");
        TreePathResponse unmapped = response;
        unmapped.level_offsets.pop_back();
        require_test(rejects([&] {
                       (void)extract_path_chunks_mvp(unmapped, client, tree);
                     }),
                     "extracted a response without its placement map");
        if (tree.g != 1) {
          require_test(rejects([&] {
                         (void)extract_path_mvp(response, client, tree);
                       }),
                       "flat extraction accepted multi-chunk nodes");
        }
      }
      const std::vector<std::vector<uint64_t>> path =
          extract_path_chunks_mvp(response, client, tree);
      require_test(path.size() == tree.L + 1, "path has L + 1 values");
      for (size_t level = 0; level <= tree.L; ++level) {
        const size_t node = leaf >> (tree.L - level);
        require_test(path[level].size() == tree.g, "g chunks per level");
        for (size_t j = 0; j < tree.g; ++j) {
          require_test(path[level][j] == expected_chunk(level, node, j),
                       "extracted path value must match the tree node");
        }
      }
      if (shape.g == 1) {
        const std::vector<uint64_t> flat = extract_path_mvp(response, client,
                                                            tree);
        for (size_t level = 0; level <= tree.L; ++level) {
          require_test(flat[level] == path[level][0],
                       "scalar extraction view must agree with chunk view");
        }
      }
      BENCH_PRINT("L=" << shape.L << " g=" << shape.g << " leaf=" << leaf
                  << " chunks=" << response.chunks.size()
                  << " path server time " << server_ms
                  << " ms, small_q response: "
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
    require_test(extract_path_chunks_mvp(first_r, client, tree) ==
                     extract_path_chunks_mvp(second_r, client, tree),
                 "fresh-seed repetitions must decode the same path");
  }
}
