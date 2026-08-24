#include "tests.h"
#include "tree_index.h"
#include "tree_query.h"
#include "tree_response.h"
#include "tree_select.h"

#include <array>
#include <bit>
#include <utility>
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

// Rebuild the 256-bit node from its little-endian chunks of `width` bits.
std::array<uint8_t, 32> assemble_node(const std::vector<uint64_t> &chunks,
                                      size_t width) {
  std::array<uint8_t, 32> out{};
  for (size_t c = 0; c < chunks.size(); ++c) {
    for (size_t bit = 0; bit < width; ++bit) {
      const size_t position = width * c + bit;
      if (position >= 256) break;
      if ((chunks[c] >> bit) & 1U) {
        out[position / 8] |= static_cast<uint8_t>(1U << (position % 8));
      }
    }
  }
  return out;
}

}  // namespace

// Real-scenario gate (blueprint sec. 23.1): g = 32 slots per node carry a
// full 32-byte synthetic value through the complete pipeline — strided
// packing, per-level selection, private rotation aligning every chunk at
// once, projection depth min(r, level) with r = log2(n/g), same-ring packing
// at capacity rho, and chunked client extraction.
void PirTest::test_tree_g32() {
  print_func_name(__FUNCTION__);
  constexpr size_t N = DBConsts::PolyDegree;

  PirParams scheme;
  PirClient client(scheme);
  const uint64_t t = scheme.get_plain_mod();
  SharedPirSessionKeys keys =
      client.create_session_keys(std::bit_width(N) - 1);

  // ---- Parameter derivation and rejections ----
  {
    const TreePirParams p = make_tree_pir_params_for_scheme(8, 2, 32, scheme);
    require_test(p.g == 32 && p.rho == N / 32 && p.r == 6 &&
                     p.P == p.N / p.rho,
                 "g = 32 derives rho = n/32 and r = log2(rho)");
    require_test(throws_invalid_argument([&] {
                   (void)make_tree_pir_params_for_scheme(8, 2, N, scheme);
                 }),
                 "accepted g = n with a single record per plaintext");
    require_test(throws_invalid_argument([&] {
                   (void)make_tree_pir_params(8, 2, N, 3, 1, 1, 17, {577});
                 }),
                 "accepted a non-divisor g");
  }

  // ---- Strided packing identity on the smallest g = 32 shape ----
  const TreeNodeChunkSource source = [&](size_t level, size_t index,
                                         size_t chunk) {
    return synthetic_tree_node_bytes_chunk(level, index, chunk, t);
  };
  {
    const TreePirParams tree =
        make_tree_pir_params_for_scheme(8, 2, 32, scheme);
    const std::vector<TreeLevelDatabase> levels =
        preprocess_tree_reference(tree, source);
    for (size_t level = 0; level <= tree.L; ++level) {
      const TreeLevelDatabase &db = levels[level];
      for (size_t node = 0; node < (size_t{1} << level); ++node) {
        const size_t p = node % db.R;
        const size_t u = node / db.R;
        for (size_t j = 0; j < tree.g; ++j) {
          require_test(db.plaintexts[p][u + j * tree.rho] ==
                           source(level, node, j),
                       "strided chunk placement");
        }
      }
    }
    // Oracle coordinates address the record's stride slots.
    for (size_t leaf = 0; leaf < tree.N; leaf += 7) {
      for (size_t level = 0; level <= tree.L; ++level) {
        const LevelOracle oracle =
            build_level_oracle_for_test(leaf, level, tree);
        require_test(
            levels[level].plaintexts[oracle.packed_plaintext_index]
                                    [oracle.record_position] ==
                source(level, oracle.node_index, 0),
            "oracle addresses chunk zero of the packed record");
      }
    }
  }

  // ---- End-to-end 32-byte recovery over two shapes ----
  const std::vector<std::pair<size_t, size_t>> shapes = {{8, 2}, {14, 3}};
  for (const auto &[L, a] : shapes) {
    const TreePirParams tree =
        make_tree_pir_params_for_scheme(L, a, 32, scheme);
    const PirParams qparams = tree_query_expansion_params(tree, scheme);
    PirServer server(qparams);
    server.set_client_session_keys(client.get_client_id(), keys);
    const PreprocessedTree db = preprocess_tree_mvp(tree, source, scheme);

    require_test(path_chunk_bounds(tree.L + 1, tree.rho).size() == 1,
                 "path fits one response at capacity rho");

    const std::vector<size_t> leaves = {
        0, tree.N - 1, static_cast<size_t>(0x2BADBEEFULL % tree.N)};
    for (size_t leaf : leaves) {
      RlweCt query = make_tree_query(client, scheme, tree, leaf);
      ExpandedTreeQuery unpacked = unpack_tree_query(
          server, scheme, tree, client.get_client_id(), query);
      TreePathResponse response = answer_path_mvp(
          db, unpacked, server, client.get_client_id(), tree, scheme);
      const std::vector<std::vector<uint64_t>> path =
          extract_path_chunks_mvp(response, client, tree);
      require_test(path.size() == tree.L + 1, "path has L + 1 nodes");
      for (size_t level = 0; level <= tree.L; ++level) {
        const size_t node = leaf >> (tree.L - level);
        const size_t width = std::bit_width(t) - 1;
        require_test(assemble_node(path[level], width) ==
                         synthetic_tree_node_bytes(level, node),
                     "extracted 32-byte node must match the tree");
        for (size_t j = (255 / width) + 1; j < tree.g; ++j) {
          require_test(path[level][j] == 0, "padding chunks decode to zero");
        }
      }
    }
  }
}
