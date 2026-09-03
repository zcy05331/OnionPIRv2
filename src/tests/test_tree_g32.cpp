#include "tests.h"
#include "tree_index.h"
#include "tree_query.h"
#include "tree_response.h"
#include "tree_select.h"

#include <array>
#include <bit>
#include <cstdint>
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

// Split a 256-bit node into the little-endian `width`-bit chunk `chunk`
// (bits past the end read as zero), the layout assemble_node undoes.
uint64_t node_chunk(const std::array<uint8_t, 32> &bytes, size_t chunk,
                    size_t width) {
  uint64_t value = 0;
  for (size_t bit = 0; bit < width; ++bit) {
    const size_t position = width * chunk + bit;
    if (position >= 256) break;
    if ((bytes[position / 8] >> (position % 8)) & 1U) {
      value |= uint64_t{1} << bit;
    }
  }
  return value;
}

// A genuine parent = H(left || right) relation for the Merkle test below:
// SplitMix64 folded over the 64 input bytes. Deterministic and sensitive
// to every input bit, which is what the authentication check needs; not a
// cryptographic hash.
uint64_t splitmix64(uint64_t &state) {
  uint64_t z = (state += 0x9E3779B97F4A7C15ULL);
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31);
}
std::array<uint8_t, 32> hash_pair(const std::array<uint8_t, 32> &left,
                                  const std::array<uint8_t, 32> &right) {
  uint64_t state = 0x4D65726B6C655472ULL;
  for (const auto *child : {&left, &right}) {
    for (size_t word = 0; word < 4; ++word) {
      uint64_t v = 0;
      for (size_t b = 0; b < 8; ++b) {
        v |= uint64_t{(*child)[word * 8 + b]} << (8 * b);
      }
      state ^= v;
      (void)splitmix64(state);
    }
  }
  std::array<uint8_t, 32> out{};
  for (size_t word = 0; word < 4; ++word) {
    const uint64_t v = splitmix64(state);
    for (size_t b = 0; b < 8; ++b) {
      out[word * 8 + b] = static_cast<uint8_t>(v >> (8 * b));
    }
  }
  return out;
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
    const TreePirParams p = make_tree_pir_params_for_scheme(tree_height_for(2, 0, 32), 2, 32, scheme);
    require_test(p.g == 32 && p.rho == N / 32 &&
                     p.r == std::bit_width(N / 32) - 1 &&
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
        make_tree_pir_params_for_scheme(tree_height_for(2, 0, 32), 2, 32, scheme);
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
  const std::vector<std::pair<size_t, size_t>> shapes = {
      {tree_height_for(2, 0, 32), 2}, {tree_height_for(3, 5, 32), 3}};
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

  // ---- A real Merkle tree through the generic chunk source ----
  // Every other caller feeds synthetic nodes; this is the adapter a
  // deployment writes. Node (l, j) stores what a verifier needs at level l:
  // the root at level 0 and the hash of j's sibling below it, so the
  // retrieved ancestor path is an authentication path. The test recomputes
  // the root from the leaf hash and the retrieved siblings and compares it
  // with the root built independently from all leaves.
  {
    const size_t L = tree_height_for(2, 0, 32);
    std::vector<std::vector<std::array<uint8_t, 32>>> hashes(L + 1);
    hashes[L].resize(size_t{1} << L);
    for (size_t i = 0; i < hashes[L].size(); ++i) {
      std::array<uint8_t, 32> leaf_bytes{};
      for (size_t b = 0; b < 8; ++b) {
        leaf_bytes[b] = static_cast<uint8_t>((uint64_t{i} * 0x9E3779B1ULL) >> (8 * b));
      }
      hashes[L][i] = hash_pair(leaf_bytes, leaf_bytes);
    }
    for (size_t level = L; level-- > 0;) {
      hashes[level].resize(size_t{1} << level);
      for (size_t j = 0; j < hashes[level].size(); ++j) {
        hashes[level][j] =
            hash_pair(hashes[level + 1][2 * j], hashes[level + 1][2 * j + 1]);
      }
    }
    const size_t width = std::bit_width(t) - 1;
    const auto stored = [&](size_t level, size_t index)
        -> const std::array<uint8_t, 32> & {
      return level == 0 ? hashes[0][0] : hashes[level][index ^ 1];
    };
    const TreeNodeChunkSource merkle_source =
        [&](size_t level, size_t index, size_t chunk) {
          return node_chunk(stored(level, index), chunk, width);
        };
    // node_chunk must be the inverse of assemble_node on the stored layout.
    {
      std::vector<uint64_t> chunks(32);
      for (size_t j = 0; j < 32; ++j) chunks[j] = merkle_source(L, 5, j);
      require_test(assemble_node(chunks, width) == stored(L, 5),
                   "node_chunk and assemble_node must be inverses");
    }

    const TreePirParams tree =
        make_tree_pir_params_for_scheme(L, 2, 32, scheme);
    const PirParams qparams = tree_query_expansion_params(tree, scheme);
    PirServer server(qparams);
    server.set_client_session_keys(client.get_client_id(), keys);
    const PreprocessedTree db =
        preprocess_tree_mvp(tree, merkle_source, scheme);
    for (size_t leaf : {size_t{0}, tree.N - 1,
                        static_cast<size_t>(0x2BADBEEFULL % tree.N)}) {
      RlweCt query = make_tree_query(client, scheme, tree, leaf);
      ExpandedTreeQuery unpacked = unpack_tree_query(
          server, scheme, tree, client.get_client_id(), query);
      TreePathResponse response = answer_path_mvp(
          db, unpacked, server, client.get_client_id(), tree, scheme);
      const std::vector<std::vector<uint64_t>> path =
          extract_path_chunks_mvp(response, client, tree);
      require_test(path.size() == L + 1, "authentication path length");
      // Climb from the leaf hash with the retrieved siblings.
      std::array<uint8_t, 32> acc = hashes[L][leaf];
      for (size_t level = L; level >= 1; --level) {
        const size_t node = leaf >> (L - level);
        const std::array<uint8_t, 32> sibling =
            assemble_node(path[level], width);
        require_test(sibling == hashes[level][node ^ 1],
                     "retrieved value must be the sibling hash");
        acc = (node & 1) ? hash_pair(sibling, acc) : hash_pair(acc, sibling);
      }
      require_test(acc == hashes[0][0],
                   "siblings must reproduce the independently built root");
      require_test(assemble_node(path[0], width) == hashes[0][0],
                   "level 0 must return the root");
    }
  }
}
