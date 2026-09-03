#include "tests.h"
#include "tree_compress.h"
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

// Milestone-7 gate: the d = 2 ring switch compresses the aligned path
// response to one R_{n/2} ciphertext that still decodes the exact path.
void PirTest::test_tree_compress() {
  print_func_name(__FUNCTION__);
  constexpr size_t N = DBConsts::PolyDegree;

  // ---- Small-ring product identities (negacyclic wrap and linearity) ----
  {
    const uint64_t q = 97;
    std::vector<uint64_t> a(8, 0), b(8, 0);
    a[7] = 3;  // 3 Y^7
    b[1] = 5;  // 5 Y
    const auto product = small_ring_mul(a, b, q);
    require_test(product[0] == q - 15, "Y^8 = -1 wrap with sign");
    for (size_t i = 1; i < 8; ++i) {
      require_test(product[i] == 0, "single-term product stays a monomial");
    }
    std::vector<uint64_t> u{1, 2, 3, 4, 0, 0, 0, 0};
    std::vector<uint64_t> v{7, 0, 0, 0, 0, 0, 0, 9};
    // (u * v)[3] = u3*v0 - u4*v7-style wrap checked against direct sums.
    const auto uv = small_ring_mul(u, v, q);
    uint64_t direct = (4 * 7) % q;  // u3 v0
    direct = (direct + q - (9 * 1) % q) % q;  // u4.. wrap terms: u_i v_j,
    // i + j = 11 -> -u_i v_j at Y^3: (i, j) = (4..) none nonzero except
    // u_{i} with i + 7 = 11 -> i = 4 (zero) — recompute directly instead:
    uint64_t expect = 0;
    for (size_t i = 0; i < 8; ++i) {
      for (size_t j = 0; j < 8; ++j) {
        const uint64_t term = (u[i] * v[j]) % q;
        if (term == 0) continue;
        if (i + j == 3) expect = (expect + term) % q;
        if (i + j == 11) expect = (expect + q - term) % q;
      }
    }
    require_test(uv[3] == expect, "schoolbook matches the direct convolution");
  }

  PirParams scheme;
  // The d = 2 ring switch is defined for the single-limb scheme only; a
  // multi-limb build cannot verify this gate, so the test is reported as
  // not applicable rather than as a pass.
  require_applicable(
      scheme.K() == 1,
      "ring-switch gate requires a single-limb (K = 1) scheme build");
  PirClient client(scheme);
  const uint64_t t = scheme.get_plain_mod();
  SharedPirSessionKeys keys =
      client.create_session_keys(std::bit_width(N) - 1);
  TreeRingSwitchBundle ring = client.create_ring_switch_bundle(N / 2);

  // Malformed inputs are rejected before any arithmetic: an odd payload
  // offset, and switch keys whose small ring is not n / 2.
  {
    RlweCt dummy;
    dummy.c0.assign(N, 0);
    dummy.c1.assign(N, 0);
    require_test(throws_invalid_argument([&] {
                   (void)compress_path_response(dummy, {1}, 1, ring.keys,
                                                scheme);
                 }),
                 "accepted an odd payload offset");
    TreeRingSwitchKeys wrong_ring = ring.keys;
    wrong_ring.n2 = N / 4;
    require_test(throws_invalid_argument([&] {
                   (void)compress_path_response(dummy, {0}, 1, wrong_ring,
                                                scheme);
                 }),
                 "accepted switch keys for the wrong ring size");
  }

  // ---- Full pipeline over a real-hash shape and the scalar g = 1 shape ----
  const TreeNodeChunkSource hash_source = [&](size_t level, size_t index,
                                              size_t chunk) {
    return synthetic_tree_node_bytes_chunk(level, index, chunk, t);
  };
  const size_t width = std::bit_width(t) - 1;

  {
    const TreePirParams tree =
        make_tree_pir_params_for_scheme(tree_height_for(3, 5, 32), 3, 32, scheme);
    const PirParams qparams = tree_query_expansion_params(tree, scheme);
    PirServer server(qparams);
    server.set_client_session_keys(client.get_client_id(), keys);
    const PreprocessedTree db = preprocess_tree_mvp(tree, hash_source, scheme);

    for (size_t leaf : {size_t{0}, tree.N - 1,
                        static_cast<size_t>(0x2BADBEEFULL % tree.N)}) {
      RlweCt query = make_tree_query(client, scheme, tree, leaf);
      ExpandedTreeQuery unpacked = unpack_tree_query(
          server, scheme, tree, client.get_client_id(), query);
      CompressedPathResponse compressed = answer_path_compressed(
          db, unpacked, server, client.get_client_id(), tree, scheme,
          ring.keys);
      require_test(compressed.n2 == N / 2,
                   "compressed response lives in the half ring");
      if (leaf == 0) {
        // decode_compressed_path refuses a secret from another ring, a
        // response without its offset map, and an odd record stride.
        TreeRingSwitchSecret other_ring = ring.secret;
        other_ring.n2 = N / 4;
        require_test(throws_invalid_argument([&] {
                       (void)decode_compressed_path(compressed, other_ring,
                                                    t, tree.g, tree.rho);
                     }),
                     "decoded with a secret for another ring");
        CompressedPathResponse unmapped = compressed;
        unmapped.level_offsets.pop_back();
        require_test(throws_invalid_argument([&] {
                       (void)decode_compressed_path(unmapped, ring.secret,
                                                    t, tree.g, tree.rho);
                     }),
                     "decoded a response without its offset map");
        require_test(throws_invalid_argument([&] {
                       (void)decode_compressed_path(
                           compressed, ring.secret, t, tree.g, tree.rho + 1);
                     }),
                     "decoded with an odd record stride");
      }
      const std::vector<std::vector<uint64_t>> path = decode_compressed_path(
          compressed, ring.secret, t, tree.g, tree.rho);
      require_test(path.size() == tree.L + 1, "compressed path length");
      for (size_t level = 0; level <= tree.L; ++level) {
        const size_t node = leaf >> (tree.L - level);
        require_test(assemble_node(path[level], width) ==
                         synthetic_tree_node_bytes(level, node),
                     "compressed path must decode the exact 32-byte node");
      }

      // The compressed decode equals the uncompressed extraction.
      ExpandedTreeQuery second = unpack_tree_query(
          server, scheme, tree, client.get_client_id(), query);
      TreePathResponse plain = answer_path_mvp(
          db, second, server, client.get_client_id(), tree, scheme);
      require_test(extract_path_chunks_mvp(plain, client, tree) == path,
                   "compressed and plain responses must decode identically");
    }
    const size_t small_q_bits = std::bit_width(scheme.get_small_q() - 1);
    BENCH_PRINT("response bytes: plain "
                << 2 * N * small_q_bits / 8 << " -> compressed "
                << 2 * (N / 2) * small_q_bits / 8 << " (payload "
                << (tree.L + 1) * 32 << " B)");
  }

  // The even-aligned packer needs 2L < rho: with g = n/16 (rho = 16) and
  // L = 8 the offsets would reach 2L = 16 = rho, so the compressed path must
  // be refused before any homomorphic work (the MVP packer still serves it).
  {
    const TreePirParams tree =
        make_tree_pir_params_for_scheme(8, 1, N / 16, scheme);
    require_test(2 * tree.L >= tree.rho, "fixture must violate 2L < rho");
    const PirParams qparams = tree_query_expansion_params(tree, scheme);
    PirServer server(qparams);
    server.set_client_session_keys(client.get_client_id(), keys);
    const PreprocessedTree db = preprocess_tree_mvp(tree, hash_source, scheme);
    RlweCt query = make_tree_query(client, scheme, tree, tree.N - 1);
    ExpandedTreeQuery unpacked = unpack_tree_query(
        server, scheme, tree, client.get_client_id(), query);
    require_test(throws_invalid_argument([&] {
                   (void)answer_path_compressed(db, unpacked, server,
                                                client.get_client_id(), tree,
                                                scheme, ring.keys);
                 }),
                 "accepted an even-aligned packing with 2L >= rho");
    ExpandedTreeQuery again = unpack_tree_query(
        server, scheme, tree, client.get_client_id(), query);
    const TreePathResponse plain = answer_path_mvp(
        db, again, server, client.get_client_id(), tree, scheme);
    const auto path = extract_path_chunks_mvp(plain, client, tree);
    for (size_t level = 0; level <= tree.L; ++level) {
      const size_t node = (tree.N - 1) >> (tree.L - level);
      require_test(assemble_node(path[level], width) ==
                       synthetic_tree_node_bytes(level, node),
                   "MVP packer must still serve the shape compression rejects");
    }
  }

  // g = 1 scalar shape keeps working through the same pipeline.
  {
    const TreePirParams tree = make_tree_pir_params_for_scheme(tree_height_for(2, 0), 2, scheme);
    const PirParams qparams = tree_query_expansion_params(tree, scheme);
    PirServer server(qparams);
    server.set_client_session_keys(client.get_client_id(), keys);
    const TreeNodeSource source = [&](size_t level, size_t index) {
      return synthetic_tree_node_value(level, index, t);
    };
    const PreprocessedTree db = preprocess_tree_mvp(tree, source, scheme);
    const size_t leaf = tree.N - 1;
    RlweCt query = make_tree_query(client, scheme, tree, leaf);
    ExpandedTreeQuery unpacked = unpack_tree_query(
        server, scheme, tree, client.get_client_id(), query);
    CompressedPathResponse compressed = answer_path_compressed(
        db, unpacked, server, client.get_client_id(), tree, scheme,
        ring.keys);
    const std::vector<std::vector<uint64_t>> path = decode_compressed_path(
        compressed, ring.secret, t, tree.g, tree.rho);
    for (size_t level = 0; level <= tree.L; ++level) {
      require_test(path[level][0] ==
                       synthetic_tree_node_value(
                           level, leaf >> (tree.L - level), t),
                   "compressed scalar path value");
    }
  }
}
