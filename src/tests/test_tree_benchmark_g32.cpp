#include "tests.h"
#include "merkle_benchmark.h"
#include "tree_index.h"
#include "tree_query.h"
#include "tree_response.h"
#include "tree_select.h"

#include <array>
#include <bit>
#include <chrono>
#include <numeric>
#include <utility>
#include <vector>

// Real-scenario efficiency: g = 32 (full 32-byte nodes) at N = 2^22 leaves,
// the largest workload whose canonical + NTT views fit this machine's
// memory budget (~4.3 GiB; the 2^24 row needs ~17 GiB and is reported by
// linear first-dimension extrapolation instead). Same scheme and statistics
// conventions as the baselines; the payload per node now matches theirs
// exactly (32 bytes), stored as 32 x 12-bit chunks (384-bit slots, the
// power-of-two rounding of 256 bits).
void PirTest::test_tree_benchmark_g32() {
  print_func_name(__FUNCTION__);
  constexpr size_t N = DBConsts::PolyDegree;
  using Clock = std::chrono::steady_clock;
  const auto ms_since = [](Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start)
        .count();
  };

  PirParams scheme;
  const uint64_t t = scheme.get_plain_mod();
  // Real-hash slot count for this scheme: 256 bits over (log2(t) - 1)-bit
  // chunks, rounded to a power of two (n=2048/12-bit -> g=32;
  // n=4096/39-bit -> g=8).
  const size_t chunk_bits = std::bit_width(t) - 1;
  const size_t g = std::bit_ceil((size_t{255} / chunk_bits) + 1);
  // Fold-halving experiment result (k1_comp, 2^22): pushing h_q to 11 via
  // key-height 11 admits a = 10, but the doubled expansion (+72 ms) and the
  // doubled pyramid eat the fold savings (path only -26 ms) while the 1024-
  // term first-dimension sum lifts max noise to 294 > 256 — over the small-q
  // bound on unused coefficients. The scan therefore stays inside the
  // scheme's default expansion height, which is the noise-safe envelope.
  const size_t key_height = scheme.get_expan_height();
  size_t chosen_a = 2;
  for (size_t a = 20; a >= 2; --a) {
    try {
      (void)make_tree_pir_params_for_scheme(22, a, g, scheme, key_height);
      chosen_a = a;
      break;
    } catch (const std::invalid_argument &) {
      // Shape infeasible; try a smaller first dimension.
    }
  }
  const TreePirParams tree =
      make_tree_pir_params_for_scheme(22, chosen_a, g, scheme, key_height);
  const TreeNodeChunkSource source = [&](size_t level, size_t index,
                                         size_t chunk) {
    return synthetic_tree_node_bytes_chunk(level, index, chunk, t);
  };

  PirClient client(scheme);
  SharedPirSessionKeys keys =
      client.create_session_keys(std::bit_width(N) - 1);
  const PirParams qparams = tree_query_expansion_params(tree, scheme);
  PirServer server(qparams);
  server.set_client_session_keys(client.get_client_id(), keys);

  const auto setup_start = Clock::now();
  const PreprocessedTree db = preprocess_tree_mvp(tree, source, scheme);
  const double setup_ms = ms_since(setup_start);
  size_t total_pt = 0;
  for (const auto &level_db : db.canonical) {
    total_pt += level_db.plaintexts.size();
  }

  constexpr size_t kWarmups = 3;
  constexpr size_t kTrials = 16;
  const BenchmarkTrialPlan plan = make_benchmark_trial_plan(
      tree.N, kWarmups, kTrials, 0x747265654733325fULL);

  std::vector<double> query_ms, unpack_ms, path_ms, extract_ms;
  size_t actual_response_bytes = 0;
  const auto run_trial = [&](size_t leaf, bool measured) {
    auto start = Clock::now();
    RlweCt query = make_tree_query(client, scheme, tree, leaf);
    const double q_ms = ms_since(start);

    start = Clock::now();
    ExpandedTreeQuery unpacked = unpack_tree_query(
        server, scheme, tree, client.get_client_id(), query);
    const double u_ms = ms_since(start);

    start = Clock::now();
    TreePathResponse response =
        answer_path_mvp(db, unpacked, server, client.get_client_id(), tree,
                        scheme);
    const double p_ms = ms_since(start);

    start = Clock::now();
    const std::vector<std::vector<uint64_t>> path =
        extract_path_chunks_mvp(response, client, tree);
    const double e_ms = ms_since(start);

    require_test(path.size() == tree.L + 1, "benchmark path length");
    for (size_t level = 0; level <= tree.L; ++level) {
      const size_t node = leaf >> (tree.L - level);
      // Full 32-byte comparison chunk by chunk, outside every timer.
      for (size_t j = 0; j < tree.g; ++j) {
        require_test(path[level][j] == source(level, node, j),
                     "benchmark path chunk mismatch");
      }
    }
    if (measured) {
      query_ms.push_back(q_ms);
      unpack_ms.push_back(u_ms);
      path_ms.push_back(p_ms);
      extract_ms.push_back(e_ms);
      std::stringstream wire;
      actual_response_bytes =
          server.save_resp_to_stream(response.chunks[0], wire);
    }
  };

  for (size_t leaf : plan.warmup_leaf_indices) run_trial(leaf, false);
  for (size_t leaf : plan.measured_leaf_indices) run_trial(leaf, true);

  const auto avg = [](const std::vector<double> &v) {
    return std::accumulate(v.begin(), v.end(), 0.0) / v.size();
  };
  const size_t query_bytes = scheme.get_BFV_size(true);
  const size_t helper_bytes =
      scheme.with_query_shape({1, 0, std::bit_width(N) - 1})
          .get_bv_galois_key_size(true) +
      scheme.get_gsw_key_size(true);

  BENCH_PRINT("tree MVP real-hash benchmark: N=2^22 leaves, L=22, g="
              << tree.g << " (" << chunk_bits << "-bit chunks), N0="
              << tree.N0 << ", b=" << tree.b << ", rho=" << tree.rho
              << ", r=" << tree.r << ", w=" << tree.w << ", W=" << tree.W
              << ", h_q=" << tree.h_q);
  BENCH_PRINT("database: " << total_pt << " packed plaintexts, 32-byte nodes"
              " (" << (total_pt * scheme.get_pt_size()) / (1 << 20)
              << " MiB logical payload), setup " << setup_ms << " ms");
  BENCH_PRINT("trials: " << kTrials << " measured after " << kWarmups
              << " warmup");
  BENCH_PRINT("client query avg " << avg(query_ms) << " ms");
  BENCH_PRINT("server unpack (expand+convert) avg " << avg(unpack_ms)
              << " ms");
  BENCH_PRINT("server path (select+rotate+project+pack) avg "
              << avg(path_ms) << " ms");
  BENCH_PRINT("server total avg " << avg(unpack_ms) + avg(path_ms)
              << " ms; samples(path):");
  for (double v : path_ms) BENCH_PRINT("  path " << v << " ms");
  BENCH_PRINT("client extract avg " << avg(extract_ms) << " ms");
  BENCH_PRINT("communication: query " << query_bytes
              << " B (modeled, 1 ciphertext), response "
              << actual_response_bytes
              << " B (actual wire codec), helper keys " << helper_bytes
              << " B (modeled)");
  BENCH_PRINT("payload: " << (tree.L + 1) << " x 32-byte path nodes = "
              << (tree.L + 1) * 32 << " B useful");
}
