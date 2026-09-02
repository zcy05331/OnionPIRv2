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

// Timed MVP path retrieval at the Merkle-baseline workload scale: N = 2^24
// leaves (H = L = 24), CONFIG_N2048_K1_COMP scheme — the same tree shape and
// cryptographic parameters as the 1 GB baseline row. Differences to state
// with every comparison: g = 1, so each node carries one Z_t scalar instead
// of the baselines' 32-byte value (payload extension is blueprint sec. 23.1),
// while the whole path returns in ONE small-q ciphertext (Milestone 5)
// computed over the NTT-view first dimension (Milestone 6).
void PirTest::test_tree_benchmark() {
  print_func_name(__FUNCTION__);
  constexpr size_t N = DBConsts::PolyDegree;
  using Clock = std::chrono::steady_clock;
  const auto ms_since = [](Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start)
        .count();
  };

  PirParams scheme;
  // a = 7 keeps h_q = 8 within the scheme expansion height while bounding the
  // beta fold work; L = 24 matches the baselines' 2^24-leaf tree.
  const TreePirParams tree = make_tree_pir_params_for_scheme(24, 7, scheme);
  const uint64_t t = scheme.get_plain_mod();
  const TreeNodeSource source = [&](size_t level, size_t index) {
    return synthetic_tree_node_value(level, index, t);
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

  // Distinct deterministic query leaves, same sampler as the baselines.
  constexpr size_t kWarmups = 1;
  constexpr size_t kTrials = 5;
  const BenchmarkTrialPlan plan = make_benchmark_trial_plan(
      tree.N, kWarmups, kTrials, 0x74726565426e6368ULL);

  std::vector<double> query_ms, unpack_ms, path_ms, extract_ms;
  size_t actual_response_bytes = 0;
  bool response_small_q = false;
  // Server-path stage breakdown via the TimerLogger sections that
  // answer_path_mvp and the select kernels bracket (one experiment per trial).
  constexpr std::array<const char *, 7> kStages = {
      TREE_PYRAMID_TIME, TREE_SCAN_TIME,    TREE_FOLD_TIME, TREE_ROTATE_TIME,
      TREE_PROJECT_TIME, TREE_PACK_TIME,    TREE_SWITCH_TIME};
  constexpr std::array<const char *, 7> kStageLabels = {
      "pyramid", "scan", "fold", "rotate", "project", "pack", "switch"};
  std::array<double, 7> stage_sum{};
  CLEAN_TIMER();
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
    const std::vector<uint64_t> path =
        extract_path_mvp(response, client, tree);
    const double e_ms = ms_since(start);
    END_EXPERIMENT();
    if (measured) {
      for (size_t i = 0; i < kStages.size(); ++i) {
        stage_sum[i] += GET_LAST_TIME(kStages[i]);
      }
    }

    // Correctness gate outside every timer boundary consumer: hard-fail on
    // any wrong path value.
    require_test(path.size() == tree.L + 1, "benchmark path length");
    for (size_t level = 0; level <= tree.L; ++level) {
      require_test(path[level] ==
                       source(level, leaf >> (tree.L - level)),
                   "benchmark path value mismatch");
    }
    if (measured) {
      query_ms.push_back(q_ms);
      unpack_ms.push_back(u_ms);
      path_ms.push_back(p_ms);
      extract_ms.push_back(e_ms);
      response_small_q = response.small_q;
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
  const double server_avg = avg(unpack_ms) + avg(path_ms);

  // Communication accounting, same conventions as the baseline suite: query
  // and helper keys are seed-compressed models; the response byte count is
  // read from the real small-q wire codec.
  const size_t query_bytes = scheme.get_BFV_size(true);
  const size_t helper_bytes =
      scheme.with_query_shape({1, 0, std::bit_width(N) - 1})
          .get_bv_galois_key_size(true) +
      scheme.get_gsw_key_size(true);

  BENCH_PRINT("tree MVP benchmark: N=2^24 leaves, L=24, N0=" << tree.N0
              << ", b=" << tree.b << ", w=" << tree.w << ", W=" << tree.W);
  BENCH_PRINT("database: " << total_pt << " packed plaintexts, g=1 payload "
              << (total_pt * N * 8) / (1 << 20) << " MiB coefficient storage,"
              " setup " << setup_ms << " ms");
  BENCH_PRINT("trials: " << kTrials << " measured after " << kWarmups
              << " warmup, leaves "
              << plan.measured_leaf_indices.size() << " distinct");
  BENCH_PRINT("client query avg " << avg(query_ms) << " ms");
  BENCH_PRINT("server unpack (expand+convert) avg " << avg(unpack_ms)
              << " ms");
  BENCH_PRINT("server path (select+rotate+project+pack) avg "
              << avg(path_ms) << " ms");
  BENCH_PRINT("server total avg " << server_avg << " ms; samples(path):");
  for (double v : path_ms) BENCH_PRINT("  path " << v << " ms");
  {
    std::string breakdown = "server path breakdown avg (ms):";
    double stage_total = 0;
    for (size_t i = 0; i < kStages.size(); ++i) {
      const double v = stage_sum[i] / path_ms.size();
      stage_total += v;
      breakdown += std::string(" ") + kStageLabels[i] + " " +
                   std::to_string(v);
    }
    BENCH_PRINT(breakdown);
    BENCH_PRINT("  stages sum " << stage_total << " ms of path avg "
                << avg(path_ms) << " ms (remainder = glue/alloc)");
  }
  BENCH_PRINT("client extract avg " << avg(extract_ms) << " ms");
  BENCH_PRINT("communication: query " << query_bytes
              << " B (modeled, 1 ciphertext), response "
              << actual_response_bytes << " B (actual wire codec, small_q="
              << (response_small_q ? "yes" : "no") << "), helper keys "
              << helper_bytes << " B (modeled, "
              << (std::bit_width(N) - 1) << " BV + GSW)");
}
