#include "tests.h"
#include "cuckoo_batch.h"
#include "merkle_baseline.h"
#include "merkle_benchmark.h"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <limits>
#include <memory>
#include <numeric>
#include <optional>
#include <vector>

namespace {

// Flat root-excluded heap decode: ordinal -> (level, level-local index).
std::pair<size_t, size_t> node_of_ordinal(size_t ordinal) {
  const size_t heap = ordinal + 2;
  const size_t level = std::bit_width(heap) - 1;
  return {level, heap - (size_t{1} << level)};
}

// First feasible flat reference layout, as in the baseline suite.
PirParams flat_reference(size_t target_num_pt) {
  PirParams scheme;
  for (size_t height = 0; height <= 10; ++height) {
    try {
      return scheme.with_layout({target_num_pt, height, true});
    } catch (const std::runtime_error &) {
    }
  }
  throw std::runtime_error("no flat reference layout for this workload");
}

// The k sibling ordinals of one leaf (levels H..1), the same work unit the
// flat and layerwise baselines retrieve.
std::vector<uint32_t> sibling_ordinals(size_t leaf, size_t tree_height) {
  std::vector<uint32_t> ordinals;
  ordinals.reserve(tree_height);
  for (size_t level = tree_height; level >= 1; --level) {
    const size_t local = merkle_sibling_local(leaf, tree_height, level);
    ordinals.push_back(
        static_cast<uint32_t>(merkle_flat_ordinal(level, local)));
    if (level == 1) break;
  }
  return ordinals;
}

// Plaintext source packing one bucket's sorted members with synthetic nodes.
PlaintextSource bucket_source(const CuckooBucket &bucket,
                              const PirParams &params) {
  return [&bucket, &params](size_t index, RlwePt &out) {
    const size_t first = index * 96;
    const size_t count =
        std::min(size_t{96}, bucket.members.size() - first);
    std::vector<MerkleNode> nodes;
    nodes.reserve(count);
    for (size_t offset = 0; offset < count; ++offset) {
      const auto [level, local] =
          node_of_ordinal(bucket.members[first + offset]);
      nodes.push_back(synthetic_merkle_node(level, local));
    }
    out = encode_merkle_nodes(nodes, params);
  };
}

template <typename Fn>
bool throws_invalid_argument(Fn &&fn) {
  try {
    fn();
  } catch (const std::invalid_argument &) {
    return true;
  }
  return false;
}

// Every ordinal placed exactly once, in one of its candidate buckets.
void require_valid_placement(
    const std::vector<std::optional<uint32_t>> &assignment,
    const std::vector<uint32_t> &ordinals, const CuckooBatchParams &params) {
  require_test(assignment.size() == params.num_buckets, "assignment size");
  std::vector<uint32_t> placed;
  for (size_t b = 0; b < assignment.size(); ++b) {
    if (!assignment[b].has_value()) continue;
    placed.push_back(*assignment[b]);
    bool candidate = false;
    for (size_t j = 0; j < params.num_hashes; ++j) {
      candidate |= cuckoo_bucket_of(*assignment[b], j, params) == b;
    }
    require_test(candidate, "assignment respects the candidate buckets");
  }
  std::vector<uint32_t> expected = ordinals;
  std::sort(placed.begin(), placed.end());
  std::sort(expected.begin(), expected.end());
  require_test(placed == expected, "every batch item is placed exactly once");
}

}  // namespace

// Correctness gate at H = 13: bucket membership, deterministic cuckoo
// placement, and a full encrypted batch round recovering every sibling.
void PirTest::test_cuckoo_batch() {
  print_func_name(__FUNCTION__);
  const size_t tree_height = 13;
  const size_t leaf_count = size_t{1} << tree_height;
  const size_t item_count = 2 * (leaf_count - 1);
  const CuckooBatchParams params =
      make_cuckoo_batch_params(item_count, tree_height, 0x63756b31ULL);
  require_test(params.num_buckets == (3 * tree_height + 1) / 2,
               "1.5x bucket sizing");

  const PirParams reference =
      flat_reference(utils::roundup_div(item_count, size_t{96}));
  std::vector<CuckooBucket> buckets =
      build_cuckoo_buckets(params, reference);

  // Membership: every sampled ordinal is present in each hashed bucket, and
  // positions are consistent with the sorted member lists.
  for (uint32_t ordinal = 0; ordinal < item_count;
       ordinal += 977) {
    for (size_t j = 0; j < params.num_hashes; ++j) {
      const CuckooBucket &bucket =
          buckets[cuckoo_bucket_of(ordinal, j, params)];
      const size_t position = cuckoo_position(bucket, ordinal);
      require_test(bucket.members[position] == ordinal,
                   "position rank addresses the ordinal");
    }
  }

  PirClient client(reference);
  SharedPirSessionKeys keys = client.create_session_keys();
  std::vector<std::unique_ptr<PirServer>> servers;
  servers.reserve(buckets.size());
  for (const CuckooBucket &bucket : buckets) {
    auto server = std::make_unique<PirServer>(bucket.params);
    server->set_client_session_keys(client.get_client_id(), keys);
    server->load_data(bucket.target_num_pt,
                      bucket_source(bucket, bucket.params));
    servers.push_back(std::move(server));
  }

  for (size_t leaf : {size_t{0}, leaf_count / 2 + 3, leaf_count - 1}) {
    const std::vector<uint32_t> ordinals =
        sibling_ordinals(leaf, tree_height);
    const auto assignment = cuckoo_place(ordinals, params);

    require_valid_placement(assignment, ordinals, params);

    // One PIR round per bucket; unassigned buckets ask a dummy index.
    for (size_t b = 0; b < buckets.size(); ++b) {
      const size_t position =
          assignment[b].has_value()
              ? cuckoo_position(buckets[b], *assignment[b])
              : 0;
      RlweCt query = client.fast_generate_query(buckets[b].params,
                                                position / 96);
      RlweCt response = servers[b]->make_query(client.get_client_id(), query);
      std::stringstream wire;
      (void)servers[b]->save_resp_to_stream(response, wire);
      RlweCt loaded = client.load_resp_from_stream(wire);
      const RlwePt pt = client.decrypt_mod_q(loaded);
      if (assignment[b].has_value()) {
        const auto [level, local] = node_of_ordinal(*assignment[b]);
        require_test(decode_merkle_node(pt, position % 96,
                                        buckets[b].params) ==
                         synthetic_merkle_node(level, local),
                     "batched sibling must decode exactly");
      }
    }
  }

  // Parameter and placement validation.
  require_test(throws_invalid_argument([&] {
                 (void)make_cuckoo_batch_params(0, tree_height, 1);
               }),
               "accepted an empty database");
  require_test(throws_invalid_argument([&] {
                 (void)make_cuckoo_batch_params(item_count, 0, 1);
               }),
               "accepted an empty batch");
  require_test(throws_invalid_argument([&] {
                 (void)make_cuckoo_batch_params(
                     size_t{std::numeric_limits<uint32_t>::max()} + 1,
                     tree_height, 1);
               }),
               "accepted ordinals beyond uint32");
  require_test(make_cuckoo_batch_params(item_count, 1, 1).num_buckets == 2,
               "k = 1 still gets two buckets");
  require_test(throws_invalid_argument([&] {
                 (void)cuckoo_bucket_of(0, params.num_hashes, params);
               }),
               "accepted a hash index beyond num_hashes");
  {
    // An ordinal that hashes nowhere near bucket 0 is not positioned there.
    uint32_t outsider = 0;
    for (;; ++outsider) {
      bool hits = false;
      for (size_t j = 0; j < params.num_hashes; ++j) {
        hits |= cuckoo_bucket_of(outsider, j, params) == 0;
      }
      if (!hits) break;
    }
    require_test(throws_invalid_argument(
                     [&] { (void)cuckoo_position(buckets[0], outsider); }),
                 "positioned an ordinal outside its bucket");
  }
  {
    std::vector<uint32_t> duplicated = sibling_ordinals(0, tree_height);
    duplicated[1] = duplicated[0];
    require_test(throws_invalid_argument(
                     [&] { (void)cuckoo_place(duplicated, params); }),
                 "placed a batch with a repeated ordinal");
    std::vector<uint32_t> short_batch = sibling_ordinals(0, tree_height);
    short_batch.pop_back();
    require_test(throws_invalid_argument(
                     [&] { (void)cuckoo_place(short_batch, params); }),
                 "placed a batch of the wrong size");
  }

  // Placement is not tied to k = H or to one seed: a different seed, a
  // smaller batch and a batch larger than the tree height all place.
  {
    const CuckooBatchParams reseeded =
        make_cuckoo_batch_params(item_count, tree_height, 0x6f746865ULL);
    const std::vector<uint32_t> ordinals = sibling_ordinals(4099, tree_height);
    require_valid_placement(cuckoo_place(ordinals, reseeded), ordinals,
                            reseeded);

    const CuckooBatchParams small_batch =
        make_cuckoo_batch_params(item_count, 5, 0x63756b31ULL);
    const std::vector<uint32_t> five(ordinals.begin(), ordinals.begin() + 5);
    require_valid_placement(cuckoo_place(five, small_batch), five,
                            small_batch);
  }
  {
    // 20 distinct ordinals: the sibling sets of the first and the last leaf
    // are disjoint (right children versus left children at every level).
    std::vector<uint32_t> twenty = sibling_ordinals(0, tree_height);
    const std::vector<uint32_t> tail =
        sibling_ordinals(leaf_count - 1, tree_height);
    twenty.insert(twenty.end(), tail.begin(), tail.begin() + 7);
    require_test(twenty.size() == 20, "fixture batch size");
    const CuckooBatchParams large_batch =
        make_cuckoo_batch_params(item_count, 20, 0x63756b31ULL);
    require_test(large_batch.num_buckets == 30, "1.5x sizing at k = 20");
    const std::vector<CuckooBucket> large_buckets =
        build_cuckoo_buckets(large_batch, reference);
    const auto assignment = cuckoo_place(twenty, large_batch);
    require_valid_placement(assignment, twenty, large_batch);
    // Encrypted round over the 30 buckets: every placed ordinal decodes.
    std::vector<std::unique_ptr<PirServer>> large_servers;
    for (const CuckooBucket &bucket : large_buckets) {
      auto server = std::make_unique<PirServer>(bucket.params);
      server->set_client_session_keys(client.get_client_id(), keys);
      server->load_data(bucket.target_num_pt,
                        bucket_source(bucket, bucket.params));
      large_servers.push_back(std::move(server));
    }
    size_t recovered = 0;
    for (size_t b = 0; b < large_buckets.size(); ++b) {
      if (!assignment[b].has_value()) continue;
      const size_t position =
          cuckoo_position(large_buckets[b], *assignment[b]);
      RlweCt query = client.fast_generate_query(large_buckets[b].params,
                                                position / 96);
      RlweCt response =
          large_servers[b]->make_query(client.get_client_id(), query);
      const RlwePt pt = client.decrypt_mod_q(response);
      const auto [level, local] = node_of_ordinal(*assignment[b]);
      require_test(decode_merkle_node(pt, position % 96,
                                      large_buckets[b].params) ==
                       synthetic_merkle_node(level, local),
                   "k = 20 batched node must decode exactly");
      ++recovered;
    }
    require_test(recovered == 20, "every item of the k = 20 batch recovered");
  }
}

// Timed batch retrieval at the comparison workload: L = 22, 32-byte nodes,
// 16 measured trials after 3 warmups, one full 22-sibling batch per trial.
void PirTest::test_cuckoo_benchmark() {
  print_func_name(__FUNCTION__);
  using Clock = std::chrono::steady_clock;
  const auto ms_since = [](Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start)
        .count();
  };

  const size_t tree_height = 22;
  const size_t leaf_count = size_t{1} << tree_height;
  const size_t item_count = 2 * (leaf_count - 1);
  const CuckooBatchParams params =
      make_cuckoo_batch_params(item_count, tree_height, 0x63756b32ULL);
  const PirParams reference =
      flat_reference(utils::roundup_div(item_count, size_t{96}));

  const auto setup_start = Clock::now();
  std::vector<CuckooBucket> buckets =
      build_cuckoo_buckets(params, reference);
  PirClient client(reference);
  SharedPirSessionKeys keys = client.create_session_keys();
  std::vector<std::unique_ptr<PirServer>> servers;
  servers.reserve(buckets.size());
  size_t total_pt = 0, max_bucket = 0;
  for (const CuckooBucket &bucket : buckets) {
    auto server = std::make_unique<PirServer>(bucket.params);
    server->set_client_session_keys(client.get_client_id(), keys);
    server->load_data(bucket.target_num_pt,
                      bucket_source(bucket, bucket.params));
    total_pt += bucket.target_num_pt;
    max_bucket = std::max(max_bucket, bucket.members.size());
    servers.push_back(std::move(server));
  }
  const double setup_ms = ms_since(setup_start);

  constexpr size_t kWarmups = 3;
  constexpr size_t kTrials = 16;
  const BenchmarkTrialPlan plan = make_benchmark_trial_plan(
      leaf_count, kWarmups, kTrials, 0x63756b6f6f504952ULL);

  std::vector<double> client_ms, server_ms, decode_ms;
  size_t response_bytes_total = 0;
  // Server phase breakdown from the TimerLogger sections make_query brackets,
  // summed over every bucket query of one trial (one experiment per trial).
  constexpr std::array<const char *, 5> kPhaseKeys = {
      EXPAND_TIME, CONVERT_TIME, FST_DIM_TIME, OTHER_DIM_TIME, MOD_SWITCH};
  constexpr std::array<const char *, 5> kPhaseLabels = {
      "expand", "convert", "first_dim", "other_dim", "mod_switch"};
  std::array<double, 5> phase_sum{};
  CLEAN_TIMER();
  const auto run_trial = [&](size_t leaf, bool measured) {
    const std::vector<uint32_t> ordinals =
        sibling_ordinals(leaf, tree_height);
    const auto assignment = cuckoo_place(ordinals, params);
    double c_ms = 0, s_ms = 0, d_ms = 0;
    size_t resp_bytes = 0;
    size_t recovered = 0;
    for (size_t b = 0; b < buckets.size(); ++b) {
      const size_t position =
          assignment[b].has_value()
              ? cuckoo_position(buckets[b], *assignment[b])
              : 0;
      auto start = Clock::now();
      RlweCt query = client.fast_generate_query(buckets[b].params,
                                                position / 96);
      c_ms += ms_since(start);

      start = Clock::now();
      RlweCt response = servers[b]->make_query(client.get_client_id(), query);
      s_ms += ms_since(start);

      std::stringstream wire;
      resp_bytes += servers[b]->save_resp_to_stream(response, wire);
      start = Clock::now();
      RlweCt loaded = client.load_resp_from_stream(wire);
      const RlwePt pt = client.decrypt_mod_q(loaded);
      d_ms += ms_since(start);
      if (assignment[b].has_value()) {
        const auto [level, local] = node_of_ordinal(*assignment[b]);
        require_test(decode_merkle_node(pt, position % 96,
                                        buckets[b].params) ==
                         synthetic_merkle_node(level, local),
                     "benchmark batch sibling mismatch");
        ++recovered;
      }
    }
    END_EXPERIMENT();
    if (measured) {
      for (size_t i = 0; i < kPhaseKeys.size(); ++i) {
        phase_sum[i] += GET_LAST_TIME(kPhaseKeys[i]);
      }
    }
    require_test(recovered == tree_height,
                 "every sibling recovered in the batch");
    if (measured) {
      client_ms.push_back(c_ms);
      server_ms.push_back(s_ms);
      decode_ms.push_back(d_ms);
      response_bytes_total = resp_bytes;
    }
  };

  for (size_t leaf : plan.warmup_leaf_indices) run_trial(leaf, false);
  for (size_t leaf : plan.measured_leaf_indices) run_trial(leaf, true);

  const auto avg = [](const std::vector<double> &v) {
    return std::accumulate(v.begin(), v.end(), 0.0) / v.size();
  };
  const size_t query_bytes =
      params.num_buckets * reference.get_BFV_size(true);

  BENCH_PRINT("cuckoo batch PIR: L=" << tree_height << ", k=" << tree_height
              << ", buckets=" << params.num_buckets << " (3 hashes, 1.5x)");
  BENCH_PRINT("database: " << total_pt << " packed plaintexts across buckets"
              " (3x replication, " << (total_pt * 3072) / (1 << 20)
              << " MiB logical), largest bucket " << max_bucket
              << " nodes, setup " << setup_ms << " ms");
  BENCH_PRINT("trials: " << kTrials << " measured after " << kWarmups
              << " warmup");
  BENCH_PRINT("client query avg " << avg(client_ms) << " ms");
  BENCH_PRINT("server batch avg " << avg(server_ms)
              << " ms; samples:");
  for (double v : server_ms) BENCH_PRINT("  batch " << v << " ms");
  {
    std::string breakdown = "server phase breakdown avg (ms, sum over buckets):";
    double phase_total = 0;
    for (size_t i = 0; i < kPhaseKeys.size(); ++i) {
      const double v = phase_sum[i] / server_ms.size();
      phase_total += v;
      breakdown += std::string(" ") + kPhaseLabels[i] + " " +
                   std::to_string(v);
    }
    BENCH_PRINT(breakdown);
    BENCH_PRINT("  phases sum " << phase_total << " ms of server batch avg "
                << avg(server_ms) << " ms");
  }
  BENCH_PRINT("client decode avg " << avg(decode_ms) << " ms");
  BENCH_PRINT("communication: queries " << query_bytes << " B (modeled, "
              << params.num_buckets << " ciphertexts), responses "
              << response_bytes_total << " B (actual wire codec), online "
              << query_bytes + response_bytes_total
              << " B; helper keys shared bundle "
              << modeled_helper_key_bytes(reference) << " B (modeled)");
  BENCH_PRINT("payload: " << tree_height << " x 32-byte siblings = "
              << tree_height * 32 << " B useful; position metadata public");
}
