#include "tests.h"

#include <memory>
#include "merkle_baseline.h"
#include "merkle_benchmark.h"

#include <array>
#include <filesystem>
#include <vector>

namespace {

// Expected authentication path from the 1-based heap index alone (root = 1,
// children 2i and 2i + 1), independent of the merkle_baseline index helpers
// the runners use to build their databases.
void require_expected_path(const MerklePath &path, size_t leaf,
                           size_t tree_height) {
  // Runners return leaf-to-root order (levels H..1), matching client use.
  require_test(path.size() == tree_height, "Merkle path length");
  size_t node = leaf + (size_t{1} << tree_height);
  for (size_t offset = 0; offset < tree_height; ++offset) {
    const size_t level = tree_height - offset;
    const size_t local = (node ^ 1U) - (size_t{1} << level);
    require_test(path[offset] == synthetic_merkle_node(level, local),
                 "Merkle path node mismatch");
    node >>= 1;
  }
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

}  // namespace

void PirTest::test_merkle_integration() {
  // H=8 cheaply covers first, last, and interior leaves through codec, query,
  // server evaluation, response wire round-trip, and decryption.
  const MerkleWorkload small{size_t{1} << 8, 8, 32};
  const size_t small_target = utils::roundup_div(
      2 * (small.leaf_count - 1), size_t{96});
  PirParams small_reference =
      PirParams().with_layout({small_target, 3, true});
  const BenchmarkTrialPlan small_trials{
      {}, {0, small.leaf_count - 1, small.leaf_count / 2}};

  BenchmarkCaseExecution standard =
      run_standard_case(small, small_reference, small_trials);
  require_test(standard.result.correctness_passed,
               "standard deterministic case");
  require_test(standard.result.communication.pir_call_count == 1,
               "standard call count");
  require_test(!standard.result.pipeline_profile_ms.empty() &&
                   !standard.result.server_phase_ms.empty(),
               "standard case records its stage timings");

  BenchmarkCaseExecution flat =
      run_merkle_flat_case(small, small_reference, small_trials);
  BenchmarkCaseExecution layerwise =
      run_merkle_layerwise_case(small, small_reference, small_trials);
  require_test(flat.result.correctness_passed, "H=8 flat correctness");
  require_test(layerwise.result.correctness_passed,
               "H=8 layerwise correctness");
  require_test(flat.measured_paths == layerwise.measured_paths,
               "H=8 flat/layerwise path mismatch");
  require_test(flat.measured_paths.size() ==
                   small_trials.measured_leaf_indices.size(),
               "H=8 measured path count");
  for (size_t i = 0; i < flat.measured_paths.size(); ++i) {
    require_expected_path(flat.measured_paths[i],
                          small_trials.measured_leaf_indices[i],
                          small.tree_height);
  }
  // The flat case serves H calls on the same layout as the single standard
  // call, so its actual response bytes are exactly H times the standard's.
  require_test(flat.result.communication.pir_call_count == 8 &&
                   flat.result.communication.online_response_bytes_actual ==
                       8 * standard.result.communication
                               .online_response_bytes_actual,
               "flat response bytes are H standard responses");
  // Levels 1..6 (2..64 nodes) fit one 96-node plaintext and are returned in
  // the clear; levels 7 and 8 stay PIR calls.
  require_test(layerwise.result.direct_return_levels == 6,
               "H=8 direct-return level count");
  require_test(layerwise.result.communication.pir_call_count == 2,
               "H=8 layerwise PIR call count");
  require_test(layerwise.result.direct_return_response_bytes ==
                   (2 + 4 + 8 + 16 + 32 + 64) * 32,
               "H=8 direct-return plain bytes");
  validate_layerwise_path_communication(
      flat.result.communication, layerwise.result.communication,
      layerwise.result.direct_return_levels,
      layerwise.result.direct_return_response_bytes);

  // A tree whose every level fits one plaintext (H <= 6) would make no PIR
  // call at all; the layerwise case rejects it instead of reporting a
  // communication model with zero calls.
  {
    const MerkleWorkload tiny{size_t{1} << 6, 6, 32};
    const PirParams tiny_reference = PirParams().with_layout({2, 1, true});
    require_test(throws_invalid_argument([&] {
                   (void)run_merkle_layerwise_case(tiny, tiny_reference,
                                                   BenchmarkTrialPlan{{}, {5}});
                 }),
                 "accepted a layerwise tree with no PIR level");
  }

  // Profiled planner end to end at H=8: sweep the PIR levels on this machine,
  // then the profiled layerwise case must recover the same paths as the
  // legacy plan with identical communication accounting.
  std::shared_ptr<LayerLayoutProfile> profile8;
  {
    LayerLayoutSweepOptions sweep;
    sweep.leaf_count = small.leaf_count;
    sweep.warmups = 1;
    sweep.measured_trials = 2;
    sweep.trial_seed = 7;
    profile8 =
        std::make_shared<LayerLayoutProfile>(run_layer_layout_sweep(sweep));
    require_test(profile8->tree_height == 8 &&
                     profile8->selected_expansion_heights.size() == 8,
                 "H=8 sweep profile shape");
    require_test(!profile8->measurements.empty(),
                 "H=8 sweep measured the PIR levels");
    for (const LayerLayoutMeasurement &m : profile8->measurements) {
      require_test(m.level >= 7, "H=8 sweep skips direct-return levels");
      require_test(m.server_samples_ms.size() == 2,
                   "H=8 sweep keeps one sample per measured trial");
    }
    const PirParams sweep_reference = make_benchmark_reference(small);
    LayerPlannerConfig config;
    config.policy = LayerLayoutPolicy::profiled;
    config.profile = profile8;
    BenchmarkCaseExecution legacy_ref =
        run_merkle_layerwise_case(small, sweep_reference, small_trials);
    BenchmarkCaseExecution profiled = run_merkle_layerwise_case(
        small, sweep_reference, small_trials, config);
    require_test(profiled.result.correctness_passed,
                 "H=8 profiled layerwise correctness");
    require_test(profiled.measured_paths == legacy_ref.measured_paths,
                 "H=8 profiled/legacy path mismatch");
    validate_matching_path_communication(legacy_ref.result.communication,
                                         profiled.result.communication);
    require_test(profiled.result.layer_layout_policy == "profiled" &&
                     legacy_ref.result.layer_layout_policy == "legacy",
                 "layout policy recorded in the case result");
    require_test(profiled.result.layers.size() == 8 &&
                     profiled.result.layers[0].direct_return &&
                     !profiled.result.layers[7].direct_return,
                 "per-level layout records");
    require_test(!profiled.result.pipeline_profile_ms.empty() &&
                     profiled.result.pipeline_profile_ms.at("first_dim_core") >
                         0.0,
                 "pipeline profile recorded for the layerwise case");
    // The case runner honours the fallback flag on a mismatched profile and
    // rejects it without the flag.
    auto mismatched = std::make_shared<LayerLayoutProfile>(*profile8);
    mismatched->tree_height = 9;
    LayerPlannerConfig bad = config;
    bad.profile = mismatched;
    require_test(throws_invalid_argument([&] {
                   (void)run_merkle_layerwise_case(small, sweep_reference,
                                                   small_trials, bad);
                 }),
                 "case runner accepted a mismatched profile");
    bad.allow_profile_fallback = true;
    BenchmarkCaseExecution fallback = run_merkle_layerwise_case(
        small, sweep_reference, small_trials, bad);
    require_test(fallback.result.layer_layout_policy == "legacy" &&
                     fallback.measured_paths == legacy_ref.measured_paths,
                 "case runner fallback must produce the legacy plan");
  }

  // H=16 forces remaining-dimension RGSW MUX work; a small-only fixture could
  // otherwise pass while testing only the first-dimension path.
  const MerkleWorkload multidimensional{size_t{1} << 16, 16, 32};
  const size_t multidimensional_target = utils::roundup_div(
      2 * (multidimensional.leaf_count - 1), size_t{96});
  PirParams multidimensional_reference =
      PirParams().with_layout({multidimensional_target, 8, true});
  require_test(multidimensional_target > 1024,
               "H=16 fixture is not multidimensional");
  require_test(multidimensional_reference.get_num_other_dims() > 0,
               "H=16 fixture does not exercise MUX dimensions");
  const BenchmarkTrialPlan multidimensional_trials{
      {}, {48879, multidimensional.leaf_count - 1}};
  BenchmarkCaseExecution flat_multi = run_merkle_flat_case(
      multidimensional, multidimensional_reference,
      multidimensional_trials);
  BenchmarkCaseExecution layerwise_multi = run_merkle_layerwise_case(
      multidimensional, multidimensional_reference,
      multidimensional_trials);
  require_test(flat_multi.measured_paths == layerwise_multi.measured_paths,
               "H=16 flat/layerwise path mismatch");
  require_expected_path(flat_multi.measured_paths.at(0), 48879, 16);
  require_expected_path(flat_multi.measured_paths.at(1),
                        multidimensional.leaf_count - 1, 16);
  require_test(layerwise_multi.result.direct_return_levels == 6,
               "H=16 direct-return level count");
  validate_layerwise_path_communication(
      flat_multi.result.communication, layerwise_multi.result.communication,
      layerwise_multi.result.direct_return_levels,
      layerwise_multi.result.direct_return_response_bytes);

  // Profiled planner at H=16 with RGSW MUX levels: same paths, same bytes.
  std::shared_ptr<LayerLayoutProfile> profile16;
  {
    LayerLayoutSweepOptions sweep;
    sweep.leaf_count = multidimensional.leaf_count;
    sweep.warmups = 1;
    sweep.measured_trials = 2;
    sweep.trial_seed = 11;
    profile16 =
        std::make_shared<LayerLayoutProfile>(run_layer_layout_sweep(sweep));
    const PirParams sweep_reference =
        make_benchmark_reference(multidimensional);
    LayerPlannerConfig config;
    config.policy = LayerLayoutPolicy::profiled;
    config.profile = profile16;
    BenchmarkCaseExecution legacy_ref = run_merkle_layerwise_case(
        multidimensional, sweep_reference, multidimensional_trials);
    BenchmarkCaseExecution profiled = run_merkle_layerwise_case(
        multidimensional, sweep_reference, multidimensional_trials, config);
    require_test(profiled.measured_paths == legacy_ref.measured_paths,
                 "H=16 profiled/legacy path mismatch");
    require_expected_path(profiled.measured_paths.at(0), 48879, 16);
    validate_matching_path_communication(legacy_ref.result.communication,
                                         profiled.result.communication);
    uint64_t legacy_padded = 0, profiled_padded = 0;
    for (size_t i = 0; i < 16; ++i) {
      legacy_padded += legacy_ref.result.layers[i].features.padded_plaintexts;
      profiled_padded +=
          profiled.result.layers[i].features.padded_plaintexts;
    }
    require_test(profiled_padded <= legacy_padded * 1.01 + 1,
                 "H=16 profiled plan respects the padding budget");
  }

  // The benchmark suite with profiles loaded from disk, one per tree height:
  // the suite must pick the profile whose height matches the workload even
  // when the primary profile is the other one, reject a run with no matching
  // profile, and fall back to legacy only when asked. The full case set at
  // H=8 also runs the standard, flat and layerwise cases together.
  {
    const std::filesystem::path dir = std::filesystem::temp_directory_path();
    const std::string path8 = (dir / "merkle-integration-h8.json").string();
    const std::string path16 = (dir / "merkle-integration-h16.json").string();
    save_layer_layout_profile(*profile8, path8);
    save_layer_layout_profile(*profile16, path16);
    auto loaded8 =
        std::make_shared<LayerLayoutProfile>(load_layer_layout_profile(path8));
    auto loaded16 = std::make_shared<LayerLayoutProfile>(
        load_layer_layout_profile(path16));
    std::filesystem::remove(path8);
    std::filesystem::remove(path16);
    require_test(loaded8->tree_height == 8 && loaded16->tree_height == 16,
                 "profiles reloaded from disk");

    MerkleBenchmarkOptions options;
    options.leaf_count = small.leaf_count;
    options.warmups = 0;
    options.measured_trials = 1;
    options.trial_seed = 0x6d65726b6c65ULL;
    options.case_selection = BenchmarkCaseSelection::all;
    options.layer_planner.policy = LayerLayoutPolicy::profiled;
    options.layer_planner.profile = loaded16;  // wrong height on purpose
    options.layer_profiles = {loaded16, loaded8};
    const BenchmarkReport report = run_merkle_benchmark_suite(options);
    require_test(report.cases.size() == 3 &&
                     report.cases[0].name == "standard_onionpir" &&
                     report.cases[1].name == "merkle_flat" &&
                     report.cases[2].name == "merkle_layerwise",
                 "full case set order");
    for (const BenchmarkCaseResult &c : report.cases) {
      require_test(c.correctness_passed, "full case set correctness");
    }
    require_test(report.cases[2].layer_layout_policy == "profiled" &&
                     report.cases[2].layers.size() == 8,
                 "suite selected the matching-height profile");
    require_test(report.workload.optional_workloads.size() == 1 &&
                     report.workload.optional_workloads[0].status ==
                         "not_requested",
                 "optional tier is reported as not requested");
    print_benchmark_report(report);

    options.case_selection = BenchmarkCaseSelection::merkle_layerwise;
    options.layer_profiles = {loaded16};
    require_test(throws_invalid_argument(
                     [&] { (void)run_merkle_benchmark_suite(options); }),
                 "suite accepted a run without a matching profile");
    options.layer_planner.allow_profile_fallback = true;
    const BenchmarkReport fallback = run_merkle_benchmark_suite(options);
    require_test(fallback.cases.size() == 1 &&
                     fallback.cases[0].layer_layout_policy == "legacy",
                 "suite fallback must report the legacy policy");
  }
}
