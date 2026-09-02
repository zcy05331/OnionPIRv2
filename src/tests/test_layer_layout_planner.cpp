#include "tests.h"
#include "layer_layout_planner.h"
#include "merkle_baseline.h"

#include <filesystem>
#include <stdexcept>
#include <vector>

namespace {

const LayerLayoutCandidate &candidate_with_height(
    const std::vector<LayerLayoutCandidate> &candidates, size_t height) {
  for (const LayerLayoutCandidate &c : candidates) {
    if (c.features.expansion_height == height) return c;
  }
  throw std::runtime_error("no candidate with the requested height");
}

LayerLayoutMeasurement synthetic_measurement(const LayerLayoutCandidate &c,
                                             double median_ms) {
  LayerLayoutMeasurement m;
  m.level = c.layout.level;
  m.features = c.features;
  m.server_samples_ms = {median_ms};
  m.median_server_ms = median_ms;
  return m;
}

}  // namespace

void PirTest::test_layer_layout_planner() {
  print_func_name(__FUNCTION__);

  // Pruned expansion geometry, checked by hand against fast_expand_qry's walk.
  require_test(count_pruned_expansion_substitutions(1, 0) == 0, "h=0 count");
  require_test(count_pruned_expansion_substitutions(2, 1) == 1, "h=1 count");
  require_test(count_pruned_expansion_substitutions(3, 2) == 3, "u=3 h=2");
  require_test(count_pruned_expansion_substitutions(2, 2) == 2,
               "right subtree pruned at u=2 h=2");
  require_test(count_pruned_expansion_substitutions(4, 2) == 3, "full h=2");

  // H=24 fixture: the level-24 frontier is exactly h=9 and h=10.
  const PirParams reference = PirParams().with_layout({349526, 10, true});
  const std::vector<LayerLayoutCandidate> candidates =
      enumerate_layer_layout_candidates(24, 96, reference);
  require_test(!candidates.empty(), "level 24 has legal candidates");
  for (const LayerLayoutCandidate &c : candidates) {
    const PirParams &p = c.layout.params;
    const LayerLayoutFeatures &f = c.features;
    require_test(reference.scheme_compatible(p), "candidate scheme drift");
    require_test(p.get_num_other_dims() <= reference.get_num_other_dims(),
                 "candidate exceeds reference dimensions");
    require_test(f.useful_expanded_ciphertexts ==
                     p.get_fst_dim_sz() + p.get_l() * p.get_num_other_dims(),
                 "useful expanded identity");
    require_test(f.first_dim_query_ntts == 2 * p.get_fst_dim_sz(),
                 "query NTT identity");
    require_test(f.selector_rows_to_complete ==
                     p.get_l() * p.get_num_other_dims(),
                 "selector rows identity");
    require_test(f.inverse_ntts == 2 * p.get_other_dim_sz(),
                 "inverse NTT identity");
    require_test(f.cmux_count == p.get_other_dim_sz() - 1, "cmux identity");
    if (p.get_composite_rns().enabled) {
      require_test(f.crt_coefficients_to_compose ==
                       2 * p.get_poly_degree() * p.get_other_dim_sz(),
                   "CRT compose identity");
    }
    require_test(f.padded_plaintexts == p.get_num_pt() &&
                     f.padding_plaintexts ==
                         p.get_num_pt() - p.get_target_num_pt(),
                 "padding identity");
    require_test(f.logical_padded_bytes ==
                     uint64_t{p.get_num_pt()} * p.get_pt_size(),
                 "padded bytes identity");
  }
  const std::vector<LayerLayoutCandidate> frontier =
      pareto_layer_layout_candidates(candidates);
  require_test(frontier.size() == 2, "level 24 frontier has two candidates");
  const LayerLayoutCandidate &h9 = candidate_with_height(frontier, 9);
  const LayerLayoutCandidate &h10 = candidate_with_height(frontier, 10);
  require_test(h9.features.first_dim_size == 256 &&
                   h9.features.other_dim_size == 683 &&
                   h9.features.padded_plaintexts == 174848 &&
                   h9.features.useful_expanded_ciphertexts == 316 &&
                   h9.features.cmux_count == 682,
               "h=9 frontier candidate");
  require_test(h10.features.first_dim_size == 512 &&
                   h10.features.other_dim_size == 342 &&
                   h10.features.padded_plaintexts == 175104 &&
                   h10.features.useful_expanded_ciphertexts == 566 &&
                   h10.features.cmux_count == 341,
               "h=10 frontier candidate");
  require_test(candidates[legacy_layer_layout_candidate(candidates)]
                       .features.expansion_height == 9,
               "legacy picks the minimal-padding h=9 layout");

  // Synthetic profile: h=10 measured faster than h=9 at level 24.
  LayerLayoutProfile profile;
  profile.environment = detect_layer_layout_environment(
      reference, "test-commit", "Benchmark", "CONFIG_N2048_K1_COMP");
  profile.tree_height = 24;
  profile.nodes_per_plaintext = 96;
  profile.warmups = 0;
  profile.measured_trials = 1;
  profile.trial_seed = 5723628103747520850ULL;
  profile.measurements.push_back(synthetic_measurement(h9, 100.0));
  profile.measurements.push_back(synthetic_measurement(h10, 90.0));

  const LayerLayoutSelection permitted =
      select_layer_layouts(profile, 24, 96, reference, 1.01);
  require_test(permitted.expansion_heights.size() == 24, "one height per level");
  require_test(permitted.expansion_heights[23] == 10,
               "1% budget admits the faster h=10 layout");
  require_test(permitted.selected_total_padded_plaintexts ==
                   permitted.legacy_total_padded_plaintexts + 256,
               "h=10 costs exactly 256 extra plaintexts");
  const LayerLayoutSelection zero_budget =
      select_layer_layouts(profile, 24, 96, reference, 1.0);
  require_test(zero_budget.expansion_heights[23] == 9,
               "zero padding budget keeps h=9");
  require_test(zero_budget.selected_total_padded_plaintexts ==
                   zero_budget.legacy_total_padded_plaintexts,
               "zero budget keeps the legacy total");
  // Within 2% the deterministic order (smaller scan bytes first) wins.
  profile.measurements[1].median_server_ms = 99.0;
  profile.measurements[1].server_samples_ms = {99.0};
  const LayerLayoutSelection tied =
      select_layer_layouts(profile, 24, 96, reference, 1.01);
  require_test(tied.expansion_heights[23] == 9,
               "2% tie rule prefers the smaller layout");
  profile.measurements[1].median_server_ms = 90.0;
  profile.measurements[1].server_samples_ms = {90.0};

  // JSON round trip and profile validation.
  const std::string path =
      (std::filesystem::temp_directory_path() / "layer-layout-planner-test.json")
          .string();
  save_layer_layout_profile(profile, path);
  const LayerLayoutProfile loaded = load_layer_layout_profile(path);
  require_test(loaded.trial_seed == profile.trial_seed &&
                   loaded.tree_height == 24 && loaded.nodes_per_plaintext == 96 &&
                   loaded.measurements.size() == 2 &&
                   loaded.measurements[1].features.padded_plaintexts == 175104 &&
                   loaded.measurements[1].median_server_ms == 90.0 &&
                   loaded.environment.cpu == profile.environment.cpu,
               "profile JSON round trip");
  const LayerLayoutProfileEnvironment runtime =
      detect_layer_layout_environment(reference, "other", "Benchmark", "X");
  require_test(describe_layer_layout_profile_mismatch(loaded, runtime, 24, 96)
                   .empty(),
               "same machine and scheme validate");
  require_test(!describe_layer_layout_profile_mismatch(loaded, runtime, 22, 96)
                    .empty(),
               "tree height mismatch is reported");
  LayerLayoutProfileEnvironment other_cpu = runtime;
  other_cpu.cpu = "some other cpu";
  require_test(!describe_layer_layout_profile_mismatch(loaded, other_cpu, 24, 96)
                    .empty(),
               "cpu mismatch is reported");

  // Policy-aware planner: profiled selection versus the frozen legacy plan.
  const std::vector<LayerLayout> legacy = plan_layer_layouts(24, 96, reference);
  LayerPlannerConfig config;
  config.policy = LayerLayoutPolicy::profiled;
  config.profile = std::make_shared<LayerLayoutProfile>(loaded);
  const std::vector<LayerLayout> profiled =
      plan_layer_layouts(24, 96, reference, config);
  require_test(profiled.size() == 24, "profiled plan has one layout per level");
  for (size_t i = 0; i + 1 < 24; ++i) {
    require_test(profiled[i].params.get_expan_height() ==
                     legacy[i].params.get_expan_height(),
                 "unmeasured levels keep the legacy layout");
    require_test(profiled[i].direct_return == legacy[i].direct_return,
                 "direct-return flags agree");
  }
  require_test(profiled[23].params.get_expan_height() == 10,
               "profiled plan uses h=10 at level 24");
  require_test(sum_padded_bytes(profiled) ==
                   sum_padded_bytes(legacy) + 256 * reference.get_pt_size(),
               "profiled plan adds exactly 256 padded plaintexts");
  LayerPlannerConfig mismatched = config;
  auto bad = std::make_shared<LayerLayoutProfile>(loaded);
  bad->tree_height = 22;
  mismatched.profile = bad;
  bool rejected = false;
  try {
    (void)plan_layer_layouts(24, 96, reference, mismatched);
  } catch (const std::invalid_argument &) {
    rejected = true;
  }
  require_test(rejected, "mismatched profile is rejected by default");
  mismatched.allow_profile_fallback = true;
  const std::vector<LayerLayout> fallback =
      plan_layer_layouts(24, 96, reference, mismatched);
  require_test(sum_padded_bytes(fallback) == sum_padded_bytes(legacy),
               "explicit fallback reproduces the legacy plan");
  LayerPlannerConfig legacy_config;
  require_test(sum_padded_bytes(plan_layer_layouts(24, 96, reference,
                                                   legacy_config)) ==
                   1074843648ULL,
               "legacy policy keeps the frozen H=24 padded total");
  std::filesystem::remove(path);
}
