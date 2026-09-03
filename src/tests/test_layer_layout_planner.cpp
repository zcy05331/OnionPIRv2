#include "tests.h"
#include "layer_layout_planner.h"
#include "merkle_baseline.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <stdexcept>
#include <string>
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

std::string read_text(const std::string &path) {
  std::ifstream file(path, std::ios::binary);
  std::stringstream buffer;
  buffer << file.rdbuf();
  return buffer.str();
}

void write_text(const std::string &path, const std::string &text) {
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  file << text;
}

// Loads a mutated profile text and reports whether loading failed with a
// message containing `needle`.
bool load_fails_with(const std::string &path, const std::string &text,
                     const std::string &needle) {
  write_text(path, text);
  try {
    (void)load_layer_layout_profile(path);
  } catch (const std::exception &error) {
    return std::string(error.what()).find(needle) != std::string::npos;
  }
  return false;
}

std::string replace_first(std::string text, const std::string &from,
                          const std::string &to) {
  const size_t at = text.find(from);
  if (at == std::string::npos) {
    throw std::runtime_error("profile text lacks: " + from);
  }
  return text.replace(at, from.size(), to);
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

  // Every environment field the profile is validated on, mutated one at a
  // time, must be named in the mismatch description.
  {
    using Env = LayerLayoutProfileEnvironment;
    const std::vector<std::pair<std::string, std::function<void(Env &)>>>
        mutations = {
            {"poly_degree", [](Env &e) { e.poly_degree += 1; }},
            {"log_q", [](Env &e) { e.log_q += 1; }},
            {"log_t", [](Env &e) { e.log_t += 1; }},
            {"log_q_prime", [](Env &e) { e.log_q_prime += 1; }},
            {"L_EP", [](Env &e) { e.l_ep += 1; }},
            {"L_KEY", [](Env &e) { e.l_key += 1; }},
            {"L_KS", [](Env &e) { e.l_ks += 1; }},
            {"composite_first_dim",
             [](Env &e) { e.composite_first_dim = !e.composite_first_dim; }},
            {"architecture", [](Env &e) { e.architecture += "-other"; }},
            {"cpu", [](Env &e) { e.cpu += " other"; }},
            {"compiler", [](Env &e) { e.compiler += " other"; }},
            {"hexl_version", [](Env &e) { e.hexl_version += ".1"; }},
        };
    for (const auto &[field, mutate] : mutations) {
      Env other = runtime;
      mutate(other);
      const std::string description =
          describe_layer_layout_profile_mismatch(loaded, other, 24, 96);
      require_test(description.find(field) != std::string::npos,
                   "mismatch description does not name " + field);
    }
    require_test(describe_layer_layout_profile_mismatch(loaded, runtime, 24, 95)
                         .find("nodes_per_plaintext") != std::string::npos,
                 "nodes per plaintext mismatch is reported");
    // commit, build type and config are informational: the same machine and
    // scheme validate whatever they say.
    Env relabelled = runtime;
    relabelled.commit = "elsewhere";
    relabelled.build_type = "Debug";
    relabelled.config = "renamed";
    require_test(describe_layer_layout_profile_mismatch(loaded, relabelled, 24,
                                                         96)
                     .empty(),
                 "commit/build/config labels must not block a profile");
  }

  // Malformed profile files are rejected with a specific reason.
  {
    const std::string text = read_text(path);
    const std::string bad_path =
        (std::filesystem::temp_directory_path() / "layer-layout-bad.json")
            .string();
    require_test(load_fails_with(bad_path,
                                 replace_first(text, "\"tree_height\": 24",
                                               "\"tree_heigh\": 24"),
                                 "missing key"),
                 "loader accepted a missing key");
    require_test(load_fails_with(bad_path,
                                 replace_first(text, "\"tree_height\": 24",
                                               "\"tree_height\": \"24\""),
                                 "expected a number"),
                 "loader accepted a string where a number is required");
    require_test(load_fails_with(bad_path,
                                 replace_first(text, "layer-layout-profile-v1",
                                               "layer-layout-profile-v0"),
                                 "unsupported"),
                 "loader accepted an unknown schema version");
    require_test(load_fails_with(bad_path, text + "x", "trailing"),
                 "loader accepted trailing characters");
    {
      const size_t at = text.find("\"server_samples_ms\": [");
      require_test(at != std::string::npos, "profile text lacks samples");
      const size_t open = text.find('[', at);
      const size_t close = text.find(']', open);
      const std::string no_samples =
          text.substr(0, open + 1) + text.substr(close);
      require_test(load_fails_with(bad_path, no_samples, "no samples"),
                   "loader accepted a measurement without samples");
    }
    std::filesystem::remove(bad_path);
    bool missing_file = false;
    try {
      (void)load_layer_layout_profile(bad_path);
    } catch (const std::runtime_error &) {
      missing_file = true;
    }
    require_test(missing_file, "loader did not report a missing file");
  }

  // Structural rejections of the selector and the enumerator.
  {
    LayerLayoutProfile drifted = loaded;
    drifted.measurements[1].features.padded_plaintexts += 1;
    bool rejected_shape = false;
    try {
      (void)select_layer_layouts(drifted, 24, 96, reference, 1.01);
    } catch (const std::invalid_argument &) {
      rejected_shape = true;
    }
    require_test(rejected_shape,
                 "selector accepted a measurement of an illegal layout");

    LayerLayoutProfile only_alternative = loaded;
    only_alternative.measurements.erase(only_alternative.measurements.begin());
    require_test(only_alternative.measurements.size() == 1 &&
                     only_alternative.measurements[0].features
                             .expansion_height == 10,
                 "fixture keeps only the h=10 measurement");
    bool infeasible = false;
    try {
      (void)select_layer_layouts(only_alternative, 24, 96, reference, 1.0);
    } catch (const std::runtime_error &) {
      infeasible = true;
    }
    require_test(infeasible,
                 "selector found a plan although no measured option fits");

    const auto rejects = [](auto &&fn) {
      try {
        fn();
      } catch (const std::invalid_argument &) {
        return true;
      }
      return false;
    };
    require_test(rejects([&] {
                   (void)enumerate_layer_layout_candidates(0, 96, reference);
                 }),
                 "enumerator accepted level 0");
    require_test(rejects([&] {
                   (void)enumerate_layer_layout_candidates(24, 0, reference);
                 }),
                 "enumerator accepted zero nodes per plaintext");
    require_test(rejects([&] {
                   (void)select_layer_layouts(loaded, 24, 96, reference, 0.5);
                 }),
                 "selector accepted a budget below 1.0");
    LayerPlannerConfig no_profile;
    no_profile.policy = LayerLayoutPolicy::profiled;
    require_test(rejects([&] {
                   (void)plan_layer_layouts(24, 96, reference, no_profile);
                 }),
                 "profiled policy accepted a null profile");
  }

  // Multi-level knapsack under a binding budget: levels 22, 23 and 24 each
  // get a measured legacy layout and one measured alternative that costs
  // extra padding and saves time. The budget admits some but not all
  // alternatives; the DP's choice must match a brute-force search over the
  // eight subsets, and the unconstrained budget must take every alternative.
  {
    struct Level {
      size_t level;
      size_t legacy_height, alt_height;
      size_t extra;
      double saving;
    };
    std::vector<Level> levels;
    LayerLayoutProfile multi = loaded;
    multi.measurements.clear();
    const std::vector<double> savings = {12.0, 8.0, 10.0};
    for (size_t level = 22; level <= 24; ++level) {
      const std::vector<LayerLayoutCandidate> cands =
          enumerate_layer_layout_candidates(level, 96, reference);
      const std::vector<LayerLayoutCandidate> front =
          pareto_layer_layout_candidates(cands);
      const LayerLayoutCandidate &leg =
          cands[legacy_layer_layout_candidate(cands)];
      const LayerLayoutCandidate *alt = nullptr;
      for (const LayerLayoutCandidate &c : front) {
        if (c.features.padded_plaintexts > leg.features.padded_plaintexts &&
            (!alt || c.features.padded_plaintexts >
                         alt->features.padded_plaintexts)) {
          alt = &c;
        }
      }
      require_test(alt != nullptr,
                   "level has no frontier alternative with extra padding");
      const double saving = savings[level - 22];
      multi.measurements.push_back(synthetic_measurement(leg, 100.0));
      multi.measurements.push_back(
          synthetic_measurement(*alt, 100.0 - saving));
      levels.push_back({level, leg.features.expansion_height,
                        alt->features.expansion_height,
                        alt->features.padded_plaintexts -
                            leg.features.padded_plaintexts,
                        saving});
    }
    const LayerLayoutSelection all_in =
        select_layer_layouts(multi, 24, 96, reference, 2.0);
    for (const Level &l : levels) {
      require_test(all_in.expansion_heights[l.level - 1] == l.alt_height,
                   "unconstrained budget must take every faster layout");
    }
    require_test(all_in.predicted_legacy_ms == 300.0 &&
                     all_in.predicted_selected_ms == 270.0,
                 "predicted times sum the chosen medians");

    // Cap the extra plaintexts to the two cheapest alternatives together
    // minus one, so at most those two (or one expensive one) fit.
    std::vector<size_t> extras;
    for (const Level &l : levels) extras.push_back(l.extra);
    std::sort(extras.begin(), extras.end());
    const size_t cap = extras[0] + extras[1] - 1;
    const uint64_t legacy_total = all_in.legacy_total_padded_plaintexts;
    const double budget = 1.0 + (static_cast<double>(cap) + 0.5) /
                                    static_cast<double>(legacy_total);
    const LayerLayoutSelection capped =
        select_layer_layouts(multi, 24, 96, reference, budget);
    double best_time = 300.0;
    for (unsigned mask = 0; mask < 8; ++mask) {
      size_t used = 0;
      double time = 300.0;
      for (size_t i = 0; i < 3; ++i) {
        if (mask & (1U << i)) {
          used += levels[i].extra;
          time -= levels[i].saving;
        }
      }
      if (used <= cap) best_time = std::min(best_time, time);
    }
    require_test(best_time > 270.0, "budget must be binding");
    require_test(capped.predicted_selected_ms == best_time,
                 "DP must match the brute-force optimum under the budget");
    require_test(capped.selected_total_padded_plaintexts <=
                     legacy_total + cap,
                 "DP must respect the padded-plaintext cap");
    double chosen_time = 300.0;
    size_t chosen_extra = 0;
    for (const Level &l : levels) {
      const size_t h = capped.expansion_heights[l.level - 1];
      require_test(h == l.legacy_height || h == l.alt_height,
                   "DP chose an unmeasured layout");
      if (h == l.alt_height) {
        chosen_time -= l.saving;
        chosen_extra += l.extra;
      }
    }
    require_test(chosen_time == capped.predicted_selected_ms &&
                     chosen_extra + legacy_total ==
                         capped.selected_total_padded_plaintexts,
                 "selection bookkeeping matches the chosen heights");
  }

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
