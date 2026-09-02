#include "merkle_benchmark.h"
#include "tests.h"

#include <cstring>
#include <memory>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

namespace {

size_t parse_size_argument(const char *option, const char *value) {
  std::string text(value);
  if (text.empty() || text.front() == '-') {
    throw std::invalid_argument(std::string(option) +
                                " requires a non-negative integer");
  }
  size_t parsed_characters = 0;
  unsigned long long parsed = 0;
  try {
    parsed = std::stoull(text, &parsed_characters, 10);
  } catch (const std::exception &) {
    throw std::invalid_argument(std::string(option) +
                                " requires a non-negative integer");
  }
  if (parsed_characters != text.size() ||
      parsed > std::numeric_limits<size_t>::max()) {
    throw std::invalid_argument(std::string(option) +
                                " is outside the size_t range");
  }
  return static_cast<size_t>(parsed);
}

uint64_t parse_seed_argument(const char *value) {
  std::string text(value);
  if (text.empty() || text.front() == '-') {
    throw std::invalid_argument(
        "--trial-seed requires a non-negative integer");
  }
  size_t parsed_characters = 0;
  unsigned long long parsed = 0;
  try {
    parsed = std::stoull(text, &parsed_characters, 10);
  } catch (const std::exception &) {
    throw std::invalid_argument(
        "--trial-seed requires a non-negative integer");
  }
  if (parsed_characters != text.size()) {
    throw std::invalid_argument("--trial-seed is outside the uint64_t range");
  }
  return static_cast<uint64_t>(parsed);
}

const char *require_value(int argc, char *argv[], int &index) {
  if (index + 1 >= argc) {
    throw std::invalid_argument(std::string(argv[index]) +
                                " requires a value");
  }
  return argv[++index];
}

}  // namespace

int main(int argc, char *argv[]) {
  try {
    std::string test_name = "pir";
    size_t num_experiments = 10;
    size_t warmup = 3;
    size_t leaf_count = size_t{1} << 24;
    uint64_t trial_seed = MerkleBenchmarkOptions{}.trial_seed;
    std::string benchmark_json;
    bool run_optional_4gb = false;
    BenchmarkCaseSelection benchmark_case = BenchmarkCaseSelection::all;
    // Layerwise layout planner / sweep flags.
    std::string layout_profile_json;
    bool layout_sweep_all = false;
    double layer_padding_budget = 1.01;
    std::string layer_layout_policy = "legacy";
    std::string layer_layout_profile;
    bool allow_layout_profile_fallback = false;

    for (int i = 1; i < argc; ++i) {
      if (std::strcmp(argv[i], "--test") == 0) {
        test_name = require_value(argc, argv, i);
      } else if (std::strcmp(argv[i], "--experiments") == 0) {
        num_experiments = parse_size_argument(
            "--experiments", require_value(argc, argv, i));
      } else if (std::strcmp(argv[i], "--warmup") == 0) {
        warmup = parse_size_argument("--warmup",
                                     require_value(argc, argv, i));
      } else if (std::strcmp(argv[i], "--leaf-count") == 0) {
        leaf_count = parse_size_argument(
            "--leaf-count", require_value(argc, argv, i));
      } else if (std::strcmp(argv[i], "--trial-seed") == 0) {
        trial_seed = parse_seed_argument(require_value(argc, argv, i));
      } else if (std::strcmp(argv[i], "--benchmark-json") == 0) {
        benchmark_json = require_value(argc, argv, i);
      } else if (std::strcmp(argv[i], "--benchmark-case") == 0) {
        const std::string value = require_value(argc, argv, i);
        if (value == "all") {
          benchmark_case = BenchmarkCaseSelection::all;
        } else if (value == "standard_onionpir") {
          benchmark_case = BenchmarkCaseSelection::standard_onionpir;
        } else if (value == "merkle_paths") {
          benchmark_case = BenchmarkCaseSelection::merkle_paths;
        } else if (value == "merkle_layerwise") {
          benchmark_case = BenchmarkCaseSelection::merkle_layerwise;
        } else {
          throw std::invalid_argument(
              "--benchmark-case must be all, standard_onionpir, or "
              "merkle_paths, or merkle_layerwise");
        }
      } else if (std::strcmp(argv[i], "--run-optional-4gb") == 0) {
        run_optional_4gb = true;
      } else if (std::strcmp(argv[i], "--layout-profile-json") == 0) {
        layout_profile_json = require_value(argc, argv, i);
      } else if (std::strcmp(argv[i], "--layout-sweep-all") == 0) {
        layout_sweep_all = true;
      } else if (std::strcmp(argv[i], "--layer-padding-budget") == 0) {
        layer_padding_budget =
            parse_padding_budget(require_value(argc, argv, i));
      } else if (std::strcmp(argv[i], "--layer-layout-policy") == 0) {
        layer_layout_policy = require_value(argc, argv, i);
        if (layer_layout_policy != "legacy" &&
            layer_layout_policy != "profiled") {
          throw std::invalid_argument(
              "--layer-layout-policy must be legacy or profiled");
        }
      } else if (std::strcmp(argv[i], "--layer-layout-profile") == 0) {
        layer_layout_profile = require_value(argc, argv, i);
      } else if (std::strcmp(argv[i], "--allow-layout-profile-fallback") == 0) {
        allow_layout_profile_fallback = true;
      } else if (std::strcmp(argv[i], "--no-compress") == 0) {
        // Retained for run.py compatibility. Current query packing has one path.
      } else {
        throw std::invalid_argument(std::string("Unknown option: ") + argv[i]);
      }
    }

    if (test_name == "layer_layout_sweep") {
      if (layout_profile_json.empty()) {
        throw std::invalid_argument(
            "--test layer_layout_sweep requires --layout-profile-json <path>");
      }
      if (num_experiments == 0) {
        throw std::invalid_argument("--experiments must be positive");
      }
      LayerLayoutSweepOptions sweep;
      sweep.leaf_count = leaf_count;
      sweep.warmups = warmup;
      sweep.measured_trials = num_experiments;
      sweep.trial_seed = trial_seed;
      sweep.padding_budget = layer_padding_budget;
      sweep.include_dominated = layout_sweep_all;
      const LayerLayoutProfile profile = run_layer_layout_sweep(sweep);
      save_layer_layout_profile(profile, layout_profile_json);
      std::cout << "Layer layout profile: " << layout_profile_json << '\n';
      return 0;
    }

    if (test_name == "merkle_benchmarks") {
      MerkleBenchmarkOptions options;
      options.leaf_count = leaf_count;
      options.warmups = warmup;
      options.measured_trials = num_experiments;
      options.trial_seed = trial_seed;
      options.run_optional_4gb = run_optional_4gb;
      options.case_selection = benchmark_case;
      options.layer_planner.total_padding_budget = layer_padding_budget;
      options.layer_planner.allow_profile_fallback =
          allow_layout_profile_fallback;
      if (layer_layout_policy == "profiled") {
        if (layer_layout_profile.empty()) {
          throw std::invalid_argument(
              "--layer-layout-policy profiled requires "
              "--layer-layout-profile <path>");
        }
        options.layer_planner.policy = LayerLayoutPolicy::profiled;
        options.layer_planner.profile = std::make_shared<LayerLayoutProfile>(
            load_layer_layout_profile(layer_layout_profile));
      }
      BenchmarkReport report = run_merkle_benchmark_suite(options);
      print_benchmark_report(report);
      if (!benchmark_json.empty()) {
        write_benchmark_report_json(report, benchmark_json);
        std::cout << "Benchmark JSON: " << benchmark_json << '\n';
      }
      return 0;
    }

    if (num_experiments >
        std::numeric_limits<size_t>::max() - warmup) {
      throw std::overflow_error("experiment count plus warmup overflows");
    }
    TimerLogger::setWarmup(warmup);
    PirTest test;
    test.num_experiments = num_experiments + warmup;
    test.run_test(test_name);
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "Error: " << error.what() << '\n';
    return 1;
  }
}
