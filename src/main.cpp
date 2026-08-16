#include "merkle_benchmark.h"
#include "tests.h"

#include <cstring>
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
    bool run_optional_8gb = false;
    BenchmarkCaseSelection benchmark_case = BenchmarkCaseSelection::all;

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
        } else {
          throw std::invalid_argument(
              "--benchmark-case must be all, standard_onionpir, or "
              "merkle_paths");
        }
      } else if (std::strcmp(argv[i], "--run-optional-8gb") == 0) {
        run_optional_8gb = true;
      } else if (std::strcmp(argv[i], "--no-compress") == 0) {
        // Retained for run.py compatibility. Current query packing has one path.
      } else {
        throw std::invalid_argument(std::string("Unknown option: ") + argv[i]);
      }
    }

    if (test_name == "merkle_benchmarks") {
      MerkleBenchmarkOptions options;
      options.leaf_count = leaf_count;
      options.warmups = warmup;
      options.measured_trials = num_experiments;
      options.trial_seed = trial_seed;
      options.run_optional_8gb = run_optional_8gb;
      options.case_selection = benchmark_case;
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
