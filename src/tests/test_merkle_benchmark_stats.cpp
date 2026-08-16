#include "tests.h"
#include "merkle_benchmark.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <sstream>

void PirTest::test_merkle_benchmark_stats() {
  BenchmarkTrialPlan distinct_queries =
      make_benchmark_trial_plan(8, 3, 5, 0x123456789abcdef0ULL);
  std::vector<size_t> all_query_ids = distinct_queries.warmup_leaf_indices;
  all_query_ids.insert(all_query_ids.end(),
                       distinct_queries.measured_leaf_indices.begin(),
                       distinct_queries.measured_leaf_indices.end());
  std::sort(all_query_ids.begin(), all_query_ids.end());
  require_test(all_query_ids.size() == 8,
               "trial planner omitted query IDs");
  require_test(std::adjacent_find(all_query_ids.begin(), all_query_ids.end()) ==
                   all_query_ids.end(),
               "trial planner repeated a query ID");

  bool rejected_too_many_distinct_queries = false;
  try {
    (void)make_benchmark_trial_plan(4, 2, 3, 7);
  } catch (const std::invalid_argument &) {
    rejected_too_many_distinct_queries = true;
  }
  require_test(rejected_too_many_distinct_queries,
               "trial planner accepted more queries than leaves");

  PirParams reference = PirParams().with_layout({349526, 10, true});
  // Freeze v2 seed-compressed request/helper models independently of the
  // response serializer, whose byte count is measured at runtime.
  require_test(reference.get_BFV_size(true) == 14880, "query bytes");
  require_test(modeled_helper_key_bytes(reference) == 1488000,
               "helper bytes");

  CommunicationStats standard =
      communication_stats(reference, 1, {11264});
  require_test(standard.online_total_bytes_mixed == 26144,
               "standard online");
  require_test(standard.first_session_total_bytes_mixed == 1514144,
               "standard first session");

  // Both naive path baselines make H calls and share one helper bundle, so
  // their online and first-session totals must match exactly.
  CommunicationStats path = communication_stats(
      reference, 24, std::vector<size_t>(24, 11264));
  require_test(path.online_total_bytes_mixed == 627456, "path online");
  require_test(path.first_session_total_bytes_mixed == 2115456,
               "path first session");
  validate_matching_path_communication(path, path);
  bool rejected_path_mismatch = false;
  try {
    CommunicationStats mismatched = path;
    --mismatched.online_response_bytes_actual;
    validate_matching_path_communication(path, mismatched);
  } catch (const std::invalid_argument &) {
    rejected_path_mismatch = true;
  }
  require_test(rejected_path_mismatch,
               "accepted flat/layerwise communication mismatch");

  // Model a flat H=24 trial: one ~1 GiB plaintext database, 24 repeated scans,
  // and one full-path server time. Paper throughput must use the database
  // footprint once; paper_scan_throughput retains the repeated-work diagnostic.
  BenchmarkCaseResult result;
  result.name = "merkle_flat";
  result.correctness_passed = true;
  result.communication = standard;
  result.raw_dataset_bytes = 1073741760;
  result.paper_plaintext_database_bytes = 1073743872;
  result.logical_padded_database_bytes = 1074266112;
  result.paper_plaintext_scan_bytes = 25769852928;
  result.logical_padded_scan_bytes = 25782386688;
  result.raw_application_scan_bytes = 25769852928;
  result.physical_preprocessed_storage_bytes = 5729419264;
  result.useful_response_bytes = 768;
  result.timing.setup = std::chrono::milliseconds(12);
  result.timing.client_query = std::chrono::milliseconds(1);
  result.timing.server_compute = std::chrono::milliseconds(250);
  result.timing.response_serialize = std::chrono::milliseconds(2);
  result.timing.response_load_decrypt_extract = std::chrono::milliseconds(3);
  finalize_case_statistics(result);
  require_test(result.paper_server_throughput_MBps > 4095.0 &&
                   result.paper_server_throughput_MBps < 4097.0,
               "paper throughput used repeated scan bytes as database size");
  // JSON must keep the primary and scan metrics distinct and preserve bytes.
  BenchmarkReport report;
  report.schema_version = "onionpir-merkle-baselines-v2";
  report.environment.architecture = "x86_64";
  report.environment.hexl_enabled = true;
  report.environment.rosetta = true;
  report.environment.non_native_label =
      "x86_64 + Intel HEXL under Rosetta 2 on Apple M4; non-native result";
  report.paper_alignment.poly_degree = 2048;
  report.workload.leaf_count = size_t{1} << 24;
  report.workload.tree_height = 24;
  report.workload.node_bytes = 32;
  report.workload.nodes_per_plaintext = 96;
  report.workload.warmup_leaf_indices = {1, 2, 3};
  report.workload.trial_leaf_indices = {4, 5, 6, 7, 8};
  report.cases.push_back(result);

  const std::string path_name = "/tmp/onionpir-benchmark-stats-test.json";
  write_benchmark_report_json(report, path_name);
  std::ifstream input(path_name);
  std::stringstream contents;
  contents << input.rdbuf();
  require_test(input.good() || input.eof(), "benchmark JSON was not readable");
  require_test(contents.str().find("\"online_total_bytes_mixed\": 26144") !=
                   std::string::npos,
               "JSON omitted exact online bytes");
  require_test(contents.str().find(
                   "\"paper_server_throughput_MBps\": 4096.007812") !=
                   std::string::npos,
               "JSON did not use database size for paper throughput");
  require_test(contents.str().find(
                   "\"paper_scan_throughput_MBps\": 98304.187500") !=
                   std::string::npos,
               "JSON omitted the repeated-scan diagnostic throughput");
  require_test(contents.str().find(
                   "\"warmup_leaf_indices\": [1, 2, 3]") !=
                   std::string::npos,
               "JSON omitted warm-up query IDs");
  require_test(contents.str().find(
                   "\"trial_leaf_indices\": [4, 5, 6, 7, 8]") !=
                   std::string::npos,
               "JSON omitted measured query IDs");
  // Publication gates reject invalid denominators, inconsistent wire counts,
  // and attempts to bypass the explicit 8 GB resource gate.
  bool rejected_zero_time = false;
  try {
    BenchmarkCaseResult invalid = result;
    invalid.timing.server_compute = BenchmarkDuration::zero();
    finalize_case_statistics(invalid);
  } catch (const std::invalid_argument &) {
    rejected_zero_time = true;
  }
  require_test(rejected_zero_time, "accepted a zero throughput denominator");

  bool rejected_count_mismatch = false;
  try {
    (void)communication_stats(reference, 2, {11264});
  } catch (const std::invalid_argument &) {
    rejected_count_mismatch = true;
  }
  require_test(rejected_count_mismatch,
               "accepted mismatched PIR call and response counts");

  MerkleBenchmarkOptions standard_only_options;
  standard_only_options.leaf_count = 256;
  standard_only_options.warmups = 0;
  standard_only_options.measured_trials = 1;
  standard_only_options.trial_seed = 0x7374616e64617264ULL;
  standard_only_options.case_selection =
      BenchmarkCaseSelection::standard_onionpir;
  const BenchmarkReport standard_only_report =
      run_merkle_benchmark_suite(standard_only_options);
  require_test(standard_only_report.cases.size() == 1,
               "standard-only benchmark executed extra cases");
  require_test(standard_only_report.cases.front().name ==
                   "standard_onionpir",
               "standard-only benchmark omitted the requested case");

  bool rejected_ungated_large_primary = false;
  try {
    MerkleBenchmarkOptions unsafe_options;
    unsafe_options.leaf_count = size_t{1} << 27;
    unsafe_options.warmups = 0;
    unsafe_options.measured_trials = 1;
    (void)run_merkle_benchmark_suite(unsafe_options);
  } catch (const std::invalid_argument &) {
    rejected_ungated_large_primary = true;
  }
  require_test(rejected_ungated_large_primary,
               "accepted an ungated 8 GB primary workload");
}
