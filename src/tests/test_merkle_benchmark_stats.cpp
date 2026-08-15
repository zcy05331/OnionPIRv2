#include "tests.h"
#include "merkle_benchmark.h"

#include <chrono>
#include <fstream>
#include <sstream>

void PirTest::test_merkle_benchmark_stats() {
  PirParams reference = PirParams().with_layout({349526, 10, true});
  require_test(reference.get_BFV_size(true) == 14880, "query bytes");
  require_test(modeled_helper_key_bytes(reference) == 1488000,
               "helper bytes");

  CommunicationStats standard =
      communication_stats(reference, 1, {11264});
  require_test(standard.online_total_bytes_mixed == 26144,
               "standard online");
  require_test(standard.first_session_total_bytes_mixed == 1514144,
               "standard first session");

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

  BenchmarkCaseResult result;
  result.name = "standard_onionpir";
  result.correctness_passed = true;
  result.communication = standard;
  result.raw_dataset_bytes = 1073741760;
  result.paper_plaintext_database_bytes = 1073743872;
  result.logical_padded_database_bytes = 1074266112;
  result.paper_plaintext_scan_bytes = 1073743872;
  result.logical_padded_scan_bytes = 1074266112;
  result.raw_application_scan_bytes = 1073743872;
  result.physical_preprocessed_storage_bytes = 5729419264;
  result.useful_response_bytes = 3072;
  result.timing.setup = std::chrono::milliseconds(12);
  result.timing.client_query = std::chrono::milliseconds(1);
  result.timing.server_compute = std::chrono::milliseconds(250);
  result.timing.response_serialize = std::chrono::milliseconds(2);
  result.timing.response_load_decrypt_extract = std::chrono::milliseconds(3);
  finalize_case_statistics(result);
  require_test(result.paper_server_throughput_MBps > 4095.0 &&
                   result.paper_server_throughput_MBps < 4097.0,
               "paper throughput denominator");

  BenchmarkReport report;
  report.schema_version = "1";
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
  require_test(contents.str().find("\"paper_server_throughput_MBps\"") !=
                   std::string::npos,
               "JSON omitted throughput field");

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
}
