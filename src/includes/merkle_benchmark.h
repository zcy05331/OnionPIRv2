#pragma once

#include "merkle_baseline.h"
#include "pir.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

using BenchmarkClock = std::chrono::steady_clock;
using BenchmarkDuration = std::chrono::nanoseconds;

struct TrialTiming {
  // setup is offline. The remaining fields partition one local online trial;
  // they intentionally exclude network transport latency.
  BenchmarkDuration setup{};
  BenchmarkDuration client_query{};
  BenchmarkDuration server_compute{};
  BenchmarkDuration response_serialize{};
  BenchmarkDuration response_load_decrypt_extract{};

  BenchmarkDuration local_online_pipeline() const;
};

struct CommunicationStats {
  // Query/helper sizes are seed-compressed protocol models. Response bytes are
  // read from the real serializer, hence totals containing both are "mixed".
  uint64_t pir_call_count = 0;
  uint64_t modeled_query_bytes_per_pir = 0;
  uint64_t online_query_bytes_modeled = 0;
  uint64_t online_response_bytes_actual = 0;
  uint64_t online_total_bytes_mixed = 0;
  uint64_t helper_key_bytes_modeled = 0;
  uint64_t first_session_total_bytes_mixed = 0;
};

struct MetricSampleStatistics {
  uint64_t count = 0;
  double mean = 0.0;
  double population_variance = 0.0;
  double population_standard_deviation = 0.0;
  std::optional<double> sample_variance;
  std::optional<double> sample_standard_deviation;
};

struct BenchmarkCaseResult {
  std::string name;
  bool correctness_passed = false;
  uint64_t raw_dataset_bytes = 0;
  // "database" is the plaintext footprint stored by one case. "scan" counts
  // all passes made during one reported trial: H passes over the same flat
  // database versus one pass over each of H level databases.
  uint64_t paper_plaintext_database_bytes = 0;
  uint64_t logical_padded_database_bytes = 0;
  uint64_t paper_plaintext_scan_bytes = 0;
  uint64_t logical_padded_scan_bytes = 0;
  uint64_t raw_application_scan_bytes = 0;
  uint64_t physical_preprocessed_storage_bytes = 0;
  TrialTiming timing;
  CommunicationStats communication;
  // Raw measured samples make means and variance independently auditable.
  // Warm-up trials are intentionally excluded from both vectors.
  std::vector<double> server_compute_samples_ms;
  std::optional<MetricSampleStatistics> server_compute_ms_statistics;
  // Paper definition: plaintext database bytes / full-case server time. For a
  // Merkle case, full-case time retrieves the complete H-node path.
  double paper_server_throughput_MBps = 0.0;
  std::vector<double> paper_server_throughput_samples_MBps;
  std::optional<MetricSampleStatistics>
      paper_server_throughput_MBps_statistics;
  // Diagnostics below charge every repeated database pass. They explain
  // kernel efficiency but are not end-to-end Merkle throughput. All _MBps
  // fields use the repository convention 1 MB = 2^20 bytes (MiB/s).
  double paper_scan_throughput_MBps = 0.0;
  double padded_scan_throughput_MBps = 0.0;
  uint64_t useful_response_bytes = 0;
  double useful_response_throughput_Bps = 0.0;
};

struct BenchmarkEnvironment {
  std::string commit;
  std::string branch;
  std::string build_type;
  std::string config;
  std::string architecture;
  std::string process_architecture;
  std::string operating_system;
  std::string cpu;
  std::string compiler;
  std::string cmake_version;
  bool hexl_enabled = false;
  std::string hexl_version;
  std::string hexl_path;
  bool rosetta = false;
  std::string non_native_label;
};

struct PaperAlignment {
  std::string paper;
  std::string revision;
  std::vector<std::string> sections;
  uint64_t poly_degree = 0;
  uint64_t log_q = 0;
  uint64_t log_t = 0;
  uint64_t log_q_prime = 0;
  uint64_t L_KEY = 0;
  uint64_t L_EP = 0;
  uint64_t L_KS = 0;
  double sigma = 0.0;
  double estimated_security_bits = 0.0;
  std::string reference_hardware;
  bool local_result_is_hardware_replication = false;
};

struct OptionalWorkloadResult {
  uint64_t leaf_count = 0;
  uint64_t tree_height = 0;
  std::string paper_row;
  std::string status;
  std::string skip_reason;
};

struct BenchmarkWorkload {
  uint64_t leaf_count = 0;
  uint64_t tree_height = 0;
  uint64_t node_bytes = 0;
  uint64_t nodes_per_plaintext = 0;
  std::string paper_row;
  uint64_t warmups = 0;
  uint64_t measured_trials = 0;
  uint64_t trial_seed = 0;
  std::vector<uint64_t> warmup_leaf_indices;
  std::vector<uint64_t> trial_leaf_indices;
  std::vector<OptionalWorkloadResult> optional_workloads;
};

struct BenchmarkReport {
  std::string schema_version;
  BenchmarkEnvironment environment;
  PaperAlignment paper_alignment;
  BenchmarkWorkload workload;
  std::vector<BenchmarkCaseResult> cases;
};

using MerklePath = std::vector<MerkleNode>;

struct BenchmarkTrialPlan {
  std::vector<size_t> warmup_leaf_indices;
  std::vector<size_t> measured_leaf_indices;
};

struct BenchmarkCaseExecution {
  BenchmarkCaseResult result;
  // Correctness evidence only. Oracle comparisons occur outside timed regions.
  std::vector<MerklePath> measured_paths;
};

enum class BenchmarkCaseSelection {
  all,
  standard_onionpir,
  merkle_paths,
  merkle_layerwise,
};

struct MerkleBenchmarkOptions {
  size_t leaf_count = size_t{1} << 24;
  size_t warmups = 3;
  size_t measured_trials = 5;
  uint64_t trial_seed = 0x4f6e696f6e504952ULL;
  bool run_optional_8gb = false;
  BenchmarkCaseSelection case_selection = BenchmarkCaseSelection::all;
};

// Deterministically samples query IDs without replacement. Keeping the plan
// public lets tests and benchmark artifacts verify the exact query schedule.
BenchmarkTrialPlan make_benchmark_trial_plan(size_t leaf_count, size_t warmups,
                                             size_t measured, uint64_t seed);

uint64_t modeled_helper_key_bytes(const PirParams &reference);
CommunicationStats communication_stats(
    const PirParams &reference, size_t pir_call_count,
    const std::vector<size_t> &actual_response_bytes);
void validate_matching_path_communication(const CommunicationStats &flat,
                                          const CommunicationStats &layerwise);
MetricSampleStatistics summarize_metric_samples(
    const std::vector<double> &samples);
void finalize_case_statistics(BenchmarkCaseResult &result);

std::string benchmark_report_json(const BenchmarkReport &report);
void write_benchmark_report_json(const BenchmarkReport &report,
                                 const std::string &path);

BenchmarkCaseExecution run_standard_case(
    const MerkleWorkload &workload, const PirParams &reference,
    const BenchmarkTrialPlan &trials);
BenchmarkCaseExecution run_merkle_flat_case(
    const MerkleWorkload &workload, const PirParams &reference,
    const BenchmarkTrialPlan &trials);
BenchmarkCaseExecution run_merkle_layerwise_case(
    const MerkleWorkload &workload, const PirParams &reference,
    const BenchmarkTrialPlan &trials);

BenchmarkReport run_merkle_benchmark_suite(
    const MerkleBenchmarkOptions &options);
void print_benchmark_report(const BenchmarkReport &report);
uint64_t estimate_merkle_benchmark_peak_bytes(size_t leaf_count);
