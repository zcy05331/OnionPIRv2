#pragma once

#include "merkle_baseline.h"
#include "pir.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

using BenchmarkClock = std::chrono::steady_clock;
using BenchmarkDuration = std::chrono::nanoseconds;

struct TrialTiming {
  BenchmarkDuration setup{};
  BenchmarkDuration client_query{};
  BenchmarkDuration server_compute{};
  BenchmarkDuration response_serialize{};
  BenchmarkDuration response_load_decrypt_extract{};

  BenchmarkDuration local_online_pipeline() const;
};

struct CommunicationStats {
  uint64_t pir_call_count = 0;
  uint64_t modeled_query_bytes_per_pir = 0;
  uint64_t online_query_bytes_modeled = 0;
  uint64_t online_response_bytes_actual = 0;
  uint64_t online_total_bytes_mixed = 0;
  uint64_t helper_key_bytes_modeled = 0;
  uint64_t first_session_total_bytes_mixed = 0;
};

struct BenchmarkCaseResult {
  std::string name;
  bool correctness_passed = false;
  uint64_t raw_dataset_bytes = 0;
  uint64_t paper_plaintext_database_bytes = 0;
  uint64_t logical_padded_database_bytes = 0;
  uint64_t paper_plaintext_scan_bytes = 0;
  uint64_t logical_padded_scan_bytes = 0;
  uint64_t raw_application_scan_bytes = 0;
  uint64_t physical_preprocessed_storage_bytes = 0;
  TrialTiming timing;
  CommunicationStats communication;
  double paper_server_throughput_MBps = 0.0;
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
  bool hexl_enabled = false;
  std::string hexl_version;
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
  std::vector<MerklePath> measured_paths;
};

uint64_t modeled_helper_key_bytes(const PirParams &reference);
CommunicationStats communication_stats(
    const PirParams &reference, size_t pir_call_count,
    const std::vector<size_t> &actual_response_bytes);
void validate_matching_path_communication(const CommunicationStats &flat,
                                          const CommunicationStats &layerwise);
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
