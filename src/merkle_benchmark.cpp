#include "merkle_benchmark.h"

#include <cmath>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace {

uint64_t checked_add(uint64_t left, uint64_t right, const char *field) {
  if (left > std::numeric_limits<uint64_t>::max() - right) {
    throw std::overflow_error(std::string(field) + " overflows uint64_t");
  }
  return left + right;
}

uint64_t checked_multiply(uint64_t left, uint64_t right,
                          const char *field) {
  if (left != 0 && right > std::numeric_limits<uint64_t>::max() / left) {
    throw std::overflow_error(std::string(field) + " overflows uint64_t");
  }
  return left * right;
}

double milliseconds(BenchmarkDuration duration) {
  return std::chrono::duration<double, std::milli>(duration).count();
}

std::string json_escape(const std::string &value) {
  std::ostringstream escaped;
  for (unsigned char character : value) {
    switch (character) {
      case '"': escaped << "\\\""; break;
      case '\\': escaped << "\\\\"; break;
      case '\b': escaped << "\\b"; break;
      case '\f': escaped << "\\f"; break;
      case '\n': escaped << "\\n"; break;
      case '\r': escaped << "\\r"; break;
      case '\t': escaped << "\\t"; break;
      default:
        if (character < 0x20) {
          escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                  << static_cast<unsigned int>(character) << std::dec;
        } else {
          escaped << character;
        }
    }
  }
  return escaped.str();
}

void write_string(std::ostringstream &out, const std::string &value) {
  out << '"' << json_escape(value) << '"';
}

void write_string_array(std::ostringstream &out,
                        const std::vector<std::string> &values) {
  out << '[';
  for (size_t i = 0; i < values.size(); ++i) {
    if (i != 0) out << ", ";
    write_string(out, values[i]);
  }
  out << ']';
}

void write_integer_array(std::ostringstream &out,
                         const std::vector<uint64_t> &values) {
  out << '[';
  for (size_t i = 0; i < values.size(); ++i) {
    if (i != 0) out << ", ";
    out << values[i];
  }
  out << ']';
}

}  // namespace

BenchmarkDuration TrialTiming::local_online_pipeline() const {
  BenchmarkDuration total = client_query;
  if (BenchmarkDuration::max() - total < server_compute) {
    throw std::overflow_error("local online timing overflows");
  }
  total += server_compute;
  if (BenchmarkDuration::max() - total < response_serialize) {
    throw std::overflow_error("local online timing overflows");
  }
  total += response_serialize;
  if (BenchmarkDuration::max() - total < response_load_decrypt_extract) {
    throw std::overflow_error("local online timing overflows");
  }
  return total + response_load_decrypt_extract;
}

uint64_t modeled_helper_key_bytes(const PirParams &reference) {
  const uint64_t bv = reference.get_bv_galois_key_size(true);
  const uint64_t gsw = reference.get_gsw_key_size(true);
  return checked_add(bv, gsw, "modeled helper key bytes");
}

CommunicationStats communication_stats(
    const PirParams &reference, size_t pir_call_count,
    const std::vector<size_t> &actual_response_bytes) {
  if (pir_call_count == 0) {
    throw std::invalid_argument("PIR call count must be positive");
  }
  if (actual_response_bytes.size() != pir_call_count) {
    throw std::invalid_argument(
        "PIR call count does not match actual response count");
  }

  CommunicationStats result;
  result.pir_call_count = pir_call_count;
  result.modeled_query_bytes_per_pir = reference.get_BFV_size(true);
  result.online_query_bytes_modeled = checked_multiply(
      result.pir_call_count, result.modeled_query_bytes_per_pir,
      "modeled online query bytes");
  for (size_t bytes : actual_response_bytes) {
    result.online_response_bytes_actual = checked_add(
        result.online_response_bytes_actual, bytes,
        "actual online response bytes");
  }
  result.online_total_bytes_mixed = checked_add(
      result.online_query_bytes_modeled, result.online_response_bytes_actual,
      "mixed online bytes");
  result.helper_key_bytes_modeled = modeled_helper_key_bytes(reference);
  result.first_session_total_bytes_mixed = checked_add(
      result.helper_key_bytes_modeled, result.online_total_bytes_mixed,
      "mixed first-session bytes");
  return result;
}

void validate_matching_path_communication(const CommunicationStats &flat,
                                          const CommunicationStats &layerwise) {
  if (flat.pir_call_count != layerwise.pir_call_count ||
      flat.modeled_query_bytes_per_pir !=
          layerwise.modeled_query_bytes_per_pir ||
      flat.online_query_bytes_modeled !=
          layerwise.online_query_bytes_modeled ||
      flat.online_response_bytes_actual !=
          layerwise.online_response_bytes_actual ||
      flat.online_total_bytes_mixed != layerwise.online_total_bytes_mixed ||
      flat.helper_key_bytes_modeled != layerwise.helper_key_bytes_modeled ||
      flat.first_session_total_bytes_mixed !=
          layerwise.first_session_total_bytes_mixed) {
    throw std::invalid_argument(
        "Flat and layerwise paths have different communication totals");
  }
}

void finalize_case_statistics(BenchmarkCaseResult &result) {
  if (!result.correctness_passed) {
    throw std::invalid_argument(
        "Cannot publish throughput for a failed correctness case");
  }
  const double server_seconds =
      std::chrono::duration<double>(result.timing.server_compute).count();
  if (!(server_seconds > 0.0) || !std::isfinite(server_seconds)) {
    throw std::invalid_argument(
        "Server compute time must be a finite positive duration");
  }
  constexpr double bytes_per_mebibyte = static_cast<double>(uint64_t{1} << 20);
  result.paper_server_throughput_MBps =
      static_cast<double>(result.paper_plaintext_scan_bytes) /
      server_seconds / bytes_per_mebibyte;
  result.padded_scan_throughput_MBps =
      static_cast<double>(result.logical_padded_scan_bytes) /
      server_seconds / bytes_per_mebibyte;
  result.useful_response_throughput_Bps =
      static_cast<double>(result.useful_response_bytes) / server_seconds;
}

std::string benchmark_report_json(const BenchmarkReport &report) {
  std::ostringstream out;
  out << std::fixed << std::setprecision(6);
  out << "{\n  \"schema_version\": ";
  write_string(out, report.schema_version);

  const BenchmarkEnvironment &environment = report.environment;
  out << ",\n  \"environment\": {\n"
      << "    \"commit\": ";
  write_string(out, environment.commit);
  out << ",\n    \"branch\": ";
  write_string(out, environment.branch);
  out << ",\n    \"build_type\": ";
  write_string(out, environment.build_type);
  out << ",\n    \"config\": ";
  write_string(out, environment.config);
  out << ",\n    \"architecture\": ";
  write_string(out, environment.architecture);
  out << ",\n    \"hexl_enabled\": "
      << (environment.hexl_enabled ? "true" : "false")
      << ",\n    \"hexl_version\": ";
  write_string(out, environment.hexl_version);
  out << ",\n    \"rosetta\": " << (environment.rosetta ? "true" : "false")
      << ",\n    \"non_native_label\": ";
  write_string(out, environment.non_native_label);
  out << "\n  }";

  const PaperAlignment &paper = report.paper_alignment;
  out << ",\n  \"paper_alignment\": {\n    \"paper\": ";
  write_string(out, paper.paper);
  out << ",\n    \"revision\": ";
  write_string(out, paper.revision);
  out << ",\n    \"sections\": ";
  write_string_array(out, paper.sections);
  out << ",\n    \"poly_degree\": " << paper.poly_degree
      << ",\n    \"log_q\": " << paper.log_q
      << ",\n    \"log_t\": " << paper.log_t
      << ",\n    \"log_q_prime\": " << paper.log_q_prime
      << ",\n    \"L_KEY\": " << paper.L_KEY
      << ",\n    \"L_EP\": " << paper.L_EP
      << ",\n    \"L_KS\": " << paper.L_KS
      << ",\n    \"sigma\": " << paper.sigma
      << ",\n    \"estimated_security_bits\": "
      << paper.estimated_security_bits
      << ",\n    \"reference_hardware\": ";
  write_string(out, paper.reference_hardware);
  out << ",\n    \"local_result_is_hardware_replication\": "
      << (paper.local_result_is_hardware_replication ? "true" : "false")
      << "\n  }";

  const BenchmarkWorkload &workload = report.workload;
  out << ",\n  \"workload\": {\n"
      << "    \"leaf_count\": " << workload.leaf_count
      << ",\n    \"tree_height\": " << workload.tree_height
      << ",\n    \"node_bytes\": " << workload.node_bytes
      << ",\n    \"nodes_per_plaintext\": "
      << workload.nodes_per_plaintext
      << ",\n    \"paper_row\": ";
  write_string(out, workload.paper_row);
  out << ",\n    \"warmups\": " << workload.warmups
      << ",\n    \"measured_trials\": " << workload.measured_trials
      << ",\n    \"trial_leaf_indices\": ";
  write_integer_array(out, workload.trial_leaf_indices);
  out << ",\n    \"optional_workloads\": [";
  for (size_t i = 0; i < workload.optional_workloads.size(); ++i) {
    if (i != 0) out << ',';
    const OptionalWorkloadResult &optional = workload.optional_workloads[i];
    out << "\n      {\"leaf_count\": " << optional.leaf_count
        << ", \"tree_height\": " << optional.tree_height
        << ", \"paper_row\": ";
    write_string(out, optional.paper_row);
    out << ", \"status\": ";
    write_string(out, optional.status);
    out << ", \"skip_reason\": ";
    write_string(out, optional.skip_reason);
    out << '}';
  }
  if (!workload.optional_workloads.empty()) out << '\n' << "    ";
  out << "]\n  }";

  out << ",\n  \"cases\": [";
  for (size_t i = 0; i < report.cases.size(); ++i) {
    if (i != 0) out << ',';
    const BenchmarkCaseResult &result = report.cases[i];
    const CommunicationStats &communication = result.communication;
    out << "\n    {\n      \"name\": ";
    write_string(out, result.name);
    out << ",\n      \"correctness_passed\": "
        << (result.correctness_passed ? "true" : "false")
        << ",\n      \"pir_call_count\": " << communication.pir_call_count
        << ",\n      \"raw_dataset_bytes\": " << result.raw_dataset_bytes
        << ",\n      \"paper_plaintext_database_bytes\": "
        << result.paper_plaintext_database_bytes
        << ",\n      \"logical_padded_database_bytes\": "
        << result.logical_padded_database_bytes
        << ",\n      \"paper_plaintext_scan_bytes\": "
        << result.paper_plaintext_scan_bytes
        << ",\n      \"logical_padded_scan_bytes\": "
        << result.logical_padded_scan_bytes
        << ",\n      \"raw_application_scan_bytes\": "
        << result.raw_application_scan_bytes
        << ",\n      \"physical_preprocessed_storage_bytes\": "
        << result.physical_preprocessed_storage_bytes
        << ",\n      \"setup_ms\": " << milliseconds(result.timing.setup)
        << ",\n      \"client_query_ms\": "
        << milliseconds(result.timing.client_query)
        << ",\n      \"server_compute_ms\": "
        << milliseconds(result.timing.server_compute)
        << ",\n      \"response_serialize_ms\": "
        << milliseconds(result.timing.response_serialize)
        << ",\n      \"response_load_decrypt_extract_ms\": "
        << milliseconds(result.timing.response_load_decrypt_extract)
        << ",\n      \"local_online_pipeline_ms\": "
        << milliseconds(result.timing.local_online_pipeline())
        << ",\n      \"online_query_bytes_modeled\": "
        << communication.online_query_bytes_modeled
        << ",\n      \"online_response_bytes_actual\": "
        << communication.online_response_bytes_actual
        << ",\n      \"online_total_bytes_mixed\": "
        << communication.online_total_bytes_mixed
        << ",\n      \"helper_key_bytes_modeled\": "
        << communication.helper_key_bytes_modeled
        << ",\n      \"first_session_total_bytes_mixed\": "
        << communication.first_session_total_bytes_mixed
        << ",\n      \"paper_server_throughput_MBps\": "
        << result.paper_server_throughput_MBps
        << ",\n      \"padded_scan_throughput_MBps\": "
        << result.padded_scan_throughput_MBps
        << ",\n      \"useful_response_bytes\": "
        << result.useful_response_bytes
        << ",\n      \"useful_response_throughput_Bps\": "
        << result.useful_response_throughput_Bps << "\n    }";
  }
  if (!report.cases.empty()) out << '\n' << "  ";
  out << "]\n}\n";
  return out.str();
}

void write_benchmark_report_json(const BenchmarkReport &report,
                                 const std::string &path) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) {
    throw std::runtime_error("Failed to open benchmark JSON output: " + path);
  }
  output << benchmark_report_json(report);
  if (!output) {
    throw std::runtime_error("Failed to write benchmark JSON output: " + path);
  }
}
