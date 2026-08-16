#include "merkle_benchmark.h"

#include "client.h"
#include "server.h"
#include "utils.h"

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>

#if defined(__APPLE__)
#include <sys/sysctl.h>
#else
#include <unistd.h>
#endif

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
  // The paper-defined metric uses the plaintext database footprint once. The
  // separate scan diagnostics below may count repeated passes (H for flat) and
  // therefore measure kernel scan efficiency rather than path throughput.
  result.paper_server_throughput_MBps =
      static_cast<double>(result.paper_plaintext_database_bytes) /
      server_seconds / bytes_per_mebibyte;
  result.paper_scan_throughput_MBps =
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
  out << ",\n    \"process_architecture\": ";
  write_string(out, environment.process_architecture);
  out << ",\n    \"operating_system\": ";
  write_string(out, environment.operating_system);
  out << ",\n    \"cpu\": ";
  write_string(out, environment.cpu);
  out << ",\n    \"compiler\": ";
  write_string(out, environment.compiler);
  out << ",\n    \"cmake_version\": ";
  write_string(out, environment.cmake_version);
  out << ",\n    \"hexl_enabled\": "
      << (environment.hexl_enabled ? "true" : "false")
      << ",\n    \"hexl_version\": ";
  write_string(out, environment.hexl_version);
  out << ",\n    \"hexl_path\": ";
  write_string(out, environment.hexl_path);
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
      << ",\n    \"trial_seed\": " << workload.trial_seed
      << ",\n    \"warmup_leaf_indices\": ";
  write_integer_array(out, workload.warmup_leaf_indices);
  out << ",\n    \"trial_leaf_indices\": ";
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
        << ",\n      \"paper_scan_throughput_MBps\": "
        << result.paper_scan_throughput_MBps
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

namespace {

struct PirCallOutput {
  TrialTiming timing;
  size_t response_bytes = 0;
  RlwePt plaintext;
  std::optional<MerkleNode> node;
};

struct PathTrialOutput {
  TrialTiming timing;
  std::vector<size_t> response_bytes;
  MerklePath path;
};

size_t flat_target_num_pt(const MerkleWorkload &workload) {
  if (workload.tree_height == 0 ||
      workload.tree_height >= std::numeric_limits<size_t>::digits - 1 ||
      workload.leaf_count != (size_t{1} << workload.tree_height) ||
      workload.node_bytes != sizeof(MerkleNode)) {
    throw std::invalid_argument("Invalid Merkle benchmark workload");
  }
  const size_t node_count = 2 * (workload.leaf_count - 1);
  return utils::roundup_div(node_count, size_t{96});
}

void validate_trial_plan(const MerkleWorkload &workload,
                         const PirParams &reference,
                         const BenchmarkTrialPlan &trials) {
  const size_t target_num_pt = flat_target_num_pt(workload);
  if (reference.get_target_num_pt() != target_num_pt) {
    throw std::invalid_argument(
        "Reference layout target does not match the flat Merkle database");
  }
  if (reference.get_pt_size() != 96 * sizeof(MerkleNode)) {
    throw std::invalid_argument(
        "Merkle benchmark requires 96 nodes per v2 plaintext");
  }
  if (trials.measured_leaf_indices.empty()) {
    throw std::invalid_argument("At least one measured trial is required");
  }
  auto validate_leaf = [&](size_t leaf) {
    if (leaf >= workload.leaf_count) {
      throw std::invalid_argument("Benchmark leaf index is out of range");
    }
  };
  for (size_t leaf : trials.warmup_leaf_indices) validate_leaf(leaf);
  for (size_t leaf : trials.measured_leaf_indices) validate_leaf(leaf);
}

RlwePt standard_plaintext(size_t index, const PirParams &params) {
  RlwePt plaintext;
  plaintext.data.resize(params.get_poly_degree());
  for (size_t coefficient = 0; coefficient < plaintext.data.size();
       ++coefficient) {
    plaintext.data[coefficient] =
        (17 * index + 3 * coefficient + 11) % params.get_plain_mod();
  }
  return plaintext;
}

BenchmarkDuration elapsed_since(BenchmarkClock::time_point start) {
  return std::chrono::duration_cast<BenchmarkDuration>(
      BenchmarkClock::now() - start);
}

PirCallOutput timed_pir_call(PirClient &client,
                             const PirParams &query_params,
                             PirServer &server, size_t client_id,
                             size_t plaintext_index,
                             std::optional<size_t> node_offset) {
  PirCallOutput output;

  // All cases use identical timer boundaries. Callers perform oracle/path
  // comparison after this function so correctness work is outside the timer.
  auto start = BenchmarkClock::now();
  RlweCt query =
      client.fast_generate_query(query_params, plaintext_index);
  output.timing.client_query = elapsed_since(start);

  start = BenchmarkClock::now();
  RlweCt response = server.make_query(client_id, query);
  output.timing.server_compute = elapsed_since(start);

  std::stringstream response_stream;
  start = BenchmarkClock::now();
  output.response_bytes =
      server.save_resp_to_stream(response, response_stream);
  output.timing.response_serialize = elapsed_since(start);

  start = BenchmarkClock::now();
  RlweCt reconstructed = client.load_resp_from_stream(response_stream);
  output.plaintext = client.decrypt_mod_q(reconstructed);
  if (node_offset.has_value()) {
    output.node =
        decode_merkle_node(output.plaintext, *node_offset, query_params);
  }
  output.timing.response_load_decrypt_extract = elapsed_since(start);
  return output;
}

void add_online_timing(TrialTiming &total, const TrialTiming &sample) {
  total.client_query += sample.client_query;
  total.server_compute += sample.server_compute;
  total.response_serialize += sample.response_serialize;
  total.response_load_decrypt_extract +=
      sample.response_load_decrypt_extract;
}

TrialTiming average_online_timing(const TrialTiming &total, size_t count) {
  if (count == 0) {
    throw std::invalid_argument("Cannot average zero benchmark trials");
  }
  TrialTiming average;
  average.client_query = total.client_query / count;
  average.server_compute = total.server_compute / count;
  average.response_serialize = total.response_serialize / count;
  average.response_load_decrypt_extract =
      total.response_load_decrypt_extract / count;
  return average;
}

uint64_t raw_merkle_bytes(const MerkleWorkload &workload) {
  const uint64_t nodes = 2 * (static_cast<uint64_t>(workload.leaf_count) - 1);
  return checked_multiply(nodes, workload.node_bytes,
                          "raw Merkle database bytes");
}

uint64_t physical_database_bytes(const PirParams &params) {
  const uint64_t coefficients = checked_multiply(
      params.get_num_pt(), params.get_coeff_val_cnt(),
      "preprocessed database coefficients");
  return checked_multiply(coefficients, sizeof(db_coeff_t),
                          "physical preprocessed database bytes");
}

void populate_reference_database_metadata(BenchmarkCaseResult &result,
                                          const MerkleWorkload &workload,
                                          const PirParams &reference) {
  const uint64_t target_num_pt = flat_target_num_pt(workload);
  const uint64_t plaintext_bytes = reference.get_pt_size();
  result.raw_dataset_bytes = raw_merkle_bytes(workload);
  result.paper_plaintext_database_bytes = checked_multiply(
      target_num_pt, plaintext_bytes, "paper plaintext database bytes");
  result.logical_padded_database_bytes = checked_multiply(
      reference.get_num_pt(), plaintext_bytes,
      "logical padded database bytes");
  result.physical_preprocessed_storage_bytes =
      physical_database_bytes(reference);
}

void require_response_shape(const std::vector<size_t> &expected,
                            const std::vector<size_t> &actual) {
  if (expected != actual) {
    throw std::runtime_error(
        "Actual response byte count changed between measured trials");
  }
}

}  // namespace

BenchmarkCaseExecution run_standard_case(
    const MerkleWorkload &workload, const PirParams &reference,
    const BenchmarkTrialPlan &trials) {
  validate_trial_plan(workload, reference, trials);

  const auto setup_start = BenchmarkClock::now();
  PirClient client(reference);
  SharedPirSessionKeys keys = client.create_session_keys();
  PirServer server(reference);
  server.set_client_session_keys(client.get_client_id(), keys);
  PlaintextSource source = [&](size_t index, RlwePt &out) {
    out = standard_plaintext(index, reference);
  };
  server.load_data(reference.get_target_num_pt(), source);
  const BenchmarkDuration setup_time = elapsed_since(setup_start);

  auto run_trial = [&](size_t leaf) {
    const size_t plaintext_index =
        leaf % reference.get_target_num_pt();
    PirCallOutput output = timed_pir_call(
        client, reference, server, client.get_client_id(), plaintext_index,
        std::nullopt);
    const RlwePt expected = standard_plaintext(plaintext_index, reference);
    if (!utils::plaintext_is_equal(output.plaintext, expected)) {
      throw std::runtime_error("Standard OnionPIR deterministic mismatch");
    }
    return output;
  };

  for (size_t leaf : trials.warmup_leaf_indices) {
    (void)run_trial(leaf);
  }

  TrialTiming timing_total;
  std::vector<size_t> response_shape;
  for (size_t leaf : trials.measured_leaf_indices) {
    PirCallOutput output = run_trial(leaf);
    add_online_timing(timing_total, output.timing);
    const std::vector<size_t> current_shape{output.response_bytes};
    if (response_shape.empty()) {
      response_shape = current_shape;
    } else {
      require_response_shape(response_shape, current_shape);
    }
  }

  BenchmarkCaseExecution execution;
  BenchmarkCaseResult &result = execution.result;
  result.name = "standard_onionpir";
  result.correctness_passed = true;
  populate_reference_database_metadata(result, workload, reference);
  result.paper_plaintext_scan_bytes =
      result.paper_plaintext_database_bytes;
  result.logical_padded_scan_bytes =
      result.logical_padded_database_bytes;
  result.raw_application_scan_bytes =
      result.paper_plaintext_database_bytes;
  result.useful_response_bytes = reference.get_pt_size();
  result.timing = average_online_timing(
      timing_total, trials.measured_leaf_indices.size());
  result.timing.setup = setup_time;
  result.communication = communication_stats(reference, 1, response_shape);
  finalize_case_statistics(result);
  return execution;
}

BenchmarkCaseExecution run_merkle_flat_case(
    const MerkleWorkload &workload, const PirParams &reference,
    const BenchmarkTrialPlan &trials) {
  validate_trial_plan(workload, reference, trials);

  const auto setup_start = BenchmarkClock::now();
  PirClient client(reference);
  SharedPirSessionKeys keys = client.create_session_keys();
  PirServer server(reference);
  server.set_client_session_keys(client.get_client_id(), keys);
  PlaintextSource source = [&](size_t index, RlwePt &out) {
    out = make_flat_merkle_plaintext(index, workload, reference);
  };
  server.load_data(reference.get_target_num_pt(), source);
  const BenchmarkDuration setup_time = elapsed_since(setup_start);

  auto run_trial = [&](size_t leaf) {
    PathTrialOutput trial;
    trial.response_bytes.reserve(workload.tree_height);
    trial.path.reserve(workload.tree_height);
    // One independent PIR over the complete flat tree per path level; only the
    // selected breadth-first ordinal changes between calls.
    for (size_t level = workload.tree_height; level >= 1; --level) {
      const size_t local =
          merkle_sibling_local(leaf, workload.tree_height, level);
      const size_t ordinal = merkle_flat_ordinal(level, local);
      const size_t plaintext_index = ordinal / 96;
      const size_t node_offset = ordinal % 96;
      PirCallOutput output = timed_pir_call(
          client, reference, server, client.get_client_id(), plaintext_index,
          node_offset);
      add_online_timing(trial.timing, output.timing);
      trial.response_bytes.push_back(output.response_bytes);
      const MerkleNode expected = synthetic_merkle_node(level, local);
      if (!output.node.has_value() || *output.node != expected) {
        throw std::runtime_error("Flat Merkle PIR node mismatch");
      }
      trial.path.push_back(*output.node);
      if (level == 1) break;
    }
    return trial;
  };

  for (size_t leaf : trials.warmup_leaf_indices) {
    (void)run_trial(leaf);
  }

  TrialTiming timing_total;
  std::vector<size_t> response_shape;
  BenchmarkCaseExecution execution;
  for (size_t leaf : trials.measured_leaf_indices) {
    PathTrialOutput trial = run_trial(leaf);
    add_online_timing(timing_total, trial.timing);
    if (response_shape.empty()) {
      response_shape = trial.response_bytes;
    } else {
      require_response_shape(response_shape, trial.response_bytes);
    }
    execution.measured_paths.push_back(std::move(trial.path));
  }

  BenchmarkCaseResult &result = execution.result;
  result.name = "merkle_flat";
  result.correctness_passed = true;
  populate_reference_database_metadata(result, workload, reference);
  // The database footprint remains one flat tree for paper throughput. Scan
  // diagnostics multiply by H because the complete-path trial reads that same
  // database H times; server_compute likewise sums all H calls.
  result.paper_plaintext_scan_bytes = checked_multiply(
      result.paper_plaintext_database_bytes, workload.tree_height,
      "flat paper plaintext scan bytes");
  result.logical_padded_scan_bytes = checked_multiply(
      result.logical_padded_database_bytes, workload.tree_height,
      "flat padded scan bytes");
  result.raw_application_scan_bytes = checked_multiply(
      result.raw_dataset_bytes, workload.tree_height,
      "flat raw application scan bytes");
  result.useful_response_bytes = checked_multiply(
      workload.tree_height, workload.node_bytes,
      "flat useful response bytes");
  result.timing = average_online_timing(
      timing_total, trials.measured_leaf_indices.size());
  result.timing.setup = setup_time;
  result.communication = communication_stats(
      reference, workload.tree_height, response_shape);
  finalize_case_statistics(result);
  return execution;
}

BenchmarkCaseExecution run_merkle_layerwise_case(
    const MerkleWorkload &workload, const PirParams &reference,
    const BenchmarkTrialPlan &trials) {
  validate_trial_plan(workload, reference, trials);

  const auto setup_start = BenchmarkClock::now();
  std::vector<LayerLayout> layouts =
      plan_layer_layouts(workload.tree_height, 96, reference);
  PirClient client(reference);
  SharedPirSessionKeys keys = client.create_session_keys();
  std::vector<std::unique_ptr<PirServer>> servers;
  servers.reserve(layouts.size());
  // Each level gets its own minimal shape, but every server points to the same
  // immutable scheme-level helper-key allocation.
  for (const LayerLayout &layout : layouts) {
    auto server = std::make_unique<PirServer>(layout.params);
    server->set_client_session_keys(client.get_client_id(), keys);
    if (server->client_session_keys(client.get_client_id()).get() != keys.get()) {
      throw std::runtime_error("Layer server copied the shared key bundle");
    }
    PlaintextSource source = [&](size_t index, RlwePt &out) {
      out = make_layer_merkle_plaintext(layout.level, index, workload,
                                        layout.params);
    };
    server->load_data(layout.target_num_pt, source);
    servers.push_back(std::move(server));
  }
  const BenchmarkDuration setup_time = elapsed_since(setup_start);

  auto run_trial = [&](size_t leaf) {
    PathTrialOutput trial;
    trial.response_bytes.reserve(workload.tree_height);
    trial.path.reserve(workload.tree_height);
    // Still H independent PIR calls, but call l contains only the 2^l nodes of
    // that level instead of another copy of the full flattened tree.
    for (size_t level = workload.tree_height; level >= 1; --level) {
      const LayerLayout &layout = layouts.at(level - 1);
      const size_t local =
          merkle_sibling_local(leaf, workload.tree_height, level);
      const size_t plaintext_index = local / 96;
      const size_t node_offset = local % 96;
      PirCallOutput output = timed_pir_call(
          client, layout.params, *servers.at(level - 1),
          client.get_client_id(), plaintext_index, node_offset);
      add_online_timing(trial.timing, output.timing);
      trial.response_bytes.push_back(output.response_bytes);
      const MerkleNode expected = synthetic_merkle_node(level, local);
      if (!output.node.has_value() || *output.node != expected) {
        throw std::runtime_error("Layerwise Merkle PIR node mismatch");
      }
      trial.path.push_back(*output.node);
      if (level == 1) break;
    }
    return trial;
  };

  for (size_t leaf : trials.warmup_leaf_indices) {
    (void)run_trial(leaf);
  }

  TrialTiming timing_total;
  std::vector<size_t> response_shape;
  BenchmarkCaseExecution execution;
  for (size_t leaf : trials.measured_leaf_indices) {
    PathTrialOutput trial = run_trial(leaf);
    add_online_timing(timing_total, trial.timing);
    if (response_shape.empty()) {
      response_shape = trial.response_bytes;
    } else {
      require_response_shape(response_shape, trial.response_bytes);
    }
    execution.measured_paths.push_back(std::move(trial.path));
  }

  BenchmarkCaseResult &result = execution.result;
  result.name = "merkle_layerwise";
  result.correctness_passed = true;
  result.raw_dataset_bytes = raw_merkle_bytes(workload);
  // The stored plaintext database is the sum of all disjoint level databases.
  // Each is scanned once per path, so database and scan bytes coincide here.
  for (const LayerLayout &layout : layouts) {
    result.paper_plaintext_database_bytes = checked_add(
        result.paper_plaintext_database_bytes,
        checked_multiply(layout.target_num_pt, layout.params.get_pt_size(),
                         "layer paper plaintext database bytes"),
        "layer paper plaintext database total");
    result.logical_padded_database_bytes = checked_add(
        result.logical_padded_database_bytes,
        checked_multiply(layout.params.get_num_pt(),
                         layout.params.get_pt_size(),
                         "layer padded database bytes"),
        "layer padded database total");
    result.physical_preprocessed_storage_bytes = checked_add(
        result.physical_preprocessed_storage_bytes,
        physical_database_bytes(layout.params),
        "layer physical database total");
    result.raw_application_scan_bytes = checked_add(
        result.raw_application_scan_bytes,
        checked_multiply(layout.node_count, workload.node_bytes,
                         "layer raw application bytes"),
        "layer raw application total");
  }
  result.paper_plaintext_scan_bytes =
      result.paper_plaintext_database_bytes;
  result.logical_padded_scan_bytes =
      result.logical_padded_database_bytes;
  result.useful_response_bytes = checked_multiply(
      workload.tree_height, workload.node_bytes,
      "layer useful response bytes");
  result.timing = average_online_timing(
      timing_total, trials.measured_leaf_indices.size());
  result.timing.setup = setup_time;
  result.communication = communication_stats(
      reference, workload.tree_height, response_shape);
  finalize_case_statistics(result);
  return execution;
}

namespace {

std::string environment_value(const char *name,
                              const std::string &fallback = "") {
  const char *value = std::getenv(name);
  return value == nullptr ? fallback : std::string(value);
}

uint64_t splitmix64_next(uint64_t &state) {
  state += 0x9e3779b97f4a7c15ULL;
  uint64_t value = state;
  value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
  value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
  return value ^ (value >> 31);
}

MerkleWorkload make_benchmark_workload(size_t leaf_count) {
  if (leaf_count < 2 || !std::has_single_bit(leaf_count)) {
    throw std::invalid_argument(
        "Merkle benchmark leaf count must be a power of two >= 2");
  }
  return {leaf_count,
          static_cast<size_t>(std::bit_width(leaf_count) - 1), 32};
}

PirParams make_benchmark_reference(const MerkleWorkload &workload) {
  PirParams scheme;
  if (scheme.get_poly_degree() != 2048 || scheme.get_ct_mod_width() != 58 ||
      scheme.get_num_bits_per_coeff() != 12 || scheme.get_l() != 6 ||
      scheme.get_l_key() != 10 || DBConsts::L_KS != 8 ||
      std::bit_width(scheme.get_small_q() - 1) != 22 ||
      scheme.get_noise_std_dev() != 2.55) {
    throw std::invalid_argument(
        "Merkle benchmarks require CONFIG_N2048_K1_COMP v2 parameters");
  }

  const size_t target_num_pt = flat_target_num_pt(workload);
  if (workload.leaf_count >= (size_t{1} << 24)) {
    return scheme.with_layout({target_num_pt, 10, true});
  }
  for (size_t height = 0; height <= 10; ++height) {
    try {
      return scheme.with_layout({target_num_pt, height, true});
    } catch (const std::runtime_error &) {
      // Try the next expansion height.
    }
  }
  throw std::runtime_error("No v2 reference layout for benchmark workload");
}

std::vector<BenchmarkCaseResult> execute_case_set(
    const MerkleWorkload &workload, const PirParams &reference,
    const BenchmarkTrialPlan &trials, BenchmarkCaseSelection selection,
    const std::string &name_suffix = "") {
  BenchmarkCaseExecution standard =
      run_standard_case(workload, reference, trials);
  standard.result.name += name_suffix;

  // Return before constructing either Merkle-path database. This makes a
  // Standard-only repetition independent of the flat/layerwise setup costs.
  if (selection == BenchmarkCaseSelection::standard_onionpir) {
    return {std::move(standard.result)};
  }
  if (selection != BenchmarkCaseSelection::all) {
    throw std::invalid_argument("Unknown benchmark case selection");
  }

  BenchmarkCaseExecution flat =
      run_merkle_flat_case(workload, reference, trials);
  BenchmarkCaseExecution layerwise =
      run_merkle_layerwise_case(workload, reference, trials);
  validate_matching_path_communication(flat.result.communication,
                                       layerwise.result.communication);
  if (flat.measured_paths != layerwise.measured_paths) {
    throw std::runtime_error(
        "Flat and layerwise measured Merkle paths differ");
  }
  flat.result.name += name_suffix;
  layerwise.result.name += name_suffix;
  return {std::move(standard.result), std::move(flat.result),
          std::move(layerwise.result)};
}

uint64_t detected_physical_memory_bytes() {
#if defined(__APPLE__)
  uint64_t bytes = 0;
  size_t length = sizeof(bytes);
  if (sysctlbyname("hw.memsize", &bytes, &length, nullptr, 0) == 0) {
    return bytes;
  }
  return 0;
#else
  const long pages = sysconf(_SC_PHYS_PAGES);
  const long page_size = sysconf(_SC_PAGESIZE);
  if (pages <= 0 || page_size <= 0) return 0;
  return checked_multiply(static_cast<uint64_t>(pages),
                          static_cast<uint64_t>(page_size),
                          "detected physical memory");
#endif
}

bool running_under_rosetta() {
#if defined(__APPLE__) && defined(__x86_64__)
  int translated = 0;
  size_t length = sizeof(translated);
  return sysctlbyname("sysctl.proc_translated", &translated, &length,
                      nullptr, 0) == 0 && translated == 1;
#else
  return false;
#endif
}

std::string paper_row_for(const MerkleWorkload &workload) {
  if (workload.leaf_count == (size_t{1} << 24)) return "1 GB";
  if (workload.leaf_count == (size_t{1} << 27)) return "8 GB";
  return "custom";
}

void append_case_set(std::vector<BenchmarkCaseResult> &destination,
                     std::vector<BenchmarkCaseResult> source) {
  destination.insert(destination.end(),
                     std::make_move_iterator(source.begin()),
                     std::make_move_iterator(source.end()));
}

}  // namespace

BenchmarkTrialPlan make_benchmark_trial_plan(size_t leaf_count, size_t warmups,
                                             size_t measured, uint64_t seed) {
  if (leaf_count == 0) {
    throw std::invalid_argument(
        "Merkle benchmark requires at least one query ID");
  }
  if (measured == 0) {
    throw std::invalid_argument(
        "Merkle benchmark requires at least one measured trial");
  }
  if (warmups > leaf_count || measured > leaf_count - warmups) {
    throw std::invalid_argument(
        "Merkle benchmark requires distinct query IDs for every trial");
  }

  const size_t query_count = warmups + measured;
  std::vector<size_t> selected;
  selected.reserve(query_count);
  uint64_t state = seed;

  // Floyd's algorithm samples without replacement in O(query_count^2) space
  // independent of the database size. query_count is only 8 in the frozen
  // benchmark, so the linear membership check is both bounded and explicit.
  for (size_t offset = 0; offset < query_count; ++offset) {
    const size_t upper = leaf_count - query_count + offset;
    const size_t candidate =
        static_cast<size_t>(splitmix64_next(state) % (upper + 1));
    selected.push_back(std::find(selected.begin(), selected.end(), candidate) ==
                               selected.end()
                           ? candidate
                           : upper);
  }

  BenchmarkTrialPlan plan;
  plan.warmup_leaf_indices.assign(selected.begin(),
                                  selected.begin() + warmups);
  plan.measured_leaf_indices.assign(selected.begin() + warmups,
                                    selected.end());
  return plan;
}

uint64_t estimate_merkle_benchmark_peak_bytes(size_t leaf_count) {
  const MerkleWorkload workload = make_benchmark_workload(leaf_count);
  const PirParams reference = make_benchmark_reference(workload);
  const uint64_t flat_bytes = physical_database_bytes(reference);
  const std::vector<LayerLayout> layouts =
      plan_layer_layouts(workload.tree_height, 96, reference);
  uint64_t layerwise_bytes = 0;
  for (const LayerLayout &layout : layouts) {
    layerwise_bytes = checked_add(layerwise_bytes,
                                  physical_database_bytes(layout.params),
                                  "layerwise peak bytes");
  }
  return std::max(flat_bytes, layerwise_bytes);
}

BenchmarkReport run_merkle_benchmark_suite(
    const MerkleBenchmarkOptions &options) {
  if (options.leaf_count > (size_t{1} << 24)) {
    throw std::invalid_argument(
        "Primary Merkle benchmark is capped at 2^24 leaves; request the "
        "resource-gated 2^27 workload with --run-optional-8gb");
  }
  const MerkleWorkload workload =
      make_benchmark_workload(options.leaf_count);
  const PirParams reference = make_benchmark_reference(workload);
  const BenchmarkTrialPlan trials = make_benchmark_trial_plan(
      workload.leaf_count, options.warmups, options.measured_trials,
      options.trial_seed);

  BenchmarkReport report;
  // v2 corrects paper_server_throughput_MBps to database_bytes/server_time and
  // retains repeated work as the explicit paper_scan_throughput diagnostic.
  report.schema_version = "onionpir-merkle-baselines-v2";
  report.environment.commit = environment_value("ONIONPIR_BENCH_COMMIT");
  report.environment.branch = environment_value("ONIONPIR_BENCH_BRANCH");
  report.environment.build_type = "Benchmark";
  report.environment.config = "CONFIG_N2048_K1_COMP";
#if defined(__x86_64__)
  report.environment.architecture = "x86_64";
#elif defined(__aarch64__) || defined(__arm64__)
  report.environment.architecture = "arm64";
#else
  report.environment.architecture = "unknown";
#endif
  report.environment.process_architecture =
      environment_value("ONIONPIR_BENCH_PROCESS_ARCH", "x86_64");
  report.environment.operating_system =
      environment_value("ONIONPIR_BENCH_OS");
  report.environment.cpu = environment_value("ONIONPIR_BENCH_CPU");
  report.environment.compiler =
      environment_value("ONIONPIR_BENCH_COMPILER");
  report.environment.cmake_version =
      environment_value("ONIONPIR_BENCH_CMAKE");
#if defined(ONIONPIR_USE_HEXL)
  report.environment.hexl_enabled = true;
#else
  report.environment.hexl_enabled = false;
#endif
  report.environment.hexl_version = "1.2.6";
  report.environment.hexl_path = environment_value("ONIONPIR_BENCH_HEXL_PATH");
  report.environment.rosetta = running_under_rosetta();
  report.environment.non_native_label = report.environment.rosetta
      ? "x86_64 + Intel HEXL under Rosetta 2 on Apple M4; non-native result"
      : "This run is not the frozen Apple M4 Rosetta benchmark environment";

  report.paper_alignment.paper =
      "OnionPIRv2: Efficient Single-Server PIR (2025/1142)";
  report.paper_alignment.revision = "2025-1142.pdf";
  report.paper_alignment.sections = {"4.1", "4.2", "4.3"};
  report.paper_alignment.poly_degree = 2048;
  report.paper_alignment.log_q = 58;
  report.paper_alignment.log_t = 13;
  report.paper_alignment.log_q_prime = 22;
  report.paper_alignment.L_KEY = 10;
  report.paper_alignment.L_EP = 6;
  report.paper_alignment.L_KS = 8;
  report.paper_alignment.sigma = 2.55;
  report.paper_alignment.estimated_security_bits = 117;
  report.paper_alignment.reference_hardware =
      "Intel Xeon Platinum 8358 2.60 GHz, Ubuntu 22.04, AVX-512";
  report.paper_alignment.local_result_is_hardware_replication = false;

  report.workload.leaf_count = workload.leaf_count;
  report.workload.tree_height = workload.tree_height;
  report.workload.node_bytes = workload.node_bytes;
  report.workload.nodes_per_plaintext = 96;
  report.workload.paper_row = paper_row_for(workload);
  report.workload.warmups = options.warmups;
  report.workload.measured_trials = options.measured_trials;
  report.workload.trial_seed = options.trial_seed;
  report.workload.warmup_leaf_indices.assign(
      trials.warmup_leaf_indices.begin(), trials.warmup_leaf_indices.end());
  report.workload.trial_leaf_indices.assign(
      trials.measured_leaf_indices.begin(), trials.measured_leaf_indices.end());

  append_case_set(report.cases,
                  execute_case_set(workload, reference, trials,
                                   options.case_selection));

  OptionalWorkloadResult optional;
  optional.leaf_count = size_t{1} << 27;
  optional.tree_height = 27;
  optional.paper_row = "8 GB";
  if (workload.leaf_count == optional.leaf_count) {
    optional.status = "primary_workload";
  } else if (!options.run_optional_8gb) {
    optional.status = "not_requested";
    optional.skip_reason = "optional 8 GB run flag was not set";
  } else {
    const uint64_t estimated =
        estimate_merkle_benchmark_peak_bytes(optional.leaf_count);
    const uint64_t physical_memory = detected_physical_memory_bytes();
    constexpr uint64_t safety_margin = uint64_t{2} << 30;
    if (physical_memory == 0 ||
        estimated > physical_memory ||
        safety_margin > physical_memory - estimated) {
      optional.status = "skipped_resource_limit";
      optional.skip_reason =
          "estimated peak " + std::to_string(estimated) +
          " bytes plus 2147483648-byte safety margin exceeds detected " +
          std::to_string(physical_memory) + " bytes";
    } else {
      optional.status = "completed";
      const MerkleWorkload optional_workload =
          make_benchmark_workload(optional.leaf_count);
      const PirParams optional_reference =
          make_benchmark_reference(optional_workload);
      const BenchmarkTrialPlan optional_trials = make_benchmark_trial_plan(
          optional_workload.leaf_count, options.warmups,
          options.measured_trials,
          options.trial_seed ^ 0x8b47424950524952ULL);
      append_case_set(
          report.cases,
          execute_case_set(optional_workload, optional_reference,
                           optional_trials, options.case_selection,
                           "_optional_8gb"));
    }
  }
  report.workload.optional_workloads.push_back(std::move(optional));
  return report;
}

void print_benchmark_report(const BenchmarkReport &report) {
  std::cout << report.environment.non_native_label << '\n';
  std::cout << "case,correct,server_ms,paper_MBps,paper_scan_MBps,"
               "padded_scan_MBps,online_bytes,first_session_bytes\n";
  for (const BenchmarkCaseResult &result : report.cases) {
    std::cout << result.name << ','
              << (result.correctness_passed ? "true" : "false") << ','
              << milliseconds(result.timing.server_compute) << ','
              << result.paper_server_throughput_MBps << ','
              << result.paper_scan_throughput_MBps << ','
              << result.padded_scan_throughput_MBps << ','
              << result.communication.online_total_bytes_mixed << ','
              << result.communication.first_session_total_bytes_mixed
              << '\n';
  }
  for (const OptionalWorkloadResult &optional :
       report.workload.optional_workloads) {
    std::cout << "optional " << optional.paper_row << ": " << optional.status;
    if (!optional.skip_reason.empty()) {
      std::cout << " (" << optional.skip_reason << ')';
    }
    std::cout << '\n';
  }
}
