#include "merkle_benchmark.h"

#include "client.h"
#include "server.h"
#include "utils.h"

#include <algorithm>
#include <bit>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <limits>
#include <memory>
#include <optional>
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
