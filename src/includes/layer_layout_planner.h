#pragma once

#include "merkle_baseline.h"
#include "pir.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// Runtime-aware planner for the Merkle layerwise baseline. Planning is split
// into (1) legal candidate enumeration per public level, (2) exact feature
// extraction and Pareto filtering, and (3) policy-based selection. The
// `legacy_padding` policy is the unchanged padding-first planner; `profiled`
// consumes an offline JSON profile of measured per-candidate server times and
// picks the fastest legal layout per level under a global padded-storage
// budget. Every input is public (workload, scheme, machine profile): no
// choice depends on the queried leaf or on ciphertext contents.

enum class LayerLayoutPolicy {
  legacy_padding,
  profiled,
};

// Exact, public work counters of one legal layout (see the identities in
// test_layer_layout_planner).
struct LayerLayoutFeatures {
  size_t expansion_height = 0;
  size_t first_dim_size = 0;
  size_t other_dim_size = 0;
  size_t other_dim_count = 0;
  size_t padded_plaintexts = 0;
  size_t padding_plaintexts = 0;
  size_t useful_expanded_ciphertexts = 0;
  size_t expansion_substitutions = 0;
  size_t first_dim_query_ntts = 0;
  size_t selector_rows_to_complete = 0;
  size_t crt_coefficients_to_compose = 0;
  size_t inverse_ntts = 0;
  size_t cmux_count = 0;
  uint64_t logical_padded_bytes = 0;
  uint64_t physical_scan_bytes = 0;
};

struct LayerLayoutCandidate {
  LayerLayout layout;
  LayerLayoutFeatures features;
};

// Number of Galois substitutions fast_expand_qry performs for `useful` leaves
// under expansion height `height` (right-of-useful subtrees are pruned).
size_t count_pruned_expansion_substitutions(size_t useful, size_t height);

LayerLayoutFeatures compute_layer_layout_features(const PirParams &params);

// Every scheme-compatible layout of one level with at most the reference's
// remaining-dimension count, sorted by (expansion_height, first_dim_size,
// other_dim_size). Expansion heights are unique, so the order is by height.
std::vector<LayerLayoutCandidate> enumerate_layer_layout_candidates(
    size_t level, size_t nodes_per_pt, const PirParams &reference);

// Index of the candidate the legacy padding-first planner picks.
size_t legacy_layer_layout_candidate(
    const std::vector<LayerLayoutCandidate> &candidates);

// Pareto frontier over physical_scan_bytes, expansion_substitutions,
// first_dim_query_ntts, selector_rows_to_complete, inverse_ntts, cmux_count.
// Padding is a budget, not a domination axis.
std::vector<LayerLayoutCandidate> pareto_layer_layout_candidates(
    const std::vector<LayerLayoutCandidate> &candidates);

// ---------------------------------------------------------------------------
// Offline machine profile
// ---------------------------------------------------------------------------

// Everything a profile must agree on with the process that consumes it.
struct LayerLayoutProfileEnvironment {
  std::string commit;
  std::string build_type;
  std::string config;
  std::string cpu;
  std::string architecture;
  std::string compiler;
  std::string hexl_version;
  size_t poly_degree = 0;
  size_t log_q = 0;
  size_t log_t = 0;
  size_t log_q_prime = 0;
  size_t l_ep = 0;
  size_t l_key = 0;
  size_t l_ks = 0;
  bool composite_first_dim = false;
};

struct LayerLayoutMeasurement {
  size_t level = 0;
  LayerLayoutFeatures features;
  std::vector<double> server_samples_ms;
  double median_server_ms = 0.0;
  bool dominated = false;
};

struct LayerLayoutProfile {
  std::string schema_version = "layer-layout-profile-v1";
  LayerLayoutProfileEnvironment environment;
  size_t tree_height = 0;
  size_t nodes_per_plaintext = 0;
  size_t warmups = 0;
  size_t measured_trials = 0;
  uint64_t trial_seed = 0;
  double padding_budget = 1.01;
  uint64_t legacy_total_padded_plaintexts = 0;
  uint64_t selected_total_padded_plaintexts = 0;
  std::vector<LayerLayoutMeasurement> measurements;
  std::vector<size_t> selected_expansion_heights;  // index = level - 1
};

// Detects the running machine/toolchain and copies the scheme fields.
LayerLayoutProfileEnvironment detect_layer_layout_environment(
    const PirParams &reference, const std::string &commit,
    const std::string &build_type, const std::string &config);

// Atomic write (<path>.tmp then rename) and strict read of the profile JSON.
void save_layer_layout_profile(const LayerLayoutProfile &profile,
                               const std::string &path);
LayerLayoutProfile load_layer_layout_profile(const std::string &path);

// Empty string when the profile can drive this runtime; otherwise the first
// mismatching field, spelled out.
std::string describe_layer_layout_profile_mismatch(
    const LayerLayoutProfile &profile,
    const LayerLayoutProfileEnvironment &runtime, size_t tree_height,
    size_t nodes_per_pt);

// Result of choosing one measured candidate per level.
struct LayerLayoutSelection {
  std::vector<size_t> expansion_heights;  // index = level - 1
  uint64_t legacy_total_padded_plaintexts = 0;
  uint64_t selected_total_padded_plaintexts = 0;
  double predicted_legacy_ms = 0.0;    // sum of measured legacy medians
  double predicted_selected_ms = 0.0;  // sum of selected medians
};

// Minimises the sum of per-level median server times subject to
// total padded plaintexts <= legacy total * padding_budget, by dynamic
// programming over levels and excess padded plaintexts. Candidates whose
// medians are within 2% are ordered by (physical_scan_bytes,
// expansion_substitutions, inverse_ntts, expansion_height) so noise cannot buy
// negligible speed with extra storage. Levels without measurements (or whose
// whole level fits one plaintext) keep the legacy layout.
LayerLayoutSelection select_layer_layouts(const LayerLayoutProfile &profile,
                                          size_t tree_height,
                                          size_t nodes_per_pt,
                                          const PirParams &reference,
                                          double padding_budget);

struct LayerPlannerConfig {
  LayerLayoutPolicy policy = LayerLayoutPolicy::legacy_padding;
  double total_padding_budget = 1.01;
  std::shared_ptr<const LayerLayoutProfile> profile;
  // On a profile/runtime mismatch: fall back to legacy instead of throwing.
  bool allow_profile_fallback = false;
};

// Policy-aware planner. legacy_padding delegates to the unchanged
// plan_layer_layouts(tree_height, nodes_per_pt, reference); profiled selects
// from config.profile after validating it against the running environment.
// When used_fallback is given it reports whether a profiled request ended up
// with the legacy plan through config.allow_profile_fallback, so callers can
// record the policy that was actually applied.
std::vector<LayerLayout> plan_layer_layouts(size_t tree_height,
                                            size_t nodes_per_pt,
                                            const PirParams &reference,
                                            const LayerPlannerConfig &config,
                                            bool *used_fallback = nullptr);

const char *layer_layout_policy_name(LayerLayoutPolicy policy);
