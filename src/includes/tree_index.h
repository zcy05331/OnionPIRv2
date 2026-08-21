#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

// Full-binary-tree PIR (gamma, alpha, beta) indexing layer. This header is
// pure arithmetic: no ring, key, or ciphertext dependency, so index identities
// can be exhausted on tiny synthetic configurations (blueprint sec. 25) that
// the fixed scheme ring could never instantiate.
//
// Coordinate model (blueprint sec. 3/5; draft paper sec. 3.1/3.3). The tree has
// N = 2^L leaves; level 0 is the root and level L holds the leaves. With g = 1
// each node is one Z_t scalar, rho = n/g = n records fit one plaintext, and
//   P = N / rho,  B = P / N0 = 2^b,  b = L - r - a,  r = log2 n,  N0 = 2^a.
// A leaf index i splits into gamma = floor(i/P) (the packed-record coordinate),
// then p = i mod P splits into alpha = floor(p/B) and beta = p mod B (the
// plaintext-selection coordinates). Only (alpha, beta bits, gamma bits) enter
// query generation; per-level values stay server-side derivable from public
// plans plus these encrypted coordinates.

struct TreePirParams {
  // Tree shape.
  size_t N = 0;   // leaf count, 2^L
  size_t L = 0;   // tree height; levels are 0..L inclusive
  // Ring/packing shape.
  size_t n = 0;    // ring degree (records per plaintext when g = 1)
  size_t g = 1;    // Z_t slots per node; the MVP freezes g = 1
  size_t rho = 0;  // n / g
  size_t r = 0;    // log2(rho)
  // First-dimension / beta split.
  size_t N0 = 0;  // first-dimension size, 2^a
  size_t a = 0;   // log2(N0)
  size_t P = 0;   // N / rho: plaintexts on the leaf level
  size_t B = 0;   // P / N0 = 2^b
  size_t b = 0;   // L - r - a beta selector bits
  // Packed-query layout.
  size_t ell_beta = 0;   // gadget rows per beta bit
  size_t ell_gamma = 0;  // gadget rows per gamma bit
  size_t w = 0;          // N0 + ell_beta*b + ell_gamma*r logical constants
  size_t h_q = 0;        // ceil(log2 w) expansion height
  size_t W = 0;          // 2^h_q expansion capacity
  // Scheme bindings. rns_moduli may be empty for pure index-math
  // configurations, but t must always be odd so W stays invertible mod t.
  uint64_t t = 0;                       // plaintext modulus
  std::vector<uint64_t> rns_moduli;     // full-q RNS limbs
  size_t response_degree = 0;           // MVP: same ring, n2 = n
  std::vector<uint64_t> response_moduli;  // MVP: q2 = q
};

// Derive every dependent field from (L, a) plus the ring/scheme inputs, then
// run validate_tree_params. There is no padding fallback: incompatible shapes
// throw instead of silently changing N, L, or node numbering.
TreePirParams make_tree_pir_params(size_t L, size_t a, size_t n,
                                   size_t ell_beta, size_t ell_gamma,
                                   uint64_t t,
                                   std::vector<uint64_t> rns_moduli);

// Blueprint sec. 3.2 hard validation. Throws std::invalid_argument on the
// first violated constraint; returns normally iff the whole set holds.
void validate_tree_params(const TreePirParams &params);

// Private query-side coordinates. This is the only index-derived structure
// that may feed query generation; level plans below are public and the oracle
// is test-only.
struct ClientCoordinates {
  size_t alpha = 0;
  std::vector<uint8_t> beta_bits_le;   // beta_bits_le[u] = bit u of beta
  std::vector<uint8_t> gamma_bits_le;  // gamma_bits_le[v] = bit v of gamma
};

enum class SelectCase {
  Single,          // R_l = 1: no alpha/beta selection remains
  CoarsenedAlpha,  // 1 < R_l < N0: one-hot for floor(alpha / 2^coarsen_count)
  AlphaBeta,       // R_l >= N0: full alpha one-hot plus beta_count folds
};

// Public per-level plan. Every field depends only on public parameters and the
// level, never on a query, so the server may branch on it freely.
struct LevelPlan {
  size_t level = 0;
  size_t R = 0;  // packed plaintexts on this level: 2^max(level - r, 0)

  SelectCase select_case = SelectCase::Single;
  size_t coarsen_count = 0;  // a - log2(R) pyramid steps (Single: full a)

  size_t beta_begin = 0;  // inclusive little-endian bit index; empty => b
  size_t beta_count = 0;  // folded in descending index order (MSB-first)

  size_t gamma_begin = 0;  // inclusive little-endian bit index
  size_t gamma_count = 0;

  size_t projection_depth = 0;  // min(r, level)
};

// Test-only target metadata (blueprint sec. 5.6). node_index is j_l; the node
// lives in packed plaintext D_l[packed_plaintext_index] at coefficient
// record_position, i.e. j_l = record_position * R_l + packed_plaintext_index.
// Never serialized and never accepted by production server entry points.
struct LevelOracle {
  size_t node_index = 0;
  size_t packed_plaintext_index = 0;  // p_l
  size_t record_position = 0;         // gamma_l
};

// Algorithm 1 ClientIndex: decompose one leaf into query coordinates.
ClientCoordinates client_index(size_t leaf, const TreePirParams &params);

// One public plan per level 0..L (L+1 entries).
std::vector<LevelPlan> build_level_plans(const TreePirParams &params);

// Test-only oracle for one (leaf, level).
LevelOracle build_level_oracle_for_test(size_t leaf, size_t level,
                                        const TreePirParams &params);

// Invariant 2 (blueprint sec. 16): reconstruct the level record position p_l
// from the shared (alpha, beta) coordinates alone. Defined for levels with
// level >= r; the same formula also yields the coarsened one-hot index
// floor(alpha / 2^c) on CoarsenedAlpha levels.
size_t level_record_position_from_coordinates(size_t alpha, size_t beta,
                                              size_t level,
                                              const TreePirParams &params);
