#pragma once

#include "server.h"
#include "tree_index.h"
#include "tree_query.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>

// Milestone-2 per-level selection (blueprint sec. 6, 10, 11). Everything here
// is the scalar/reference path: canonical coefficient-form level databases,
// plain PtCtMul + CtAdd loops for the alpha dimension, and one-external-
// product CMux folds for beta. The optimized NTT/matrix kernel is a later
// drop-in replacement behind the same interfaces (sec. 6.3, Milestone 6).

// One packed level (sec. 6.1): R_l = 2^max(l-r,0) plaintexts, where
// plaintexts[p][u] = M[l][p + u*R_l] for p + u*R_l < 2^l and zero elsewhere.
// For l >= r every polynomial carries exactly n nodes; above level r the
// single polynomial holds the 2^l nodes in coefficients [0, 2^l).
struct TreeLevelDatabase {
  size_t level = 0;
  size_t R = 0;
  // Coefficient-form polynomials over Z_t, each of length n.
  std::vector<std::vector<uint64_t>> plaintexts;
};

// Node oracle: value of M[level][index], already reduced mod t.
using TreeNodeSource = std::function<uint64_t(size_t level, size_t index)>;

// Deterministic synthetic node value (sec. 18): a fixed-constant SplitMix64
// mix of (level, index) reduced mod t. Benchmark/test oracle only, not a
// cryptographic hash.
uint64_t synthetic_tree_node_value(size_t level, size_t index, uint64_t t);

// Algorithm 2 PreprocessTreeReference for one level / all levels 0..L.
TreeLevelDatabase pack_tree_level(size_t level, const TreePirParams &tree,
                                  const TreeNodeSource &source);
std::vector<TreeLevelDatabase> preprocess_tree_reference(
    const TreePirParams &tree, const TreeNodeSource &source);

// Reference BFV plaintext-ciphertext product: negacyclic poly multiplication
// of a Z_t polynomial into both ciphertext components under every RNS limb.
// Input and output are coefficient-form full-q ciphertexts.
RlweCt tree_pt_ct_mul(const std::vector<uint64_t> &pt, const RlweCt &ct,
                      const PirParams &scheme);

// Coarsened alpha pyramid (sec. 10): pyramid[c][j] encrypts
// [floor(alpha / 2^c) == j], built from the expanded one-hot by ciphertext
// additions only. pyramid[0] is A^(0) (size N0); pyramid[a][0] encrypts 1.
using AlphaPyramid = std::vector<std::vector<RlweCt>>;
AlphaPyramid build_alpha_pyramid(std::span<const RlweCt> alpha_cts,
                                 const TreePirParams &tree,
                                 const PirParams &scheme);

// AlphaBeta first dimension (sec. 11.2): Y[delta] = sum_k D_l[k, delta] *
// A^(0)_k over the sec. 6.2 matrix view D_l[k, delta] = D_l[k * 2^d + delta],
// with d = plan.beta_count. Returns the 2^d candidates in ordinary integer
// order of delta.
std::vector<RlweCt> evaluate_alpha_dimension(const TreeLevelDatabase &db,
                                             std::span<const RlweCt> alpha,
                                             const LevelPlan &plan,
                                             const TreePirParams &tree,
                                             const PirParams &scheme);

// Beta fold (sec. 11.3 step 4.5): consume the active bits
// beta_{b-1}, ..., beta_{begin} in MSB-first order, halving the candidate
// array with CMux(S^beta_u, lower, upper) each step. `beta_selectors` is the
// full b-length selector array indexed by global bit position; `mux` provides
// the repository's one-external-product CMux and must be scheme-compatible.
// An LSB-first consumption order selects the wrong pairing pattern.
RlweCt fold_beta_dimension(std::vector<RlweCt> candidates,
                           const LevelPlan &plan,
                           std::span<GSWCt> beta_selectors, PirServer &mux);

// Algorithm 4 SelectLevel: returns C_l encrypting D_l[p_l] under the three
// mutually exclusive plan cases (Single / CoarsenedAlpha / AlphaBeta). Every
// branch and loop count depends only on the public plan; private values enter
// only through the pyramid and selectors.
RlweCt select_level(const TreeLevelDatabase &db, const LevelPlan &plan,
                    const AlphaPyramid &pyramid,
                    std::span<GSWCt> beta_selectors, PirServer &mux,
                    const TreePirParams &tree, const PirParams &scheme);
