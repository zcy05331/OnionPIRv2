#pragma once

#include "server.h"
#include "tree_index.h"
#include "tree_query.h"

#include <array>
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

// One packed level (sec. 6.1, generalized to g slots per node): R_l =
// 2^max(l-r,0) plaintexts. Record slot u of D_l[p] holds node
// M[l][p + u*R_l] in the STRIDED coefficients {u + j*rho : j in [0, g)} —
// the layout under which rotation by X^{-gamma_l} aligns every chunk of the
// target at once and projection depth min(r, l) keeps exactly the multiples
// of rho where those chunks live. g = 1 reduces to plaintexts[p][u].
struct TreeLevelDatabase {
  size_t level = 0;
  size_t R = 0;
  // Coefficient-form polynomials over Z_t, each of length n.
  std::vector<std::vector<uint64_t>> plaintexts;
};

// Node oracle for g = 1: value of M[level][index], already reduced mod t.
using TreeNodeSource = std::function<uint64_t(size_t level, size_t index)>;
// General node oracle: chunk j (of g) of M[level][index], reduced mod t.
using TreeNodeChunkSource =
    std::function<uint64_t(size_t level, size_t index, size_t chunk)>;

// Deterministic synthetic node value (sec. 18): a fixed-constant SplitMix64
// mix of (level, index) reduced mod t. Benchmark/test oracle only, not a
// cryptographic hash.
uint64_t synthetic_tree_node_value(size_t level, size_t index, uint64_t t);

// Deterministic synthetic 32-byte node (the real-scenario payload) and its
// little-endian chunk decomposition at the scheme's slot capacity of
// floor(log2(t)) bits: chunk j carries bits [w*j, w*(j+1)) of the 256-bit
// value and bits past the end read as zero (12-bit chunks -> 22 occupied of
// g = 32; 39-bit chunks -> 7 occupied of g = 8).
std::array<uint8_t, 32> synthetic_tree_node_bytes(size_t level, size_t index);
uint64_t synthetic_tree_node_bytes_chunk(size_t level, size_t index,
                                         size_t chunk, uint64_t t);

// Algorithm 2 PreprocessTreeReference for one level / all levels 0..L.
// The TreeNodeSource overloads require g = 1; the chunk overloads accept
// any validated g.
TreeLevelDatabase pack_tree_level(size_t level, const TreePirParams &tree,
                                  const TreeNodeSource &source);
TreeLevelDatabase pack_tree_level(size_t level, const TreePirParams &tree,
                                  const TreeNodeChunkSource &source);
std::vector<TreeLevelDatabase> preprocess_tree_reference(
    const TreePirParams &tree, const TreeNodeSource &source);
std::vector<TreeLevelDatabase> preprocess_tree_reference(
    const TreePirParams &tree, const TreeNodeChunkSource &source);

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

// ---- Milestone-6 optimized view (sec. 6.3 steps 1-2) ----
// Every packed plaintext lifted to each RNS limb and NTT-transformed once at
// preprocessing time, so per-query first-dimension work becomes pointwise
// products plus one inverse transform per candidate. The protocol semantics
// do not depend on this representation: mod-q arithmetic is exact, so the
// optimized outputs are bit-identical to the scalar reference path.
struct TreeLevelDatabaseNtt {
  size_t level = 0;
  size_t R = 0;
  std::vector<std::vector<uint64_t>> plaintexts;  // K*N values, limb-major
};
TreeLevelDatabaseNtt build_level_ntt_view(const TreeLevelDatabase &db,
                                          const PirParams &scheme);

// Milestone-6 full kernel view (composite configurations only): the level's
// NTT values split into the two 32-bit CRT limbs of the composite modulus and
// laid out level-major/row-major for matrix.h's level_mat_mat_32 —
// data[(coeff * rows + row) * cols + col] where row indexes the candidate
// (delta for AlphaBeta, the single output otherwise) and col indexes the
// selection vector entry. Mathematically identical to the u64 pointwise
// path: split, 32x32->64 matmul per limb, CRT-compose, one inverse NTT.
struct TreeLevelDatabaseM32 {
  size_t level = 0;
  size_t R = 0;
  size_t rows = 0;  // candidates
  size_t cols = 0;  // selection width
  std::vector<uint32_t> lo, hi;  // n * rows * cols each
};
TreeLevelDatabaseM32 build_level_m32_view(const TreeLevelDatabase &db,
                                          const LevelPlan &plan,
                                          const TreePirParams &tree,
                                          const PirParams &scheme);

// Canonical + optimized views plus the public plans, bundled for the answer
// path (blueprint sec. 19 PreprocessedTree). When the scheme's composite
// first-dimension split is enabled, preprocess_tree_mvp builds the m32 view
// and leaves `ntt` empty (the two views are the same size; keeping both
// would double memory); otherwise it builds `ntt` and leaves `m32` empty.
struct PreprocessedTree {
  std::vector<TreeLevelDatabase> canonical;
  std::vector<TreeLevelDatabaseNtt> ntt;
  std::vector<TreeLevelDatabaseM32> m32;
  std::vector<LevelPlan> plans;
};
PreprocessedTree preprocess_tree_mvp(const TreePirParams &tree,
                                     const TreeNodeSource &source,
                                     const PirParams &scheme);
PreprocessedTree preprocess_tree_mvp(const TreePirParams &tree,
                                     const TreeNodeChunkSource &source,
                                     const PirParams &scheme);

// Forward-transform every pyramid ciphertext once per query so all levels
// can consume NTT-domain products.
AlphaPyramid pyramid_to_ntt(const AlphaPyramid &pyramid,
                            const PirParams &scheme);

// Optimized SelectLevel: identical ring arithmetic to select_level over the
// NTT view; consumes the NTT-form pyramid and returns a coefficient-form
// candidate exactly equal to the scalar path's output.
RlweCt select_level_ntt(const TreeLevelDatabaseNtt &db, const LevelPlan &plan,
                        const AlphaPyramid &pyramid_ntt,
                        std::span<GSWCt> beta_selectors, PirServer &mux,
                        const TreePirParams &tree, const PirParams &scheme);

// Per-query CRT-limb split of the NTT-form pyramid in the kernel's B layout
// (data[(coeff * cols + col) * 2 + component]), built once and shared by
// every level.
struct AlphaPyramidM32 {
  std::vector<std::vector<uint32_t>> lo, hi;  // one buffer per pyramid row
};
AlphaPyramidM32 pyramid_to_m32(const AlphaPyramid &pyramid_ntt,
                               const PirParams &scheme);

// Milestone-6 full kernel: the same selection over the m32 view via
// level_mat_mat_32 (32x32->64 with delayed reduction per CRT limb), CRT
// composition, and one inverse NTT per candidate. Output is bit-identical
// to both other paths. Composite configurations only.
RlweCt select_level_m32(const TreeLevelDatabaseM32 &db, const LevelPlan &plan,
                        const AlphaPyramidM32 &pyramid_m32,
                        std::span<GSWCt> beta_selectors, PirServer &mux,
                        const TreePirParams &tree, const PirParams &scheme);
