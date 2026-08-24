#pragma once

#include "client.h"
#include "server.h"
#include "tree_index.h"
#include "tree_query.h"
#include "tree_select.h"

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

// Milestone-4 same-ring path packing and the end-to-end MVP answer path
// (blueprint secs 14-15). With g = 1 every projected level carries its node
// value in coefficient zero only, so one main-ring ciphertext holds up to n
// path nodes: chunk c packs its levels at coefficients 0..k_c-1 via public
// X^z monomial shifts and additions. The MVP performs no degree reduction,
// no small-ring key switch, no modulus switch, and no vectorization.

struct TreePathResponse {
  std::vector<RlweCt> chunks;  // ceil((L+1)/n) full-q main-ring ciphertexts
  size_t level_count = 0;      // L + 1 packed values, root first
};

// Chunk partition of `level_count` path slots under a per-chunk capacity:
// returns (first_level, size) per chunk. Split out so the no-overlap /
// no-wrap arithmetic is unit-testable with tiny capacities (sec. 21.8).
std::vector<std::pair<size_t, size_t>> path_chunk_bounds(size_t level_count,
                                                         size_t capacity);

// Algorithm 7 AnswerPathMVP: for every level run SelectLevel,
// PrivateRotateLevel, and ProjectRecord, then pack the projected nodes in
// root-to-leaf order. `server` supplies the CMux evaluator and must hold the
// client's session keys, whose BV coverage must reach max(h_q, r)
// substitution keys (create_session_keys(log2 n) provides this).
TreePathResponse answer_path_mvp(const std::vector<TreeLevelDatabase> &levels,
                                 const std::vector<LevelPlan> &plans,
                                 ExpandedTreeQuery &query, PirServer &server,
                                 size_t client_id, const TreePirParams &tree,
                                 const PirParams &scheme);

// Algorithm 8 ExtractPathMVP: decrypt every chunk under the original secret
// and read the L + 1 path values (mod t) in root-to-leaf order.
std::vector<uint64_t> extract_path_mvp(const TreePathResponse &response,
                                       PirClient &client,
                                       const TreePirParams &tree);
