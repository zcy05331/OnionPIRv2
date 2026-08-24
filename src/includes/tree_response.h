#pragma once

#include "client.h"
#include "server.h"
#include "tree_compress.h"
#include "tree_index.h"
#include "tree_query.h"
#include "tree_select.h"

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

// Milestone-4 same-ring path packing and the end-to-end MVP answer path
// (blueprint secs 14-15, generalized to g slots per node). Every projected
// level carries its node's g chunks in the stride-rho coefficients
// {j * rho : j < g} and nothing else, so one main-ring ciphertext holds up
// to rho path nodes: slot z packs level z's chunks at {z + j * rho} via a
// public X^z monomial shift, and distinct slots occupy distinct residues
// mod rho — no overlap, no wrap. The MVP performs no degree reduction, no
// small-ring key switch, and no vectorization.

struct TreePathResponse {
  std::vector<RlweCt> chunks;  // ceil((L+1)/rho) main-ring ciphertexts
  size_t level_count = 0;      // L + 1 packed values, root first
  // Public per-level slot offset inside its chunk: level l's chunk j lives
  // at coefficient level_offsets[l] + j * rho. The sequential packer uses
  // the in-chunk position; keeping the map explicit lets future packers
  // choose other public placements without touching extraction.
  std::vector<size_t> level_offsets;
  // Milestone 5: whether the final same-ring modulus switch to small q was
  // applied (it is whenever the configuration defines a narrower small q).
  bool small_q = false;
};

// Chunk partition of `level_count` path slots under a per-chunk capacity:
// returns (first_level, size) per chunk. Split out so the no-overlap /
// no-wrap arithmetic is unit-testable with tiny capacities (sec. 21.8).
std::vector<std::pair<size_t, size_t>> path_chunk_bounds(size_t level_count,
                                                         size_t capacity);

// Algorithm 7 AnswerPathMVP: for every level run SelectLevel (over the
// Milestone-6 NTT view), PrivateRotateLevel, and ProjectRecord, pack the
// projected nodes in root-to-leaf order, and finish each chunk with the
// Milestone-5 same-ring modulus switch. `server` supplies the CMux evaluator
// and the modulus switch, and must hold the client's session keys, whose BV
// coverage must reach max(h_q, r) substitution keys
// (create_session_keys(log2 n) provides this).
// Note on fused projection+packing: three cross-level fusion schedules
// (fine-to-coarse pair merging, direct CDKS PackLWEs, and packing before a
// shared gamma rotation) were derived and each proved unsound for stride-rho
// multi-chunk payloads — ghost terms, placement aliasing, and on-lattice
// junk collisions respectively. Amortizing the per-level rotation/projection
// switches needs an encrypted-offset projection primitive that does not
// exist in this stack, so the packer stays sequential.
TreePathResponse answer_path_mvp(const PreprocessedTree &db,
                                 ExpandedTreeQuery &query, PirServer &server,
                                 size_t client_id, const TreePirParams &tree,
                                 const PirParams &scheme);

// Milestone-7 answer path: identical per-level pipeline, but the packer
// places level z at offset 2z (the sec. 23.4 alignment: the whole payload
// lands on the even sublattice), skips the big-ring modulus switch, and
// hands the full-q response to the d = 2 ring switch. Requires a single
// chunk with 2 * (L + 1) - 2 < rho and the client's registered ring-switch
// keys; the response shrinks from 2 n log q2 to 2 (n/2) log q2 bits.
CompressedPathResponse answer_path_compressed(
    const PreprocessedTree &db, ExpandedTreeQuery &query, PirServer &server,
    size_t client_id, const TreePirParams &tree, const PirParams &scheme,
    const TreeRingSwitchKeys &keys);

// Algorithm 8 ExtractPathMVP: decrypt every chunk under the original secret
// (small-q decryption when the Milestone-5 switch ran) and read the path in
// root-to-leaf order. The chunked form returns g coefficient values per
// level (level slot z, chunk j at coefficient z + j * rho); the flat form
// is the g = 1 view.
std::vector<std::vector<uint64_t>> extract_path_chunks_mvp(
    const TreePathResponse &response, PirClient &client,
    const TreePirParams &tree);
std::vector<uint64_t> extract_path_mvp(const TreePathResponse &response,
                                       PirClient &client,
                                       const TreePirParams &tree);
