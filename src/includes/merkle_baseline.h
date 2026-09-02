#pragma once

#include "pir.h"
#include "rlwe.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

using MerkleNode = std::array<uint8_t, 32>;

// Levels use root=0 and leaves=tree_height. An authentication path contains
// one sibling from every level H..1; the root is absent from both baselines.
struct MerkleWorkload {
  size_t leaf_count;
  size_t tree_height;
  size_t node_bytes;
};

// Minimal per-level database shape. params changes layout only and remains
// scheme-compatible with the reference so all levels can share helper keys.
struct LayerLayout {
  size_t level;
  size_t node_count;
  size_t target_num_pt;
  PirParams params;
  // A level whose node_count fits one plaintext is handed to the client in
  // the clear instead of being served by PIR: sending the whole level reveals
  // nothing about which node is wanted, and it costs node_count * 32 bytes
  // instead of a query plus a ciphertext response.
  bool direct_return = false;
};

// Return a level-local sibling index, not a global heap index.
size_t merkle_sibling_local(size_t leaf, size_t tree_height, size_t level);
// Breadth-first ordinal in the root-excluded flat database; ordinal 0 is the
// left node at level 1.
size_t merkle_flat_ordinal(size_t level, size_t local_index);

// Deterministic benchmark oracle, not a cryptographic Merkle hash. Stable
// coordinate-derived bytes avoid retaining a second in-memory tree for tests.
MerkleNode synthetic_merkle_node(size_t level, size_t local_index);
// Pack exactly 96 32-byte nodes into the v2 2048 x 12-bit coefficient payload;
// unused node slots are zero padded.
RlwePt encode_merkle_nodes(std::span<const MerkleNode> nodes,
                           const PirParams &params);
MerkleNode decode_merkle_node(const RlwePt &pt, size_t node_offset,
                              const PirParams &params);

RlwePt make_flat_merkle_plaintext(size_t plaintext_index,
                                  const MerkleWorkload &workload,
                                  const PirParams &params);
RlwePt make_layer_merkle_plaintext(size_t level, size_t plaintext_index,
                                   const MerkleWorkload &workload,
                                   const PirParams &params);

// Minimize padded plaintext count per level while retaining the reference
// scheme parameters and maximum remaining-dimension count.
std::vector<LayerLayout> plan_layer_layouts(
    size_t tree_height, size_t nodes_per_pt, const PirParams &reference);
uint64_t sum_padded_bytes(const std::vector<LayerLayout> &layouts);
