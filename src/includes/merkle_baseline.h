#pragma once

#include "pir.h"
#include "rlwe.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

using MerkleNode = std::array<uint8_t, 32>;

struct MerkleWorkload {
  size_t leaf_count;
  size_t tree_height;
  size_t node_bytes;
};

struct LayerLayout {
  size_t level;
  size_t node_count;
  size_t target_num_pt;
  PirParams params;
};

size_t merkle_sibling_local(size_t leaf, size_t tree_height, size_t level);
size_t merkle_flat_ordinal(size_t level, size_t local_index);

MerkleNode synthetic_merkle_node(size_t level, size_t local_index);
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

std::vector<LayerLayout> plan_layer_layouts(
    size_t tree_height, size_t nodes_per_pt, const PirParams &reference);
uint64_t sum_padded_bytes(const std::vector<LayerLayout> &layouts);
