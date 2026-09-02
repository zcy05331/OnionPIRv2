#include "merkle_baseline.h"

#include "utils.h"

#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <tuple>

namespace {

constexpr size_t kBitsPerMerkleCoefficient = 12;
constexpr size_t kMerkleNodesPerPlaintext = 96;

void validate_shift(size_t value, const char *name) {
  if (value >= std::numeric_limits<size_t>::digits) {
    throw std::invalid_argument(std::string(name) + " is too large");
  }
}

void validate_workload(const MerkleWorkload &workload) {
  validate_shift(workload.tree_height, "tree height");
  if (workload.tree_height >= std::numeric_limits<size_t>::digits - 1) {
    throw std::invalid_argument("Merkle workload is too large to flatten");
  }
  if (workload.node_bytes != sizeof(MerkleNode)) {
    throw std::invalid_argument("Merkle workload node size must be 32 bytes");
  }
  if (workload.leaf_count != (size_t{1} << workload.tree_height)) {
    throw std::invalid_argument(
        "Merkle workload leaf count must equal 2^tree_height");
  }
  if (workload.tree_height == 0) {
    throw std::invalid_argument("Merkle workload must contain a non-root level");
  }
}

size_t codec_payload_bytes(const PirParams &params) {
  if (params.get_poly_degree() >
      std::numeric_limits<size_t>::max() / kBitsPerMerkleCoefficient) {
    throw std::invalid_argument("Merkle codec payload size overflows");
  }
  const size_t payload_bits =
      params.get_poly_degree() * kBitsPerMerkleCoefficient;
  if (payload_bits % 8 != 0 ||
      payload_bits / 8 != kMerkleNodesPerPlaintext * sizeof(MerkleNode)) {
    throw std::invalid_argument(
        "Merkle codec requires the v2 2048x12-bit plaintext payload");
  }
  if (params.get_plain_mod() <= (size_t{1} << kBitsPerMerkleCoefficient) - 1) {
    throw std::invalid_argument(
        "Merkle codec requires a plaintext modulus larger than 4095");
  }
  return payload_bits / 8;
}

uint64_t splitmix64(uint64_t value) {
  value += 0x9e3779b97f4a7c15ULL;
  value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
  value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
  return value ^ (value >> 31);
}

}  // namespace

size_t merkle_sibling_local(size_t leaf, size_t tree_height, size_t level) {
  validate_shift(tree_height, "tree height");
  if (level == 0 || level > tree_height) {
    throw std::invalid_argument("Merkle sibling level must be in [1, H]");
  }
  const size_t leaf_count = size_t{1} << tree_height;
  if (leaf >= leaf_count) {
    throw std::invalid_argument("Merkle leaf index is out of range");
  }
  return (leaf >> (tree_height - level)) ^ size_t{1};
}

size_t merkle_flat_ordinal(size_t level, size_t local_index) {
  validate_shift(level, "Merkle level");
  if (level == 0) {
    throw std::invalid_argument("The flat Merkle database excludes the root");
  }
  const size_t node_count = size_t{1} << level;
  if (local_index >= node_count) {
    throw std::invalid_argument("Merkle level-local index is out of range");
  }
  return node_count - 2 + local_index;
}

MerkleNode synthetic_merkle_node(size_t level, size_t local_index) {
  MerkleNode node{};
  uint64_t state = 0x6d65726b6c655f32ULL ^
                   (static_cast<uint64_t>(level) * 0xd6e8feb86659fd93ULL) ^
                   (static_cast<uint64_t>(local_index) *
                    0xa5a3564e27f8862fULL);
  for (size_t word = 0; word < 4; ++word) {
    state = splitmix64(state + word);
    for (size_t byte = 0; byte < 8; ++byte) {
      node[word * 8 + byte] =
          static_cast<uint8_t>(state >> (byte * 8));
    }
  }
  return node;
}

RlwePt encode_merkle_nodes(std::span<const MerkleNode> nodes,
                           const PirParams &params) {
  const size_t payload_bytes = codec_payload_bytes(params);
  if (nodes.size() > kMerkleNodesPerPlaintext) {
    throw std::invalid_argument("A plaintext holds at most 96 Merkle nodes");
  }

  // v2 gives 2048 coefficients at 12 bits each: exactly 3072 payload bytes,
  // so one plaintext carries 96 fixed 32-byte Merkle nodes without spillover.
  // This is coefficient bit-packing, not BFV SIMD/evaluation-slot packing.
  // Rebuild the same bitstream before slicing out the requested node. Rejecting
  // non-12-bit digits catches malformed decrypted plaintexts at the boundary.
  std::vector<uint8_t> bytes(payload_bytes, 0);
  for (size_t i = 0; i < nodes.size(); ++i) {
    std::memcpy(bytes.data() + i * sizeof(MerkleNode), nodes[i].data(),
                sizeof(MerkleNode));
  }

  RlwePt result;
  result.data.resize(params.get_poly_degree());
  for (size_t coefficient = 0; coefficient < result.data.size();
       ++coefficient) {
    const size_t bit_index = coefficient * kBitsPerMerkleCoefficient;
    const size_t byte_index = bit_index / 8;
    const size_t bit_offset = bit_index % 8;
    uint32_t window = bytes[byte_index];
    if (byte_index + 1 < bytes.size()) {
      window |= static_cast<uint32_t>(bytes[byte_index + 1]) << 8;
    }
    if (byte_index + 2 < bytes.size()) {
      window |= static_cast<uint32_t>(bytes[byte_index + 2]) << 16;
    }
    result.data[coefficient] =
        (window >> bit_offset) & ((size_t{1} << kBitsPerMerkleCoefficient) - 1);
    if (result.data[coefficient] >= params.get_plain_mod()) {
      throw std::runtime_error("Merkle codec produced an invalid coefficient");
    }
  }
  return result;
}

MerkleNode decode_merkle_node(const RlwePt &pt, size_t node_offset,
                              const PirParams &params) {
  const size_t payload_bytes = codec_payload_bytes(params);
  if (node_offset >= kMerkleNodesPerPlaintext) {
    throw std::invalid_argument("Merkle node offset must be below 96");
  }
  if (pt.data.size() != params.get_poly_degree()) {
    throw std::invalid_argument("Merkle plaintext has the wrong coefficient count");
  }

  std::vector<uint8_t> bytes(payload_bytes, 0);
  for (size_t coefficient = 0; coefficient < pt.data.size(); ++coefficient) {
    const uint64_t value = pt.data[coefficient];
    if (value >= params.get_plain_mod() ||
        value >= (size_t{1} << kBitsPerMerkleCoefficient)) {
      throw std::invalid_argument("Merkle plaintext coefficient is not 12-bit");
    }
    const size_t bit_index = coefficient * kBitsPerMerkleCoefficient;
    const size_t byte_index = bit_index / 8;
    const size_t bit_offset = bit_index % 8;
    const uint32_t window = static_cast<uint32_t>(value) << bit_offset;
    bytes[byte_index] |= static_cast<uint8_t>(window);
    if (byte_index + 1 < bytes.size()) {
      bytes[byte_index + 1] |= static_cast<uint8_t>(window >> 8);
    }
    if (byte_index + 2 < bytes.size()) {
      bytes[byte_index + 2] |= static_cast<uint8_t>(window >> 16);
    }
  }

  MerkleNode result{};
  std::memcpy(result.data(),
              bytes.data() + node_offset * sizeof(MerkleNode),
              sizeof(MerkleNode));
  return result;
}

RlwePt make_flat_merkle_plaintext(size_t plaintext_index,
                                  const MerkleWorkload &workload,
                                  const PirParams &params) {
  validate_workload(workload);
  const size_t total_nodes = 2 * (workload.leaf_count - 1);
  const size_t target_num_pt =
      utils::roundup_div(total_nodes, kMerkleNodesPerPlaintext);
  if (plaintext_index >= target_num_pt) {
    throw std::invalid_argument("Flat Merkle plaintext index is out of range");
  }

  const size_t first_ordinal = plaintext_index * kMerkleNodesPerPlaintext;
  const size_t node_count =
      std::min(kMerkleNodesPerPlaintext, total_nodes - first_ordinal);
  std::vector<MerkleNode> nodes;
  nodes.reserve(node_count);
  for (size_t offset = 0; offset < node_count; ++offset) {
    const size_t heap_index = first_ordinal + offset + 2;
    const size_t level = std::bit_width(heap_index) - 1;
    const size_t local_index = heap_index - (size_t{1} << level);
    nodes.push_back(synthetic_merkle_node(level, local_index));
  }
  return encode_merkle_nodes(nodes, params);
}

RlwePt make_layer_merkle_plaintext(size_t level, size_t plaintext_index,
                                   const MerkleWorkload &workload,
                                   const PirParams &params) {
  validate_workload(workload);
  if (level == 0 || level > workload.tree_height) {
    throw std::invalid_argument("Merkle layer must be in [1, H]");
  }
  const size_t level_nodes = size_t{1} << level;
  const size_t target_num_pt =
      utils::roundup_div(level_nodes, kMerkleNodesPerPlaintext);
  if (plaintext_index >= target_num_pt) {
    throw std::invalid_argument("Layer Merkle plaintext index is out of range");
  }

  const size_t first_local = plaintext_index * kMerkleNodesPerPlaintext;
  const size_t node_count =
      std::min(kMerkleNodesPerPlaintext, level_nodes - first_local);
  std::vector<MerkleNode> nodes;
  nodes.reserve(node_count);
  for (size_t offset = 0; offset < node_count; ++offset) {
    nodes.push_back(synthetic_merkle_node(level, first_local + offset));
  }
  return encode_merkle_nodes(nodes, params);
}

std::vector<LayerLayout> plan_layer_layouts(
    size_t tree_height, size_t nodes_per_pt, const PirParams &reference) {
  validate_shift(tree_height, "tree height");
  if (tree_height == 0 ||
      tree_height >= std::numeric_limits<size_t>::digits - 1 ||
      nodes_per_pt == 0) {
    throw std::invalid_argument(
        "Layer planner requires a non-empty tree and plaintext capacity");
  }

  std::vector<LayerLayout> layouts;
  layouts.reserve(tree_height);
  const size_t max_other_dims = reference.get_num_other_dims();
  for (size_t level = 1; level <= tree_height; ++level) {
    const size_t node_count = size_t{1} << level;
    const size_t target_num_pt = utils::roundup_div(node_count, nodes_per_pt);

    // Keep each layer no deeper than the frozen flat reference shape. Tuple
    // order minimizes padded plaintexts first, then expansion work, remaining
    // dimensions, and finally expansion height.
    bool found = false;
    std::tuple<size_t, size_t, size_t, size_t> best_score;
    PirParams best_params = reference;
    for (size_t height = 0; height <= reference.get_expan_height(); ++height) {
      try {
        PirParams candidate = reference.with_layout(
            {target_num_pt, height, reference.get_fst_dim_pow2()});
        const size_t other_dims = candidate.get_num_other_dims();
        if (other_dims > max_other_dims) {
          continue;
        }
        const size_t useful_expand =
            candidate.get_fst_dim_sz() + reference.get_l() * other_dims;
        const auto score = std::make_tuple(candidate.get_num_pt(), useful_expand,
                                           other_dims, height);
        if (!found || score < best_score) {
          found = true;
          best_score = score;
          best_params = std::move(candidate);
        }
      } catch (const std::runtime_error &) {
        // This expansion height cannot represent the requested layer.
      }
    }
    if (!found) {
      throw std::runtime_error("No scheme-compatible PIR layout for Merkle layer");
    }
    layouts.push_back({level, node_count, target_num_pt, best_params});
    layouts.back().direct_return = node_count <= nodes_per_pt;
  }
  return layouts;
}

uint64_t sum_padded_bytes(const std::vector<LayerLayout> &layouts) {
  uint64_t total = 0;
  for (const LayerLayout &layout : layouts) {
    const uint64_t num_pt = layout.params.get_num_pt();
    const uint64_t pt_bytes = layout.params.get_pt_size();
    if (num_pt > std::numeric_limits<uint64_t>::max() / pt_bytes ||
        total > std::numeric_limits<uint64_t>::max() - num_pt * pt_bytes) {
      throw std::overflow_error("Merkle padded byte total overflows");
    }
    total += num_pt * pt_bytes;
  }
  return total;
}
