#include "tests.h"
#include "merkle_baseline.h"

#include <bit>
#include <vector>

namespace {

template <typename Fn>
bool throws_invalid_argument(Fn &&fn) {
  try {
    fn();
  } catch (const std::invalid_argument &) {
    return true;
  }
  return false;
}

// Independent oracle for the root-excluded breadth-first layout, written in
// terms of the 1-based heap index (root = 1, children 2i and 2i + 1) rather
// than the merkle_baseline helpers under test.
std::pair<size_t, size_t> heap_node_of_ordinal(size_t ordinal) {
  const size_t heap = ordinal + 2;
  const size_t level = std::bit_width(heap) - 1;
  return {level, heap - (size_t{1} << level)};
}
size_t heap_sibling_local(size_t leaf, size_t tree_height, size_t level) {
  const size_t ancestor = (leaf + (size_t{1} << tree_height)) >>
                          (tree_height - level);
  return (ancestor ^ 1U) - (size_t{1} << level);
}

}  // namespace

void PirTest::test_merkle_baseline() {
  PirParams scheme;
  MerkleWorkload small{size_t{1} << 8, 8, 32};
  // Boundary leaves plus an interior level anchor sibling and flat-ordinal
  // conventions independently of the encrypted integration tests.
  require_test(merkle_sibling_local(0, 8, 8) == 1,
               "leaf zero sibling");
  require_test(merkle_sibling_local(255, 8, 8) == 254,
               "last sibling");
  require_test(merkle_sibling_local(173, 8, 4) == 11,
               "middle sibling");
  require_test(merkle_flat_ordinal(1, 0) == 0, "first flat node");
  require_test(merkle_flat_ordinal(8, 255) == 509, "last flat node");

  // First/middle/last checks cross the 12-bit coefficient boundaries in one
  // full 96-node plaintext and catch ordering or truncation errors.
  std::vector<MerkleNode> nodes(96);
  for (size_t i = 0; i < nodes.size(); ++i) {
    nodes[i] = synthetic_merkle_node(8, i);
  }
  RlwePt encoded = encode_merkle_nodes(nodes, scheme);
  require_test(decode_merkle_node(encoded, 0, scheme) == nodes[0],
               "codec first");
  require_test(decode_merkle_node(encoded, 47, scheme) == nodes[47],
               "codec middle");
  require_test(decode_merkle_node(encoded, 95, scheme) == nodes[95],
               "codec last");

  // Partial final plaintexts must expose deterministic zero-filled slots.
  RlwePt partial = encode_merkle_nodes(
      std::span<const MerkleNode>(nodes.data(), 1), scheme);
  require_test(decode_merkle_node(partial, 1, scheme) == MerkleNode{},
               "codec zero padding");

  const RlwePt flat_last = make_flat_merkle_plaintext(5, small, scheme);
  require_test(decode_merkle_node(flat_last, 29, scheme) ==
                   synthetic_merkle_node(8, 255),
               "flat final node");
  require_test(decode_merkle_node(flat_last, 30, scheme) == MerkleNode{},
               "flat final padding");

  // Index algebra against the heap oracle: every (leaf, level) sibling at
  // H = 8, and every ordinal of the first flat plaintext, which straddles
  // levels 1..7 (ordinals 0..61 are levels 1..5, 62..93 level 6, 94..95
  // level 7) and so exercises the cross-level packing of one plaintext.
  for (size_t leaf = 0; leaf < small.leaf_count; ++leaf) {
    for (size_t level = 1; level <= small.tree_height; ++level) {
      require_test(merkle_sibling_local(leaf, small.tree_height, level) ==
                       heap_sibling_local(leaf, small.tree_height, level),
                   "sibling index disagrees with the heap oracle");
    }
  }
  const RlwePt flat_first = make_flat_merkle_plaintext(0, small, scheme);
  for (size_t ordinal = 0; ordinal < 96; ++ordinal) {
    const auto [level, local] = heap_node_of_ordinal(ordinal);
    require_test(merkle_flat_ordinal(level, local) == ordinal,
                 "flat ordinal disagrees with the heap oracle");
    require_test(decode_merkle_node(flat_first, ordinal, scheme) ==
                     synthetic_merkle_node(level, local),
                 "cross-level flat plaintext node mismatch");
  }
  // Layer plaintexts hold one level only: the last plaintext of level 8 is
  // nodes 192..255 followed by zero padding.
  const RlwePt layer_last = make_layer_merkle_plaintext(8, 2, small, scheme);
  require_test(decode_merkle_node(layer_last, 0, scheme) ==
                       synthetic_merkle_node(8, 192) &&
                   decode_merkle_node(layer_last, 63, scheme) ==
                       synthetic_merkle_node(8, 255) &&
                   decode_merkle_node(layer_last, 64, scheme) == MerkleNode{},
               "layer plaintext content and padding");

  // Freeze representative planner transitions and the exact H=24 padded total.
  PirParams reference = scheme.with_layout({349526, 10, true});
  auto plan = plan_layer_layouts(24, 96, reference);
  require_test(plan.size() == 24, "one plan entry per non-root level");
  require_test(plan.at(0).params.get_expan_height() == 0, "level 1 h");
  require_test(plan.at(6).params.get_target_num_pt() == 2,
               "level 7 target");
  require_test(plan.at(6).params.get_expan_height() == 1, "level 7 h");
  require_test(plan.at(11).params.get_num_pt() == 48,
               "level 12 rounded");
  require_test(plan.at(23).params.get_num_pt() == 174848,
               "level 24 rounded");
  require_test(sum_padded_bytes(plan) == 1074843648ULL,
               "layer padded total");
  // Direct-return flags: levels whose node count fits one 96-node plaintext
  // (levels 1..6) are handed over in the clear at any tree height.
  for (size_t level = 1; level <= 24; ++level) {
    require_test(plan.at(level - 1).direct_return == (level <= 6),
                 "H=24 direct-return flag");
  }
  const std::vector<LayerLayout> plan8 =
      plan_layer_layouts(8, 96, scheme.with_layout({6, 3, true}));
  require_test(plan8.size() == 8, "H=8 plan size");
  for (size_t level = 1; level <= 8; ++level) {
    require_test(plan8.at(level - 1).direct_return == (level <= 6),
                 "H=8 direct-return flag");
    require_test(plan8.at(level - 1).node_count == (size_t{1} << level),
                 "H=8 level node count");
  }
  // A reference too small to represent a deeper level is a hard error, not
  // a silently truncated plan.
  bool rejected_shape = false;
  try {
    (void)plan_layer_layouts(8, 96, scheme.with_layout({1, 0, true}));
  } catch (const std::runtime_error &) {
    rejected_shape = true;
  }
  require_test(rejected_shape,
               "accepted a reference that cannot represent level 7");

  // Public helpers must reject malformed coordinates and workload geometry
  // rather than silently wrapping size_t indices.
  require_test(throws_invalid_argument(
                   [] { (void)merkle_sibling_local(0, 8, 0); }),
               "accepted root as authentication sibling level");
  require_test(throws_invalid_argument(
                   [] { (void)merkle_sibling_local(256, 8, 8); }),
               "accepted out-of-range leaf");
  require_test(throws_invalid_argument(
                   [] { (void)merkle_flat_ordinal(3, 8); }),
               "accepted out-of-range level-local node");
  require_test(throws_invalid_argument([&] {
                 std::vector<MerkleNode> too_many(97);
                 (void)encode_merkle_nodes(too_many, scheme);
               }),
               "accepted codec overflow");
  require_test(throws_invalid_argument(
                   [&] { (void)decode_merkle_node(encoded, 96, scheme); }),
               "accepted out-of-range node offset");
  require_test(throws_invalid_argument([&] {
                 (void)make_flat_merkle_plaintext(
                     0, MerkleWorkload{255, 8, 32}, scheme);
               }),
               "accepted non-power-of-two leaf count");
}
