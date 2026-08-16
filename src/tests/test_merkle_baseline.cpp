#include "tests.h"
#include "merkle_baseline.h"

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
