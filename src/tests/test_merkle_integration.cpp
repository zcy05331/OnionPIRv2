#include "tests.h"
#include "merkle_baseline.h"
#include "merkle_benchmark.h"

#include <array>
#include <vector>

namespace {

void require_expected_path(const MerklePath &path, size_t leaf,
                           size_t tree_height) {
  // Runners return leaf-to-root order (levels H..1), matching client use.
  require_test(path.size() == tree_height, "Merkle path length");
  for (size_t offset = 0; offset < tree_height; ++offset) {
    const size_t level = tree_height - offset;
    const size_t local =
        merkle_sibling_local(leaf, tree_height, level);
    require_test(path[offset] == synthetic_merkle_node(level, local),
                 "Merkle path node mismatch");
  }
}

}  // namespace

void PirTest::test_merkle_integration() {
  // H=8 cheaply covers first, last, and interior leaves through codec, query,
  // server evaluation, response wire round-trip, and decryption.
  const MerkleWorkload small{size_t{1} << 8, 8, 32};
  const size_t small_target = utils::roundup_div(
      2 * (small.leaf_count - 1), size_t{96});
  PirParams small_reference =
      PirParams().with_layout({small_target, 3, true});
  const BenchmarkTrialPlan small_trials{
      {}, {0, small.leaf_count - 1, small.leaf_count / 2}};

  BenchmarkCaseExecution standard =
      run_standard_case(small, small_reference, small_trials);
  require_test(standard.result.correctness_passed,
               "standard deterministic case");
  require_test(standard.result.communication.pir_call_count == 1,
               "standard call count");

  BenchmarkCaseExecution flat =
      run_merkle_flat_case(small, small_reference, small_trials);
  BenchmarkCaseExecution layerwise =
      run_merkle_layerwise_case(small, small_reference, small_trials);
  require_test(flat.result.correctness_passed, "H=8 flat correctness");
  require_test(layerwise.result.correctness_passed,
               "H=8 layerwise correctness");
  require_test(flat.measured_paths == layerwise.measured_paths,
               "H=8 flat/layerwise path mismatch");
  require_test(flat.measured_paths.size() ==
                   small_trials.measured_leaf_indices.size(),
               "H=8 measured path count");
  for (size_t i = 0; i < flat.measured_paths.size(); ++i) {
    require_expected_path(flat.measured_paths[i],
                          small_trials.measured_leaf_indices[i],
                          small.tree_height);
  }
  // Levels 1..6 (2..64 nodes) fit one 96-node plaintext and are returned in
  // the clear; levels 7 and 8 stay PIR calls.
  require_test(layerwise.result.direct_return_levels == 6,
               "H=8 direct-return level count");
  require_test(layerwise.result.communication.pir_call_count == 2,
               "H=8 layerwise PIR call count");
  validate_layerwise_path_communication(
      flat.result.communication, layerwise.result.communication,
      layerwise.result.direct_return_levels,
      layerwise.result.direct_return_response_bytes);

  // H=16 forces remaining-dimension RGSW MUX work; a small-only fixture could
  // otherwise pass while testing only the first-dimension path.
  const MerkleWorkload multidimensional{size_t{1} << 16, 16, 32};
  const size_t multidimensional_target = utils::roundup_div(
      2 * (multidimensional.leaf_count - 1), size_t{96});
  PirParams multidimensional_reference =
      PirParams().with_layout({multidimensional_target, 8, true});
  require_test(multidimensional_target > 1024,
               "H=16 fixture is not multidimensional");
  require_test(multidimensional_reference.get_num_other_dims() > 0,
               "H=16 fixture does not exercise MUX dimensions");
  const BenchmarkTrialPlan multidimensional_trials{{}, {48879}};
  BenchmarkCaseExecution flat_multi = run_merkle_flat_case(
      multidimensional, multidimensional_reference,
      multidimensional_trials);
  BenchmarkCaseExecution layerwise_multi = run_merkle_layerwise_case(
      multidimensional, multidimensional_reference,
      multidimensional_trials);
  require_test(flat_multi.measured_paths == layerwise_multi.measured_paths,
               "H=16 flat/layerwise path mismatch");
  require_expected_path(flat_multi.measured_paths.at(0), 48879, 16);
  require_test(layerwise_multi.result.direct_return_levels == 6,
               "H=16 direct-return level count");
  validate_layerwise_path_communication(
      flat_multi.result.communication, layerwise_multi.result.communication,
      layerwise_multi.result.direct_return_levels,
      layerwise_multi.result.direct_return_response_bytes);
}
