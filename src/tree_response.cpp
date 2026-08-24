#include "tree_response.h"

#include "tree_project.h"
#include "tree_rotate.h"
#include "utils.h"

#include <stdexcept>
#include <string>

std::vector<std::pair<size_t, size_t>> path_chunk_bounds(size_t level_count,
                                                         size_t capacity) {
  if (level_count == 0 || capacity == 0) {
    throw std::invalid_argument(
        "tree_response: chunk bounds need positive levels and capacity");
  }
  std::vector<std::pair<size_t, size_t>> bounds;
  for (size_t first = 0; first < level_count; first += capacity) {
    bounds.emplace_back(first,
                        std::min(capacity, level_count - first));
  }
  return bounds;
}

TreePathResponse answer_path_mvp(const std::vector<TreeLevelDatabase> &levels,
                                 const std::vector<LevelPlan> &plans,
                                 ExpandedTreeQuery &query, PirServer &server,
                                 size_t client_id, const TreePirParams &tree,
                                 const PirParams &scheme) {
  if (levels.size() != tree.L + 1 || plans.size() != tree.L + 1) {
    throw std::invalid_argument(
        "tree_response: one database and one plan per level are required");
  }
  const bvks::BvGaloisKeys &galois_keys =
      server.client_session_keys(client_id)->bv_galois_keys;

  const AlphaPyramid pyramid =
      build_alpha_pyramid(query.alpha, tree, scheme);

  TreePathResponse response;
  response.level_count = tree.L + 1;
  const auto bounds = path_chunk_bounds(response.level_count, tree.n);
  response.chunks.reserve(bounds.size());

  // Algorithm 7 lines 4-6: per level select, privately rotate, project, then
  // shift the lone constant coefficient to its slot inside the chunk. Since
  // every projected ciphertext is zero outside coefficient zero, the shifted
  // additions can neither overlap nor wrap (z < n is asserted through the
  // chunk bounds).
  for (const auto &[first_level, size] : bounds) {
    RlweCt packed;
    for (size_t z = 0; z < size; ++z) {
      const size_t level = first_level + z;
      RlweCt selected = select_level(
          levels[level], plans[level], pyramid,
          std::span<GSWCt>(query.beta_selectors), server, tree, scheme);
      RlweCt rotated = private_rotate_level(
          std::move(selected), plans[level],
          std::span<GSWCt>(query.gamma_selectors), server, scheme);
      RlweCt projected = project_keep_stride(
          std::move(rotated), plans[level].projection_depth, galois_keys,
          scheme);
      if (z == 0) {
        packed = std::move(projected);
      } else {
        const RlweCt shifted = mul_x_pow(projected, z, scheme);
        tree_ct_add_inplace(packed, shifted, scheme);
      }
    }
    response.chunks.push_back(std::move(packed));
  }
  return response;
}

std::vector<uint64_t> extract_path_mvp(const TreePathResponse &response,
                                       PirClient &client,
                                       const TreePirParams &tree) {
  const auto bounds = path_chunk_bounds(response.level_count, tree.n);
  if (response.chunks.size() != bounds.size()) {
    throw std::invalid_argument(
        "tree_response: chunk count does not match the level partition");
  }
  std::vector<uint64_t> path;
  path.reserve(response.level_count);
  for (size_t c = 0; c < bounds.size(); ++c) {
    const RlwePt pt = client.decrypt_ct(response.chunks[c]);
    for (size_t z = 0; z < bounds[c].second; ++z) {
      path.push_back(pt.data[z]);
    }
  }
  return path;
}
