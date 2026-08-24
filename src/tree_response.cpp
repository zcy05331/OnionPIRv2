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

TreePathResponse answer_path_mvp(const PreprocessedTree &db,
                                 ExpandedTreeQuery &query, PirServer &server,
                                 size_t client_id, const TreePirParams &tree,
                                 const PirParams &scheme) {
  const bool use_m32 = !db.m32.empty();
  if ((use_m32 ? db.m32.size() : db.ntt.size()) != tree.L + 1 ||
      db.plans.size() != tree.L + 1) {
    throw std::invalid_argument(
        "tree_response: one database view and one plan per level are "
        "required");
  }
  const bvks::BvGaloisKeys &galois_keys =
      server.client_session_keys(client_id)->bv_galois_keys;

  // One pyramid per query, lifted to NTT form once so every level's first
  // dimension runs on precomputed transforms (Milestone 6); composite
  // configurations additionally split it into the kernel's CRT limbs.
  const AlphaPyramid pyramid =
      build_alpha_pyramid(query.alpha, tree, scheme);
  const AlphaPyramid pyramid_ntt = pyramid_to_ntt(pyramid, scheme);
  AlphaPyramidM32 pyramid_m32;
  if (use_m32) {
    pyramid_m32 = pyramid_to_m32(pyramid_ntt, scheme);
  }

  TreePathResponse response;
  response.level_count = tree.L + 1;
  response.level_offsets.assign(response.level_count, 0);
  const auto bounds = path_chunk_bounds(response.level_count, tree.rho);
  response.chunks.reserve(bounds.size());

  // Selection + private rotation per level, shared by both packers.
  const auto select_and_rotate = [&](size_t level) {
    RlweCt selected =
        use_m32 ? select_level_m32(
                      db.m32[level], db.plans[level], pyramid_m32,
                      std::span<GSWCt>(query.beta_selectors), server, tree,
                      scheme)
                : select_level_ntt(
                      db.ntt[level], db.plans[level], pyramid_ntt,
                      std::span<GSWCt>(query.beta_selectors), server, tree,
                      scheme);
    return private_rotate_level(std::move(selected), db.plans[level],
                                std::span<GSWCt>(query.gamma_selectors),
                                server, scheme);
  };

  // Sequential packer (Algorithm 7 lines 4-6): per level select, privately
  // rotate, project, then shift the lone stride-lattice record to its slot
  // inside the chunk. Since every projected ciphertext is zero outside its
  // stride slots, the shifted additions can neither overlap nor wrap.
  for (const auto &[first_level, size] : bounds) {
    RlweCt packed;
    for (size_t z = 0; z < size; ++z) {
      const size_t level = first_level + z;
      RlweCt projected = project_keep_stride(
          select_and_rotate(level), db.plans[level].projection_depth,
          galois_keys, scheme);
      response.level_offsets[level] = z;
      if (z == 0) {
        packed = std::move(projected);
      } else {
        const RlweCt shifted = mul_x_pow(projected, z, scheme);
        tree_ct_add_inplace(packed, shifted, scheme);
      }
    }
    // Milestone 5: all homomorphic work for this chunk is complete, so the
    // final same-ring modulus switch may run now.
    response.small_q = server.switch_response_to_small_q(packed);
    response.chunks.push_back(std::move(packed));
  }
  return response;
}

std::vector<std::vector<uint64_t>> extract_path_chunks_mvp(
    const TreePathResponse &response, PirClient &client,
    const TreePirParams &tree) {
  const auto bounds = path_chunk_bounds(response.level_count, tree.rho);
  if (response.chunks.size() != bounds.size()) {
    throw std::invalid_argument(
        "tree_response: chunk count does not match the level partition");
  }
  if (response.level_offsets.size() != response.level_count) {
    throw std::invalid_argument(
        "tree_response: response is missing its level offset map");
  }
  std::vector<std::vector<uint64_t>> path;
  path.reserve(response.level_count);
  for (size_t c = 0; c < bounds.size(); ++c) {
    const RlwePt pt = response.small_q
                          ? client.decrypt_mod_q(response.chunks[c])
                          : client.decrypt_ct(response.chunks[c]);
    for (size_t z = 0; z < bounds[c].second; ++z) {
      const size_t offset = response.level_offsets[bounds[c].first + z];
      std::vector<uint64_t> chunks(tree.g);
      for (size_t j = 0; j < tree.g; ++j) {
        chunks[j] = pt.data[offset + j * tree.rho];
      }
      path.push_back(std::move(chunks));
    }
  }
  return path;
}

std::vector<uint64_t> extract_path_mvp(const TreePathResponse &response,
                                       PirClient &client,
                                       const TreePirParams &tree) {
  if (tree.g != 1) {
    throw std::invalid_argument(
        "tree_response: flat extraction requires g = 1; use "
        "extract_path_chunks_mvp");
  }
  std::vector<std::vector<uint64_t>> chunked =
      extract_path_chunks_mvp(response, client, tree);
  std::vector<uint64_t> path;
  path.reserve(chunked.size());
  for (const std::vector<uint64_t> &level : chunked) {
    path.push_back(level.front());
  }
  return path;
}
