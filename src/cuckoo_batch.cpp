#include "cuckoo_batch.h"

#include "utils.h"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>
#include <tuple>

namespace {

void require(bool condition, const char *message) {
  if (!condition) {
    throw std::invalid_argument(std::string("cuckoo_batch: ") + message);
  }
}

uint64_t splitmix64_once(uint64_t value) {
  value += 0x9e3779b97f4a7c15ULL;
  value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
  value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
  return value ^ (value >> 31);
}

// Minimal scheme-compatible layout for one bucket, scored exactly like the
// layerwise planner: padded plaintexts first, then expansion work, remaining
// dimensions, and height.
PirParams bucket_layout(size_t target_num_pt, const PirParams &reference) {
  bool found = false;
  std::tuple<size_t, size_t, size_t, size_t> best_score;
  PirParams best = reference;
  const size_t max_other_dims = reference.get_num_other_dims();
  for (size_t height = 0; height <= reference.get_expan_height(); ++height) {
    try {
      PirParams candidate = reference.with_layout(
          {target_num_pt, height, reference.get_fst_dim_pow2()});
      const size_t other_dims = candidate.get_num_other_dims();
      if (other_dims > max_other_dims) continue;
      const size_t useful_expand =
          candidate.get_fst_dim_sz() + reference.get_l() * other_dims;
      const auto score = std::make_tuple(candidate.get_num_pt(),
                                         useful_expand, other_dims, height);
      if (!found || score < best_score) {
        found = true;
        best_score = score;
        best = std::move(candidate);
      }
    } catch (const std::runtime_error &) {
      // This height cannot represent the bucket; try the next one.
    }
  }
  if (!found) {
    throw std::runtime_error(
        "cuckoo_batch: no scheme-compatible layout for a bucket");
  }
  return best;
}

}  // namespace

CuckooBatchParams make_cuckoo_batch_params(size_t item_count,
                                           size_t batch_size, uint64_t seed) {
  require(item_count > 0 && batch_size > 0, "empty batch or database");
  require(item_count <= std::numeric_limits<uint32_t>::max(),
          "ordinals must fit uint32");
  CuckooBatchParams params;
  params.item_count = item_count;
  params.batch_size = batch_size;
  // The classic 1.5x cuckoo expansion with three hash functions.
  params.num_buckets = std::max((3 * batch_size + 1) / 2, batch_size + 1);
  params.seed = seed;
  return params;
}

size_t cuckoo_bucket_of(uint64_t ordinal, size_t hash_index,
                        const CuckooBatchParams &params) {
  require(hash_index < params.num_hashes, "hash index out of range");
  return static_cast<size_t>(
      splitmix64_once(params.seed ^
                      (0x9e3779b97f4a7c15ULL * (hash_index + 1)) ^
                      (ordinal * 0xd6e8feb86659fd93ULL)) %
      params.num_buckets);
}

std::vector<CuckooBucket> build_cuckoo_buckets(const CuckooBatchParams &params,
                                               const PirParams &reference) {
  std::vector<CuckooBucket> buckets(params.num_buckets);
  // Replicate every ordinal into its num_hashes buckets. Membership lists
  // are sorted and deduplicated (two hash functions may name the same
  // bucket), so an item's public position is its rank in the sorted list.
  for (uint64_t ordinal = 0; ordinal < params.item_count; ++ordinal) {
    for (size_t j = 0; j < params.num_hashes; ++j) {
      buckets[cuckoo_bucket_of(ordinal, j, params)].members.push_back(
          static_cast<uint32_t>(ordinal));
    }
  }
  for (CuckooBucket &bucket : buckets) {
    std::sort(bucket.members.begin(), bucket.members.end());
    bucket.members.erase(
        std::unique(bucket.members.begin(), bucket.members.end()),
        bucket.members.end());
    require(!bucket.members.empty(),
            "every bucket must hold at least one item at this scale");
    bucket.target_num_pt =
        utils::roundup_div(bucket.members.size(), size_t{96});
    bucket.params = bucket_layout(bucket.target_num_pt, reference);
  }
  return buckets;
}

size_t cuckoo_position(const CuckooBucket &bucket, uint32_t ordinal) {
  const auto it = std::lower_bound(bucket.members.begin(),
                                   bucket.members.end(), ordinal);
  if (it == bucket.members.end() || *it != ordinal) {
    throw std::invalid_argument(
        "cuckoo_batch: ordinal does not hash into this bucket");
  }
  return static_cast<size_t>(it - bucket.members.begin());
}

std::vector<std::optional<uint32_t>> cuckoo_place(
    const std::vector<uint32_t> &ordinals, const CuckooBatchParams &params) {
  require(ordinals.size() == params.batch_size,
          "placement expects exactly the batch size");
  require(ordinals.size() < params.num_buckets,
          "more items than buckets can never place");
  std::vector<std::optional<uint32_t>> assignment(params.num_buckets);

  uint64_t walk_state = params.seed ^ 0x66616365ULL;
  for (uint32_t start : ordinals) {
    uint32_t current = start;
    // Random-walk insertion: take a free candidate bucket if one exists,
    // otherwise evict the occupant of a pseudo-randomly chosen candidate and
    // re-place it. Deterministic given the seed.
    bool placed = false;
    for (size_t step = 0; step < 10000 && !placed; ++step) {
      size_t free_bucket = params.num_buckets;
      for (size_t j = 0; j < params.num_hashes; ++j) {
        const size_t b = cuckoo_bucket_of(current, j, params);
        if (assignment[b].has_value() && *assignment[b] == current) {
          throw std::invalid_argument(
              "cuckoo_batch: batch ordinals must be distinct");
        }
        if (!assignment[b].has_value()) {
          free_bucket = b;
          break;
        }
      }
      if (free_bucket != params.num_buckets) {
        assignment[free_bucket] = current;
        placed = true;
        break;
      }
      walk_state = splitmix64_once(walk_state);
      const size_t j = static_cast<size_t>(walk_state % params.num_hashes);
      const size_t b = cuckoo_bucket_of(current, j, params);
      const uint32_t evicted = *assignment[b];
      assignment[b] = current;
      current = evicted;
    }
    if (!placed) {
      throw std::runtime_error(
          "cuckoo_batch: eviction walk failed; retry with another seed");
    }
  }
  return assignment;
}
