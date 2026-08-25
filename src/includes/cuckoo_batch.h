#pragma once

#include "merkle_baseline.h"
#include "pir.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

// Cuckoo-hash batch PIR baseline (Angel-Chen-Laine-Setty style) over the
// flat root-excluded Merkle database, for comparison against the layerwise
// and flat baselines and the tree MVP. The server replicates every item into
// the buckets named by w = 3 public hash functions (about 1.5k buckets for a
// batch of k), so one batch costs roughly three single-database scans of
// server work regardless of k; the client cuckoo-places its k indices so
// that each bucket answers at most one real query and every remaining
// bucket receives an indistinguishable dummy. This is the generic batch-PIR
// reference point: it deliberately ignores the tree's cross-level position
// structure, which is exactly what the draft paper's introduction argues
// costs it against structure-aware retrieval.
//
// Public metadata convention: the hash functions (and hence every bucket's
// sorted member list) are public. The client derives an item's position
// inside its bucket from that public information; following the batch-PIR
// literature this metadata is not counted as online communication.

struct CuckooBatchParams {
  size_t item_count = 0;   // M: flat root-excluded node ordinals [0, M)
  size_t batch_size = 0;   // k items per batch
  size_t num_buckets = 0;  // ~ceil(1.5 k)
  size_t num_hashes = 3;
  uint64_t seed = 0x6375636b6f6f5049ULL;
};

// Derive num_buckets = max(ceil(1.5 k), k + 1) and validate.
CuckooBatchParams make_cuckoo_batch_params(size_t item_count,
                                           size_t batch_size, uint64_t seed);

// Bucket named by hash function `hash_index` for `ordinal`.
size_t cuckoo_bucket_of(uint64_t ordinal, size_t hash_index,
                        const CuckooBatchParams &params);

struct CuckooBucket {
  std::vector<uint32_t> members;  // sorted, deduplicated ordinals
  size_t target_num_pt = 0;       // ceil(members / 96)
  PirParams params;               // scheme-compatible per-bucket layout
};

// Enumerate every bucket's member list and pick the minimal scheme-compatible
// layout per bucket (same scoring as the layerwise planner).
std::vector<CuckooBucket> build_cuckoo_buckets(const CuckooBatchParams &params,
                                               const PirParams &reference);

// Rank of `ordinal` inside the bucket's sorted member list; throws when the
// ordinal does not hash into this bucket.
size_t cuckoo_position(const CuckooBucket &bucket, uint32_t ordinal);

// Deterministic random-walk cuckoo placement: every queried ordinal lands in
// exactly one of its num_hashes candidate buckets and no bucket holds more
// than one. Throws when the bounded eviction walk fails (vanishingly rare at
// the 1.5x sizing) or when the ordinals are not distinct.
std::vector<std::optional<uint32_t>> cuckoo_place(
    const std::vector<uint32_t> &ordinals, const CuckooBatchParams &params);
