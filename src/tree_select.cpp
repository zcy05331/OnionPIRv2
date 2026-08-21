#include "tree_select.h"

#include "utils.h"

#include "hexl/hexl.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const char *message) {
  if (!condition) {
    throw std::invalid_argument(std::string("tree_select: ") + message);
  }
}

// Limb-wise addition of coefficient-form full-q ciphertexts.
void ct_add_inplace(RlweCt &acc, const RlweCt &x, const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs = scheme.get_rns_mods();
  require(!acc.ntt_form && !x.ntt_form &&
              acc.c0.size() == x.c0.size() &&
              acc.c0.size() == qs.size() * N,
          "ciphertext addition needs matching coefficient-form inputs");
  for (size_t k = 0; k < qs.size(); ++k) {
    intel::hexl::EltwiseAddMod(acc.c0.data() + k * N, acc.c0.data() + k * N,
                               x.c0.data() + k * N, N, qs[k]);
    intel::hexl::EltwiseAddMod(acc.c1.data() + k * N, acc.c1.data() + k * N,
                               x.c1.data() + k * N, N, qs[k]);
  }
}

uint64_t splitmix64_once(uint64_t value) {
  value += 0x9e3779b97f4a7c15ULL;
  value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
  value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
  return value ^ (value >> 31);
}

}  // namespace

uint64_t synthetic_tree_node_value(size_t level, size_t index, uint64_t t) {
  if (t == 0) {
    throw std::invalid_argument("synthetic node values need a modulus");
  }
  const uint64_t mixed = splitmix64_once(
      0x74726565506972ULL ^
      (static_cast<uint64_t>(level) * 0xd6e8feb86659fd93ULL) ^
      (static_cast<uint64_t>(index) * 0xa5a3564e27f8862fULL));
  return mixed % t;
}

TreeLevelDatabase pack_tree_level(size_t level, const TreePirParams &tree,
                                  const TreeNodeSource &source) {
  validate_tree_params(tree);
  require(level <= tree.L, "level is out of range");

  TreeLevelDatabase db;
  db.level = level;
  db.R = level >= tree.r ? size_t{1} << (level - tree.r) : size_t{1};
  const size_t node_count = size_t{1} << level;
  db.plaintexts.assign(db.R, std::vector<uint64_t>(tree.n, 0));
  // Sec. 6.1: D_l[p][u] = M[l][p + u*R_l] while the node index stays below
  // 2^l; the remaining coefficients keep their zero fill.
  for (size_t p = 0; p < db.R; ++p) {
    for (size_t u = 0; u < tree.n; ++u) {
      const size_t node = p + u * db.R;
      if (node >= node_count) break;
      db.plaintexts[p][u] = source(level, node) % tree.t;
    }
  }
  return db;
}

std::vector<TreeLevelDatabase> preprocess_tree_reference(
    const TreePirParams &tree, const TreeNodeSource &source) {
  std::vector<TreeLevelDatabase> levels;
  levels.reserve(tree.L + 1);
  for (size_t level = 0; level <= tree.L; ++level) {
    levels.push_back(pack_tree_level(level, tree, source));
  }
  return levels;
}

RlweCt tree_pt_ct_mul(const std::vector<uint64_t> &pt, const RlweCt &ct,
                      const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs = scheme.get_rns_mods();
  const size_t K = qs.size();
  require(pt.size() == N, "plaintext polynomial has the wrong degree");
  require(!ct.ntt_form && ct.c0.size() == K * N && ct.c1.size() == K * N,
          "PtCtMul needs a coefficient-form full-q ciphertext");

  // Reference negacyclic product per limb: NTT both operands, pointwise
  // multiply, and return to coefficient form. Plaintext coefficients are
  // below t < q_k, so the same values serve every limb.
  RlweCt result;
  result.c0.assign(K * N, 0);
  result.c1.assign(K * N, 0);
  result.ntt_form = false;
  std::vector<uint64_t> pt_ntt(N), component(N);
  for (size_t k = 0; k < K; ++k) {
    const uint64_t q = qs[k];
    std::copy(pt.begin(), pt.end(), pt_ntt.begin());
    utils::ntt_fwd(pt_ntt.data(), N, q);
    for (const bool second : {false, true}) {
      const uint64_t *src = (second ? ct.c1.data() : ct.c0.data()) + k * N;
      uint64_t *dst = (second ? result.c1.data() : result.c0.data()) + k * N;
      std::copy(src, src + N, component.data());
      utils::ntt_fwd(component.data(), N, q);
      intel::hexl::EltwiseMultMod(component.data(), component.data(),
                                  pt_ntt.data(), N, q, 1);
      utils::ntt_inv(component.data(), N, q);
      std::copy(component.begin(), component.end(), dst);
    }
  }
  return result;
}

AlphaPyramid build_alpha_pyramid(std::span<const RlweCt> alpha_cts,
                                 const TreePirParams &tree,
                                 const PirParams &scheme) {
  require(alpha_cts.size() == tree.N0,
          "alpha pyramid needs the N0 expanded one-hot ciphertexts");
  AlphaPyramid pyramid;
  pyramid.reserve(tree.a + 1);
  pyramid.emplace_back(alpha_cts.begin(), alpha_cts.end());
  // Sec. 10: A^(c+1)_j = A^(c)_{2j} + A^(c)_{2j+1}; only additions, so the
  // level-c vector one-hot-selects floor(alpha / 2^c).
  for (size_t c = 0; c < tree.a; ++c) {
    const std::vector<RlweCt> &prev = pyramid.back();
    std::vector<RlweCt> next;
    next.reserve(prev.size() / 2);
    for (size_t j = 0; j < prev.size() / 2; ++j) {
      RlweCt sum = prev[2 * j];
      ct_add_inplace(sum, prev[2 * j + 1], scheme);
      next.push_back(std::move(sum));
    }
    pyramid.push_back(std::move(next));
  }
  return pyramid;
}

std::vector<RlweCt> evaluate_alpha_dimension(const TreeLevelDatabase &db,
                                             std::span<const RlweCt> alpha,
                                             const LevelPlan &plan,
                                             const TreePirParams &tree,
                                             const PirParams &scheme) {
  require(plan.select_case == SelectCase::AlphaBeta,
          "alpha dimension evaluation applies to the AlphaBeta case");
  require(db.level == plan.level && db.R == plan.R,
          "level database does not match the plan");
  require(alpha.size() == tree.N0, "alpha vector must have N0 entries");
  const size_t stride = size_t{1} << plan.beta_count;  // 2^{d_l}
  require(db.R == tree.N0 * stride, "AlphaBeta level has R = N0 * 2^d");

  // Sec. 11.2 with the sec. 6.2 matrix view: candidate delta accumulates
  // D_l[k * 2^d + delta] * A_k over the first dimension.
  std::vector<RlweCt> candidates;
  candidates.reserve(stride);
  for (size_t delta = 0; delta < stride; ++delta) {
    RlweCt acc = tree_pt_ct_mul(db.plaintexts[delta], alpha[0], scheme);
    for (size_t k = 1; k < tree.N0; ++k) {
      RlweCt term =
          tree_pt_ct_mul(db.plaintexts[k * stride + delta], alpha[k], scheme);
      ct_add_inplace(acc, term, scheme);
    }
    candidates.push_back(std::move(acc));
  }
  return candidates;
}

RlweCt fold_beta_dimension(std::vector<RlweCt> candidates,
                           const LevelPlan &plan,
                           std::span<GSWCt> beta_selectors, PirServer &mux) {
  require(candidates.size() == size_t{1} << plan.beta_count,
          "candidate count must be 2^{beta_count}");
  require(plan.beta_begin + plan.beta_count <= beta_selectors.size() ||
              plan.beta_count == 0,
          "fold needs a selector for every active beta bit");

  // Sec. 11.3: the candidate array is in ordinary integer order of delta, so
  // the fold must consume beta_{b-1} first (the MSB of the remaining delta)
  // and walk down to beta_{begin}. Each step pairs the lower and upper half:
  // bit 0 keeps the lower candidate, bit 1 the upper. ext_prod_mux may alias
  // its result with x and destroys y, both acceptable here because the upper
  // half is truncated right after.
  for (size_t step = 0; step < plan.beta_count; ++step) {
    const size_t u = plan.beta_begin + plan.beta_count - 1 - step;
    const size_t half = candidates.size() / 2;
    for (size_t j = 0; j < half; ++j) {
      mux.ext_prod_mux(candidates[j], candidates[j + half], beta_selectors[u],
                       candidates[j]);
    }
    candidates.resize(half);
  }
  require(candidates.size() == 1, "fold must end with a single candidate");
  return std::move(candidates.front());
}

RlweCt select_level(const TreeLevelDatabase &db, const LevelPlan &plan,
                    const AlphaPyramid &pyramid,
                    std::span<GSWCt> beta_selectors, PirServer &mux,
                    const TreePirParams &tree, const PirParams &scheme) {
  require(db.level == plan.level && db.R == plan.R,
          "level database does not match the plan");
  require(pyramid.size() == tree.a + 1 && pyramid[0].size() == tree.N0,
          "alpha pyramid does not match the tree parameters");

  switch (plan.select_case) {
    case SelectCase::Single: {
      // Sec. 11.3 case R = 1: A^(a)_0 encrypts the constant 1.
      return tree_pt_ct_mul(db.plaintexts[0], pyramid[tree.a][0], scheme);
    }
    case SelectCase::CoarsenedAlpha: {
      // Sec. 11.3 case R < N0: the level-c pyramid one-hot-selects
      // floor(alpha / 2^c) among exactly R candidates.
      const size_t c = plan.coarsen_count;
      require(pyramid[c].size() == db.R,
              "coarsened pyramid level does not match R");
      RlweCt acc = tree_pt_ct_mul(db.plaintexts[0], pyramid[c][0], scheme);
      for (size_t k = 1; k < db.R; ++k) {
        RlweCt term = tree_pt_ct_mul(db.plaintexts[k], pyramid[c][k], scheme);
        ct_add_inplace(acc, term, scheme);
      }
      return acc;
    }
    case SelectCase::AlphaBeta: {
      std::vector<RlweCt> candidates =
          evaluate_alpha_dimension(db, pyramid[0], plan, tree, scheme);
      return fold_beta_dimension(std::move(candidates), plan, beta_selectors,
                                 mux);
    }
  }
  throw std::invalid_argument("tree_select: unknown level plan case");
}
