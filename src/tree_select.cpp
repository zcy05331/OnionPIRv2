#include "tree_select.h"

#include "matrix.h"
#include "utils.h"

#include "hexl/hexl.hpp"

#include <algorithm>
#include <bit>
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

std::array<uint8_t, 32> synthetic_tree_node_bytes(size_t level,
                                                  size_t index) {
  std::array<uint8_t, 32> node{};
  uint64_t state = 0x747265654e6f6465ULL ^
                   (static_cast<uint64_t>(level) * 0xd6e8feb86659fd93ULL) ^
                   (static_cast<uint64_t>(index) * 0xa5a3564e27f8862fULL);
  for (size_t word = 0; word < 4; ++word) {
    state = splitmix64_once(state + word);
    for (size_t byte = 0; byte < 8; ++byte) {
      node[word * 8 + byte] = static_cast<uint8_t>(state >> (byte * 8));
    }
  }
  return node;
}

uint64_t synthetic_tree_node_bytes_chunk(size_t level, size_t index,
                                         size_t chunk, uint64_t t) {
  // Chunk width follows the scheme's usable coefficient capacity:
  // floor(log2(t)) bits per slot (12 for the 13-bit t, 39 for the 40-bit t).
  const size_t width = static_cast<size_t>(std::bit_width(t)) - 1;
  if (width == 0) {
    throw std::invalid_argument(
        "tree_select: node chunks need a plaintext modulus above 1");
  }
  const std::array<uint8_t, 32> node = synthetic_tree_node_bytes(level, index);
  // Little-endian window [width*chunk, width*(chunk+1)) over the 256-bit
  // value; bits past the end read as zero.
  uint64_t value = 0;
  for (size_t bit = 0; bit < width; ++bit) {
    const size_t position = width * chunk + bit;
    if (position >= 256) break;
    const uint8_t byte = node[position / 8];
    value |= static_cast<uint64_t>((byte >> (position % 8)) & 1U) << bit;
  }
  return value;
}

TreeLevelDatabase pack_tree_level(size_t level, const TreePirParams &tree,
                                  const TreeNodeChunkSource &source) {
  validate_tree_params(tree);
  require(level <= tree.L, "level is out of range");

  TreeLevelDatabase db;
  db.level = level;
  db.R = level >= tree.r ? size_t{1} << (level - tree.r) : size_t{1};
  const size_t node_count = size_t{1} << level;
  db.plaintexts.assign(db.R, std::vector<uint64_t>(tree.n, 0));
  // Sec. 6.1 generalized: record slot u of D_l[p] holds node M[l][p + u*R_l]
  // in the strided coefficients u + j*rho, j < g. Unoccupied slots keep the
  // zero fill.
  for (size_t p = 0; p < db.R; ++p) {
    for (size_t u = 0; u < tree.rho; ++u) {
      const size_t node = p + u * db.R;
      if (node >= node_count) break;
      for (size_t j = 0; j < tree.g; ++j) {
        db.plaintexts[p][u + j * tree.rho] = source(level, node, j) % tree.t;
      }
    }
  }
  return db;
}

TreeLevelDatabase pack_tree_level(size_t level, const TreePirParams &tree,
                                  const TreeNodeSource &source) {
  require(tree.g == 1, "scalar node sources require g = 1");
  return pack_tree_level(
      level, tree,
      TreeNodeChunkSource([&source](size_t l, size_t index, size_t) {
        return source(l, index);
      }));
}

std::vector<TreeLevelDatabase> preprocess_tree_reference(
    const TreePirParams &tree, const TreeNodeChunkSource &source) {
  std::vector<TreeLevelDatabase> levels;
  levels.reserve(tree.L + 1);
  for (size_t level = 0; level <= tree.L; ++level) {
    levels.push_back(pack_tree_level(level, tree, source));
  }
  return levels;
}

std::vector<TreeLevelDatabase> preprocess_tree_reference(
    const TreePirParams &tree, const TreeNodeSource &source) {
  require(tree.g == 1, "scalar node sources require g = 1");
  return preprocess_tree_reference(
      tree, TreeNodeChunkSource([&source](size_t l, size_t index, size_t) {
        return source(l, index);
      }));
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

TreeLevelDatabaseNtt build_level_ntt_view(const TreeLevelDatabase &db,
                                          const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs = scheme.get_rns_mods();
  const size_t K = qs.size();
  TreeLevelDatabaseNtt view;
  view.level = db.level;
  view.R = db.R;
  view.plaintexts.reserve(db.plaintexts.size());
  for (const std::vector<uint64_t> &pt : db.plaintexts) {
    require(pt.size() == N, "canonical plaintext has the wrong degree");
    std::vector<uint64_t> lifted(K * N);
    for (size_t k = 0; k < K; ++k) {
      // Plaintext values are below t < q_k, so the lift per limb is a copy.
      std::copy(pt.begin(), pt.end(), lifted.begin() + k * N);
      utils::ntt_fwd(lifted.data() + k * N, N, qs[k]);
    }
    view.plaintexts.push_back(std::move(lifted));
  }
  return view;
}

PreprocessedTree preprocess_tree_mvp(const TreePirParams &tree,
                                     const TreeNodeChunkSource &source,
                                     const PirParams &scheme) {
  PreprocessedTree result;
  result.plans = build_level_plans(tree);
  result.canonical = preprocess_tree_reference(tree, source);
  if (scheme.get_composite_rns().enabled) {
    result.m32.reserve(result.canonical.size());
    for (size_t level = 0; level < result.canonical.size(); ++level) {
      result.m32.push_back(build_level_m32_view(
          result.canonical[level], result.plans[level], tree, scheme));
    }
  } else {
    result.ntt.reserve(result.canonical.size());
    for (const TreeLevelDatabase &db : result.canonical) {
      result.ntt.push_back(build_level_ntt_view(db, scheme));
    }
  }
  return result;
}

PreprocessedTree preprocess_tree_mvp(const TreePirParams &tree,
                                     const TreeNodeSource &source,
                                     const PirParams &scheme) {
  require(tree.g == 1, "scalar node sources require g = 1");
  return preprocess_tree_mvp(
      tree, TreeNodeChunkSource([&source](size_t l, size_t index, size_t) {
        return source(l, index);
      }),
      scheme);
}

AlphaPyramid pyramid_to_ntt(const AlphaPyramid &pyramid,
                            const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs = scheme.get_rns_mods();
  AlphaPyramid ntt;
  ntt.reserve(pyramid.size());
  for (const std::vector<RlweCt> &row : pyramid) {
    std::vector<RlweCt> out_row;
    out_row.reserve(row.size());
    for (const RlweCt &ct : row) {
      require(!ct.ntt_form, "pyramid must be coefficient form before lifting");
      RlweCt lifted = ct;
      for (size_t k = 0; k < qs.size(); ++k) {
        utils::ntt_fwd(lifted.c0.data() + k * N, N, qs[k]);
        utils::ntt_fwd(lifted.c1.data() + k * N, N, qs[k]);
      }
      lifted.ntt_form = true;
      out_row.push_back(std::move(lifted));
    }
    ntt.push_back(std::move(out_row));
  }
  return ntt;
}

namespace {

// NTT-domain accumulator for one candidate: acc += D_ntt * A_ntt over both
// components, finished by one inverse transform per limb.
struct NttAccumulator {
  std::vector<uint64_t> c0, c1, tmp;
  void reset(size_t size) {
    c0.assign(size, 0);
    c1.assign(size, 0);
    tmp.assign(size, 0);
  }
  void add_product(const std::vector<uint64_t> &pt_ntt, const RlweCt &a_ntt,
                   const PirParams &scheme) {
    constexpr size_t N = DBConsts::PolyDegree;
    const auto &qs = scheme.get_rns_mods();
    for (size_t k = 0; k < qs.size(); ++k) {
      const uint64_t q = qs[k];
      intel::hexl::EltwiseMultMod(tmp.data() + k * N,
                                  pt_ntt.data() + k * N,
                                  a_ntt.c0.data() + k * N, N, q, 1);
      intel::hexl::EltwiseAddMod(c0.data() + k * N, c0.data() + k * N,
                                 tmp.data() + k * N, N, q);
      intel::hexl::EltwiseMultMod(tmp.data() + k * N,
                                  pt_ntt.data() + k * N,
                                  a_ntt.c1.data() + k * N, N, q, 1);
      intel::hexl::EltwiseAddMod(c1.data() + k * N, c1.data() + k * N,
                                 tmp.data() + k * N, N, q);
    }
  }
  RlweCt finish(const PirParams &scheme) {
    constexpr size_t N = DBConsts::PolyDegree;
    const auto &qs = scheme.get_rns_mods();
    RlweCt out;
    out.c0 = std::move(c0);
    out.c1 = std::move(c1);
    out.ntt_form = false;
    for (size_t k = 0; k < qs.size(); ++k) {
      utils::ntt_inv(out.c0.data() + k * N, N, qs[k]);
      utils::ntt_inv(out.c1.data() + k * N, N, qs[k]);
    }
    return out;
  }
};

}  // namespace

namespace {

// Which pyramid row and selection width each plan case consumes.
std::pair<size_t, size_t> plan_row_and_cols(const LevelPlan &plan,
                                            const TreePirParams &tree) {
  switch (plan.select_case) {
    case SelectCase::Single:
      return {tree.a, size_t{1}};
    case SelectCase::CoarsenedAlpha:
      return {plan.coarsen_count, plan.R};
    case SelectCase::AlphaBeta:
      return {size_t{0}, tree.N0};
  }
  throw std::invalid_argument("tree_select: unknown level plan case");
}

}  // namespace

TreeLevelDatabaseM32 build_level_m32_view(const TreeLevelDatabase &db,
                                          const LevelPlan &plan,
                                          const TreePirParams &tree,
                                          const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  const CompositeRnsTables &crt = scheme.get_composite_rns();
  require(crt.enabled, "the m32 view needs a composite configuration");
  require(db.level == plan.level && db.R == plan.R,
          "level database does not match the plan");

  TreeLevelDatabaseM32 view;
  view.level = db.level;
  view.R = db.R;
  const size_t stride =
      plan.select_case == SelectCase::AlphaBeta ? size_t{1} << plan.beta_count
                                                : size_t{1};
  view.rows = plan.select_case == SelectCase::AlphaBeta ? stride : size_t{1};
  view.cols = plan_row_and_cols(plan, tree).second;
  require(view.rows * view.cols == db.R, "m32 view must cover every record");

  const uint64_t q = scheme.get_rns_mods()[0];
  view.lo.assign(N * view.rows * view.cols, 0);
  view.hi.assign(N * view.rows * view.cols, 0);
  std::vector<uint64_t> ntt(N);
  for (size_t row = 0; row < view.rows; ++row) {
    for (size_t col = 0; col < view.cols; ++col) {
      // AlphaBeta consumes the sec. 6.2 matrix view D[col * 2^d + row];
      // the one-row cases scan records in order.
      const size_t p = plan.select_case == SelectCase::AlphaBeta
                           ? col * stride + row
                           : col;
      std::copy(db.plaintexts[p].begin(), db.plaintexts[p].end(), ntt.begin());
      utils::ntt_fwd(ntt.data(), N, q);
      for (size_t coeff = 0; coeff < N; ++coeff) {
        const size_t at = (coeff * view.rows + row) * view.cols + col;
        view.lo[at] = static_cast<uint32_t>(ntt[coeff] % crt.q1);
        view.hi[at] = static_cast<uint32_t>(ntt[coeff] % crt.q2);
      }
    }
  }
  return view;
}

AlphaPyramidM32 pyramid_to_m32(const AlphaPyramid &pyramid_ntt,
                               const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  const CompositeRnsTables &crt = scheme.get_composite_rns();
  require(crt.enabled, "the m32 pyramid needs a composite configuration");
  AlphaPyramidM32 out;
  out.lo.reserve(pyramid_ntt.size());
  out.hi.reserve(pyramid_ntt.size());
  for (const std::vector<RlweCt> &row : pyramid_ntt) {
    std::vector<uint32_t> lo(N * row.size() * 2), hi(N * row.size() * 2);
    for (size_t k = 0; k < row.size(); ++k) {
      require(row[k].ntt_form, "the m32 pyramid consumes the NTT-form pyramid");
      for (size_t coeff = 0; coeff < N; ++coeff) {
        for (size_t comp = 0; comp < 2; ++comp) {
          const uint64_t value =
              comp == 0 ? row[k].c0[coeff] : row[k].c1[coeff];
          const size_t at = (coeff * row.size() + k) * 2 + comp;
          lo[at] = static_cast<uint32_t>(value % crt.q1);
          hi[at] = static_cast<uint32_t>(value % crt.q2);
        }
      }
    }
    out.lo.push_back(std::move(lo));
    out.hi.push_back(std::move(hi));
  }
  return out;
}

RlweCt select_level_m32(const TreeLevelDatabaseM32 &db, const LevelPlan &plan,
                        const AlphaPyramidM32 &pyramid_m32,
                        std::span<GSWCt> beta_selectors, PirServer &mux,
                        const TreePirParams &tree, const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  const CompositeRnsTables &crt = scheme.get_composite_rns();
  require(crt.enabled, "select_level_m32 needs a composite configuration");
  require(db.level == plan.level && db.R == plan.R,
          "level m32 view does not match the plan");
  const auto [pyramid_row, cols] = plan_row_and_cols(plan, tree);
  require(cols == db.cols && pyramid_row < pyramid_m32.lo.size(),
          "pyramid row does not match the m32 view");
  require(pyramid_m32.lo[pyramid_row].size() == N * cols * 2,
          "pyramid row width does not match the m32 view");

  // One 32x32->64 matmul per CRT limb over every NTT coefficient at once,
  // then CRT-compose each candidate and return to coefficient form.
  const size_t out_elems = N * db.rows * 2;
  std::vector<uint64_t> out_lo(out_elems), out_hi(out_elems);
  level_mat_mat_32(db.lo.data(), pyramid_m32.lo[pyramid_row].data(),
                   out_lo.data(), db.rows, db.cols, N, crt.q1);
  level_mat_mat_32(db.hi.data(), pyramid_m32.hi[pyramid_row].data(),
                   out_hi.data(), db.rows, db.cols, N, crt.q2);

  const uint64_t q = scheme.get_rns_mods()[0];
  std::vector<RlweCt> candidates;
  candidates.reserve(db.rows);
  for (size_t row = 0; row < db.rows; ++row) {
    RlweCt ct;
    ct.c0.assign(N, 0);
    ct.c1.assign(N, 0);
    ct.ntt_form = false;
    for (size_t coeff = 0; coeff < N; ++coeff) {
      for (size_t comp = 0; comp < 2; ++comp) {
        const size_t at = (coeff * db.rows + row) * 2 + comp;
        const uint64_t x1 = out_lo[at];
        const uint64_t x2 = out_hi[at];
        // CRT: x = x1 + q1 * ((x2 - x1) * q1^{-1} mod q2), yielding the
        // unique representative below q = q1 * q2.
        const uint64_t diff = (x2 + crt.q2 - x1 % crt.q2) % crt.q2;
        const uint64_t lift =
            static_cast<uint64_t>((static_cast<uint128_t>(diff) *
                                   crt.q1_inv_mod_q2) % crt.q2);
        const uint64_t value = x1 + crt.q1 * lift;
        (comp == 0 ? ct.c0 : ct.c1)[coeff] = value;
      }
    }
    utils::ntt_inv(ct.c0.data(), N, q);
    utils::ntt_inv(ct.c1.data(), N, q);
    candidates.push_back(std::move(ct));
  }

  if (plan.select_case != SelectCase::AlphaBeta) {
    return std::move(candidates.front());
  }
  return fold_beta_dimension(std::move(candidates), plan, beta_selectors,
                             mux);
}

RlweCt select_level_ntt(const TreeLevelDatabaseNtt &db, const LevelPlan &plan,
                        const AlphaPyramid &pyramid_ntt,
                        std::span<GSWCt> beta_selectors, PirServer &mux,
                        const TreePirParams &tree, const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  const size_t K = scheme.K();
  require(db.level == plan.level && db.R == plan.R,
          "level NTT view does not match the plan");
  require(pyramid_ntt.size() == tree.a + 1 &&
              pyramid_ntt[0].size() == tree.N0,
          "alpha pyramid does not match the tree parameters");

  NttAccumulator acc;
  switch (plan.select_case) {
    case SelectCase::Single: {
      acc.reset(K * N);
      acc.add_product(db.plaintexts[0], pyramid_ntt[tree.a][0], scheme);
      return acc.finish(scheme);
    }
    case SelectCase::CoarsenedAlpha: {
      const size_t c = plan.coarsen_count;
      require(pyramid_ntt[c].size() == db.R,
              "coarsened pyramid level does not match R");
      acc.reset(K * N);
      for (size_t k = 0; k < db.R; ++k) {
        acc.add_product(db.plaintexts[k], pyramid_ntt[c][k], scheme);
      }
      return acc.finish(scheme);
    }
    case SelectCase::AlphaBeta: {
      const size_t stride = size_t{1} << plan.beta_count;
      require(db.R == tree.N0 * stride, "AlphaBeta level has R = N0 * 2^d");
      std::vector<RlweCt> candidates;
      candidates.reserve(stride);
      for (size_t delta = 0; delta < stride; ++delta) {
        acc.reset(K * N);
        for (size_t k = 0; k < tree.N0; ++k) {
          acc.add_product(db.plaintexts[k * stride + delta],
                          pyramid_ntt[0][k], scheme);
        }
        candidates.push_back(acc.finish(scheme));
      }
      return fold_beta_dimension(std::move(candidates), plan, beta_selectors,
                                 mux);
    }
  }
  throw std::invalid_argument("tree_select: unknown level plan case");
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
