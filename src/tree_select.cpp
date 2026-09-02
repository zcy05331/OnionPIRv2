#include "tree_select.h"

#include "matrix.h"
#include "utils.h"

#include "hexl/hexl.hpp"

#include <algorithm>
#include <bit>
#include <stdexcept>
#include <string>

namespace {

// 统一的参数守卫：条件不满足即抛 std::invalid_argument，并带 "tree_select:"
// 前缀方便定位是本模块的哪条约束被破坏。
void require(bool condition, const char *message) {
  if (!condition) {
    throw std::invalid_argument(std::string("tree_select: ") + message);
  }
}

// 系数形式全 q 密文的逐 limb 加法：CtAdd 是 RLWE 同态加的最基本形式，
// 首维累加 Σ_k D[k]·A_k 的求和部分全靠它。
void ct_add_inplace(RlweCt &acc, const RlweCt &x, const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs = scheme.get_rns_mods();
  // 守卫：两个输入必须都是系数形式、且长度都等于 K·N（防止 NTT/系数形式
  // 混加或不同 limb 数的密文相加得到无意义结果）。
  require(!acc.ntt_form && !x.ntt_form &&
              acc.c0.size() == x.c0.size() &&
              acc.c0.size() == qs.size() * N,
          "ciphertext addition needs matching coefficient-form inputs");
  // 对每个 RNS limb 分别做模 q_k 的逐系数加：c0、c1 两个分量同时累加，
  // 对应密文加法 (c0+c0', c1+c1')。
  for (size_t k = 0; k < qs.size(); ++k) {
    intel::hexl::EltwiseAddMod(acc.c0.data() + k * N, acc.c0.data() + k * N,
                               x.c0.data() + k * N, N, qs[k]);
    intel::hexl::EltwiseAddMod(acc.c1.data() + k * N, acc.c1.data() + k * N,
                               x.c1.data() + k * N, N, qs[k]);
  }
}

// SplitMix64 的单步混合（固定常数的加-异或-乘雪崩）：用作合成节点数据的
// 确定性伪随机源，保证同一 (level, index) 在任何机器上得到相同节点值。
uint64_t splitmix64_once(uint64_t value) {
  value += 0x9e3779b97f4a7c15ULL;
  value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
  value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
  return value ^ (value >> 31);
}

}  // namespace

// 合成标量节点值（g = 1 测试/基准 oracle）：把 (level, index) 混合成一个
// 确定性的 64 位值再约减 mod t。不是密码学哈希，只求可复现且分布均匀。
uint64_t synthetic_tree_node_value(size_t level, size_t index, uint64_t t) {
  // 守卫：t = 0 时 "% t" 是未定义行为，直接报参数错误。
  if (t == 0) {
    throw std::invalid_argument("synthetic node values need a modulus");
  }
  // 域分隔常数 "treePir" 异或上 level、index 各乘一个大奇数，再过一次
  // SplitMix64 雪崩——保证不同 (level, index) 映射到互不相关的值。
  const uint64_t mixed = splitmix64_once(
      0x74726565506972ULL ^
      (static_cast<uint64_t>(level) * 0xd6e8feb86659fd93ULL) ^
      (static_cast<uint64_t>(index) * 0xa5a3564e27f8862fULL));
  // 约减到明文域 Z_t，直接可写入打包明文。
  return mixed % t;
}

// 合成 32 字节节点（模拟真实场景中哈希/承诺类的 256 位负载）：
// 由 (level, index) 确定性生成 4 个 SplitMix64 字，按小端展开成 32 字节。
std::array<uint8_t, 32> synthetic_tree_node_bytes(size_t level,
                                                  size_t index) {
  std::array<uint8_t, 32> node{};
  // 种子：域分隔常数 "treeNode"（与标量版的 "treePir" 区分开）异或
  // level、index 各乘一个大奇数——同一节点在两种 oracle 下互不混淆。
  uint64_t state = 0x747265654e6f6465ULL ^
                   (static_cast<uint64_t>(level) * 0xd6e8feb86659fd93ULL) ^
                   (static_cast<uint64_t>(index) * 0xa5a3564e27f8862fULL);
  // 4 个 64 位字 = 256 位；每个字加上序号 word 再混合一次，随后按
  // 小端字节序写入 node[word*8 .. word*8+7]。
  for (size_t word = 0; word < 4; ++word) {
    state = splitmix64_once(state + word);
    for (size_t byte = 0; byte < 8; ++byte) {
      node[word * 8 + byte] = static_cast<uint8_t>(state >> (byte * 8));
    }
  }
  return node;
}

// 32 字节合成节点的第 chunk 个分片：把 256 位值按 chunk 宽度切成小端窗口，
// 每个窗口装进一个 Z_t 系数槽位——这是 TreeNodeChunkSource 的测试实现。
uint64_t synthetic_tree_node_bytes_chunk(size_t level, size_t index,
                                         size_t chunk, uint64_t t) {
  // chunk 宽度取方案的可用系数容量：floor(log2(t)) = bit_width(t)−1 位
  // （13 位 t 给 12 位，40 位 t 给 39 位），保证每个分片值严格小于 t，
  // 装入槽位后无信息丢失。
  const size_t width = static_cast<size_t>(std::bit_width(t)) - 1;
  // 守卫：t <= 1 时宽度为 0，分片无法承载任何信息。
  if (width == 0) {
    throw std::invalid_argument(
        "tree_select: node chunks need a plaintext modulus above 1");
  }
  // 重新生成完整 32 字节节点（确定性，无需缓存）。
  const std::array<uint8_t, 32> node = synthetic_tree_node_bytes(level, index);
  // 取 256 位值的小端窗口 [width·chunk, width·(chunk+1))：逐位从字节数组
  // 抽出并放到 value 的第 bit 位；越过第 256 位的部分读作 0（所以尾部
  // 未占用的 chunk 自然为 0，客户端拼回时无需特判）。
  uint64_t value = 0;
  for (size_t bit = 0; bit < width; ++bit) {
    const size_t position = width * chunk + bit;
    if (position >= 256) break;
    const uint8_t byte = node[position / 8];
    value |= static_cast<uint64_t>((byte >> (position % 8)) & 1U) << bit;
  }
  return value;
}

// Algorithm 2 打包核心（chunk 版）：把第 level 层的全部 2^level 个节点写进
// R_ℓ 个规范系数形式明文。布局是整个 g>1 设计的秘密所在（见头文件
// TreeLevelDatabase 注释）：节点按 "node = p + u·R_ℓ" 分配到明文 p 的记录
// 槽位 u，记录的 g 个 chunk 落在跨步系数 {u + j·ρ}。
TreeLevelDatabase pack_tree_level(size_t level, const TreePirParams &tree,
                                  const TreeNodeChunkSource &source) {
  // 守卫：先做整套 §3.2 参数校验，再确认层号没有越过树高 L。
  validate_tree_params(tree);
  require(level <= tree.L, "level is out of range");

  TreeLevelDatabase db;
  db.level = level;
  // R_ℓ = 2^max(ℓ-r, 0)：浅层（ℓ < r，节点数 < ρ）单个明文就装得下全层。
  db.R = level >= tree.r ? size_t{1} << (level - tree.r) : size_t{1};
  const size_t node_count = size_t{1} << level;
  // 先全零初始化：未占用的槽位保持 0，正确性依赖这一点（选择/投影后
  // 非目标格位必须干净）。
  db.plaintexts.assign(db.R, std::vector<uint64_t>(tree.n, 0));
  // §6.1 推广形式：D_ℓ[p] 的记录槽位 u 存节点 M[ℓ][p + u·R_ℓ]，第 j 个
  // chunk 写到系数 u + j·ρ。这样同一记录的所有 chunk 对 ρ 同余于 u，
  // 一次旋转 X^{-γ} 即可全部对齐。
  for (size_t p = 0; p < db.R; ++p) {
    for (size_t u = 0; u < tree.rho; ++u) {
      // 反算该槽位承载的节点号；本层节点用完即停（浅层明文只占前几个
      // 槽位，其余保持零填充）。
      const size_t node = p + u * db.R;
      if (node >= node_count) break;
      // 逐 chunk 写入：数据源已按 mod t 约减，这里再取一次 % t 兜底，
      // 保证明文系数恒在 Z_t 内。
      for (size_t j = 0; j < tree.g; ++j) {
        db.plaintexts[p][u + j * tree.rho] = source(level, node, j) % tree.t;
      }
    }
  }
  return db;
}

// 标量数据源的打包重载：把 TreeNodeSource 适配成忽略 chunk 参数的
// TreeNodeChunkSource，然后复用 chunk 版实现——单一打包逻辑，避免两份漂移。
TreeLevelDatabase pack_tree_level(size_t level, const TreePirParams &tree,
                                  const TreeNodeSource &source) {
  // 守卫：标量源没有 chunk 维度，只在 g = 1 的配置下才有意义。
  require(tree.g == 1, "scalar node sources require g = 1");
  return pack_tree_level(
      level, tree,
      TreeNodeChunkSource([&source](size_t l, size_t index, size_t) {
        return source(l, index);
      }));
}

// Algorithm 2 PreprocessTreeReference（chunk 版）：逐层调用 pack_tree_level，
// 得到全部 L+1 个层数据库——这是服务端离线预处理的规范形式。
std::vector<TreeLevelDatabase> preprocess_tree_reference(
    const TreePirParams &tree, const TreeNodeChunkSource &source) {
  std::vector<TreeLevelDatabase> levels;
  levels.reserve(tree.L + 1);
  for (size_t level = 0; level <= tree.L; ++level) {
    levels.push_back(pack_tree_level(level, tree, source));
  }
  return levels;
}

// 标量数据源的全树打包重载：同样是 g = 1 适配后转发到 chunk 版。
std::vector<TreeLevelDatabase> preprocess_tree_reference(
    const TreePirParams &tree, const TreeNodeSource &source) {
  require(tree.g == 1, "scalar node sources require g = 1");
  return preprocess_tree_reference(
      tree, TreeNodeChunkSource([&source](size_t l, size_t index, size_t) {
        return source(l, index);
      }));
}

// 参考实现的 BFV PtCtMul：明文多项式 pt ∈ Z_t[X]/(X^n+1) 乘进密文的两个
// 分量。由于 Dec(c) = c0 + c1·s，两个分量同乘 pt 即得 Enc(pt·m)。首维
// Σ D[k]·A_k 的标量路径每一项都靠它；优化核只是改变了这一乘法的求值顺序。
RlweCt tree_pt_ct_mul(const std::vector<uint64_t> &pt, const RlweCt &ct,
                      const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs = scheme.get_rns_mods();
  const size_t K = qs.size();
  // 守卫：明文须是 n 次多项式；密文须为系数形式且两分量都覆盖全部 K 个 limb。
  require(pt.size() == N, "plaintext polynomial has the wrong degree");
  require(!ct.ntt_form && ct.c0.size() == K * N && ct.c1.size() == K * N,
          "PtCtMul needs a coefficient-form full-q ciphertext");

  // 每个 limb 做一次参考负循环乘：两操作数都前向 NTT、逐点相乘、再 INTT
  // 回系数形式。明文系数 < t < q_k，同一份系数值对每个 limb 都是合法代表元，
  // 无需按 limb 做中心化提升。
  RlweCt result;
  result.c0.assign(K * N, 0);
  result.c1.assign(K * N, 0);
  result.ntt_form = false;
  // pt_ntt/component 是逐 limb 复用的临时缓冲，避免在循环里反复分配。
  std::vector<uint64_t> pt_ntt(N), component(N);
  for (size_t k = 0; k < K; ++k) {
    const uint64_t q = qs[k];
    // 明文提升到 limb k 并前向 NTT（每 limb 一次，供 c0/c1 两次点乘共用）。
    std::copy(pt.begin(), pt.end(), pt_ntt.begin());
    utils::ntt_fwd(pt_ntt.data(), N, q);
    // 依次处理 c0（second=false）与 c1（second=true）：拷出该 limb 的分量、
    // NTT、与 pt_ntt 逐点乘、INTT 回系数形式、写回结果对应位置。
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

// 构建 α 部分和金字塔（§10）：由展开得到的 N0 维 one-hot 向量 A^(0)，
// 只用密文加法逐层求相邻对之和，得到全部 a+1 个分辨率的 one-hot 视图。
// 关键洞察：Σ_{i∈子树} [α == i] = [⌊α/2^c⌋ == j]——粗化层直接复用上层部分和，
// 免去第二次查询展开，也免去粗化层各自的密文-明文乘。噪声只按加法线性增长。
AlphaPyramid build_alpha_pyramid(std::span<const RlweCt> alpha_cts,
                                 const TreePirParams &tree,
                                 const PirParams &scheme) {
  // 守卫：输入必须恰是展开出的 N0 条 one-hot 密文（多/少都说明展开配置错）。
  require(alpha_cts.size() == tree.N0,
          "alpha pyramid needs the N0 expanded one-hot ciphertexts");
  AlphaPyramid pyramid;
  pyramid.reserve(tree.a + 1);
  // 第 0 层就是展开结果 A^(0) 本身（拷贝一份，调用方保留原件）。
  pyramid.emplace_back(alpha_cts.begin(), alpha_cts.end());
  // §10 递推：A^(c+1)_j = A^(c)_{2j} + A^(c)_{2j+1}。归纳可证第 c 层
  // one-hot 选中 ⌊α/2^c⌋；塔顶 A^(a)_0 是全体指示值之和，恒加密 1。
  for (size_t c = 0; c < tree.a; ++c) {
    const std::vector<RlweCt> &prev = pyramid.back();
    std::vector<RlweCt> next;
    next.reserve(prev.size() / 2);
    // 相邻配对求和：每层规模减半，总加法次数为 N0 − 1。
    for (size_t j = 0; j < prev.size() / 2; ++j) {
      RlweCt sum = prev[2 * j];
      ct_add_inplace(sum, prev[2 * j + 1], scheme);
      next.push_back(std::move(sum));
    }
    pyramid.push_back(std::move(next));
  }
  return pyramid;
}

// AlphaBeta 情形的首维求值（标量参考路径，§11.2）：把 R = N0·2^d 个明文
// 视作 §6.2 的 N0×2^d 矩阵 D_ℓ[k, δ] = D_ℓ[k·2^d + δ]，对每列 δ 计算
// Y[δ] = Σ_k D_ℓ[k, δ]·A^(0)_k。由于 A^(0) 是 α 的 one-hot，Y[δ] 恰加密
// D_ℓ[α·2^d + δ]——α 维被同态"消掉"，剩下 2^d 个 β 候选。
std::vector<RlweCt> evaluate_alpha_dimension(const TreeLevelDatabase &db,
                                             std::span<const RlweCt> alpha,
                                             const LevelPlan &plan,
                                             const TreePirParams &tree,
                                             const PirParams &scheme) {
  // 守卫组：本函数只服务 AlphaBeta 情形；db 与 plan 必须描述同一层；
  // α 向量必须是完整的 N0 条 one-hot 密文。
  require(plan.select_case == SelectCase::AlphaBeta,
          "alpha dimension evaluation applies to the AlphaBeta case");
  require(db.level == plan.level && db.R == plan.R,
          "level database does not match the plan");
  require(alpha.size() == tree.N0, "alpha vector must have N0 entries");
  // 矩阵列数 = β 候选数 2^{d_ℓ}；AlphaBeta 层的记录数必须恰好铺满矩阵。
  const size_t stride = size_t{1} << plan.beta_count;  // 2^{d_l}
  require(db.R == tree.N0 * stride, "AlphaBeta level has R = N0 * 2^d");

  // §11.2 主循环：候选 δ 累加 D_ℓ[k·2^d + δ] · A_k（k 扫过整个首维）。
  // 候选按 δ 的自然整数序压入——后续 β 折叠的 MSB-first 配对依赖此顺序。
  std::vector<RlweCt> candidates;
  candidates.reserve(stride);
  for (size_t delta = 0; delta < stride; ++delta) {
    // k = 0 项直接作为累加器初值，省一次全零密文的构造与加法。
    RlweCt acc = tree_pt_ct_mul(db.plaintexts[delta], alpha[0], scheme);
    for (size_t k = 1; k < tree.N0; ++k) {
      // 逐项 PtCtMul 后 CtAdd：这是最朴素的内积求值，优化核用 NTT 域
      // 累加/矩阵乘替换的正是这段循环。
      RlweCt term =
          tree_pt_ct_mul(db.plaintexts[k * stride + delta], alpha[k], scheme);
      ct_add_inplace(acc, term, scheme);
    }
    candidates.push_back(std::move(acc));
  }
  return candidates;
}

// β 折叠（§11.3 第 4.5 步）：用 RGSW 位选择器把 2^d 个候选二分收敛到 1 个。
// 每步对位 β_u 做 CMux：位为 0 保留下半，位为 1 保留上半，然后数组截半。
// 候选按 δ 的自然整数序排列，因此必须先消耗剩余 δ 的最高位（MSB-first）：
// 下半数组正是 "β_u = 0" 的那一半、上半是 "β_u = 1" 的那一半；LSB-first
// 会把不相邻的候选配成对，对非对称目标必错（明文模型 + 突变实验已验证）。
RlweCt fold_beta_dimension(std::vector<RlweCt> candidates,
                           const LevelPlan &plan,
                           std::span<GSWCt> beta_selectors, PirServer &mux) {
  // 守卫：候选数必须恰为 2^{beta_count}（否则截半流程会失衡）；
  // 活跃位窗口 [beta_begin, beta_begin+beta_count) 必须整个落在选择器数组内。
  require(candidates.size() == size_t{1} << plan.beta_count,
          "candidate count must be 2^{beta_count}");
  require(plan.beta_begin + plan.beta_count <= beta_selectors.size() ||
              plan.beta_count == 0,
          "fold needs a selector for every active beta bit");

  // 主循环：step 从 0 走到 beta_count−1，对应位号 u 从最高位
  // beta_begin+beta_count−1 递减到 beta_begin（即 MSB-first）。
  for (size_t step = 0; step < plan.beta_count; ++step) {
    const size_t u = plan.beta_begin + plan.beta_count - 1 - step;
    const size_t half = candidates.size() / 2;
    // 对每个下标 j 做 CMux(S^β_u, 下半 candidates[j], 上半 candidates[j+half])，
    // 结果写回 candidates[j]。ext_prod_mux 允许结果与 x 别名、且会破坏 y——
    // 这里都无妨：上半在本步结束后立即被 resize 截掉。
    for (size_t j = 0; j < half; ++j) {
      mux.ext_prod_mux(candidates[j], candidates[j + half], beta_selectors[u],
                       candidates[j]);
    }
    // 截半：本步位已消耗，剩余候选对应剩余 δ 位的所有取值。
    candidates.resize(half);
  }
  // 守卫：d 步截半后必然只剩一个候选——它加密的正是 D_ℓ[p_ℓ]。
  require(candidates.size() == 1, "fold must end with a single candidate");
  return std::move(candidates.front());
}

// 构建 NTT-u64 优化视图（Milestone-6，§6.3 第 1 步）：预处理期把每个规范
// 明文提升到每个 RNS limb 并各做一次前向 NTT。此后每次查询只需 NTT 域逐点
// 乘累加——数据库侧的前向 NTT 从"每查询每项一次"变成"预处理期一次"。
TreeLevelDatabaseNtt build_level_ntt_view(const TreeLevelDatabase &db,
                                          const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs = scheme.get_rns_mods();
  const size_t K = qs.size();
  // 元数据（层号、R）原样携带，供后续核与 plan 匹配校验。
  TreeLevelDatabaseNtt view;
  view.level = db.level;
  view.R = db.R;
  view.plaintexts.reserve(db.plaintexts.size());
  for (const std::vector<uint64_t> &pt : db.plaintexts) {
    // 守卫：规范明文必须是 n 次多项式。
    require(pt.size() == N, "canonical plaintext has the wrong degree");
    // 每个明文展成 K·N 的 limb-major 缓冲：明文系数 < t < q_k，对每个
    // limb 都是合法代表元，"提升"就是逐 limb 拷贝，随后原位前向 NTT。
    std::vector<uint64_t> lifted(K * N);
    for (size_t k = 0; k < K; ++k) {
      std::copy(pt.begin(), pt.end(), lifted.begin() + k * N);
      utils::ntt_fwd(lifted.data() + k * N, N, qs[k]);
    }
    view.plaintexts.push_back(std::move(lifted));
  }
  return view;
}

// MVP 预处理入口（蓝图 §19 PreprocessedTree）：一次性产出应答路径需要的
// 全部离线材料——公开 plan、规范层数据库、以及按方案配置二选一的优化视图。
PreprocessedTree preprocess_tree_mvp(const TreePirParams &tree,
                                     const TreeNodeChunkSource &source,
                                     const PirParams &scheme) {
  PreprocessedTree result;
  // 公开的逐层选择计划（只依赖参数，不依赖数据），供每层核选择分支。
  result.plans = build_level_plans(tree);
  // 规范系数形式的全树打包（Algorithm 2）。
  result.canonical = preprocess_tree_reference(tree, source);
  // 优化视图二选一：复合模数配置建 m32、留空 ntt；否则建 ntt、留空 m32。
  // 两种视图等大（8 B/系数），同时保留会让数据库内存翻倍。
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

// 标量数据源的 MVP 预处理重载：g = 1 适配后转发到 chunk 版。
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

// 金字塔的查询期 NTT 提升（§6.3 第 2 步）：把整座 α 金字塔的每条密文各做
// 一次前向 NTT。这是每次查询的一次性成本，此后所有层的首维都在 NTT 域
// 逐点相乘，无需再对查询侧密文做任何前向变换。
AlphaPyramid pyramid_to_ntt(const AlphaPyramid &pyramid,
                            const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs = scheme.get_rns_mods();
  AlphaPyramid ntt;
  ntt.reserve(pyramid.size());
  // 逐行逐密文变换：行结构（分辨率层次）原样保留，消费方按同样的
  // (c, j) 下标取用。
  for (const std::vector<RlweCt> &row : pyramid) {
    std::vector<RlweCt> out_row;
    out_row.reserve(row.size());
    for (const RlweCt &ct : row) {
      // 守卫：防止对已是 NTT 形式的密文重复变换（那会得到无意义数据）。
      require(!ct.ntt_form, "pyramid must be coefficient form before lifting");
      // 拷贝后对 c0/c1 的每个 limb 原位前向 NTT，并打上 ntt_form 标记，
      // 让下游核能校验输入形式。
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

// 单个候选的 NTT 域累加器：acc += D_ntt · A_ntt 对 c0/c1 两个分量同时进行，
// 最后每个 limb 各做一次 INTT 收尾。正确性根基是 INTT 的线性：
// INTT(Σ 点乘) = Σ INTT(点乘)，且 mod-q 算术精确，所以整段求和只花一次
// 逆变换，结果与标量路径按位相同。
struct NttAccumulator {
  // c0/c1 是 NTT 域的部分和；tmp 是逐项点乘的临时缓冲（复用避免反复分配）。
  std::vector<uint64_t> c0, c1, tmp;
  // 清零到 K·N 大小，开始一个新候选的累加。
  void reset(size_t size) {
    c0.assign(size, 0);
    c1.assign(size, 0);
    tmp.assign(size, 0);
  }
  // 累加一项 D[k]·A_k：对每个 RNS limb 做 NTT 域逐点乘（明文 × 密文分量），
  // 再逐点加进部分和；c0、c1 各一次——对应 PtCtMul 作用于密文两个分量。
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
  // 收尾：把部分和移动进结果密文，每个 limb 各做一次 INTT 回到系数形式。
  // 整个候选的求和只在这里付一次逆变换成本。
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

// 三种 plan 情形各自消费的金字塔行号与选择向量宽度 (row, cols)：
//   Single         → 塔顶行 a，宽度 1（只用恒加密 1 的 A^(a)_0）；
//   CoarsenedAlpha → 粗化行 coarsen_count，宽度 R（⌊α/2^c⌋ 的 R 维 one-hot）；
//   AlphaBeta      → 底行 0，宽度 N0（完整的 A^(0) one-hot）。
// 把这一映射独立成函数，使 m32 视图构建与 m32 核共享同一份约定，不会漂移。
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
  // 枚举值损坏（内存越界等）才会到达这里。
  throw std::invalid_argument("tree_select: unknown level plan case");
}

}  // namespace

// 构建 m32 矩阵核视图（Milestone-6 完整核，预处理期）：对每个明文做一次
// mod q 的前向 NTT，把 NTT 值按复合模数 q = q1·q2 取余拆成两组 u32，并重排
// 成 level_mat_mat_32 所需的 coefficient-major A 操作数布局
// data[(coeff·rows + row)·cols + col]——同一 NTT 系数下所有 (row, col) 连续，
// 矩阵核可对每个系数独立跑一个小矩阵乘。
TreeLevelDatabaseM32 build_level_m32_view(const TreeLevelDatabase &db,
                                          const LevelPlan &plan,
                                          const TreePirParams &tree,
                                          const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  const CompositeRnsTables &crt = scheme.get_composite_rns();
  // 守卫：q1/q2 拆分表只在复合模数配置下存在；db 与 plan 必须描述同一层。
  require(crt.enabled, "the m32 view needs a composite configuration");
  require(db.level == plan.level && db.R == plan.R,
          "level database does not match the plan");

  TreeLevelDatabaseM32 view;
  view.level = db.level;
  view.R = db.R;
  // 矩阵形状：AlphaBeta 有 2^d 个候选行、其余情形单行；列宽由
  // plan_row_and_cols 给出（1 / R / N0），且必须 rows·cols = R 覆盖全部记录。
  const size_t stride =
      plan.select_case == SelectCase::AlphaBeta ? size_t{1} << plan.beta_count
                                                : size_t{1};
  view.rows = plan.select_case == SelectCase::AlphaBeta ? stride : size_t{1};
  view.cols = plan_row_and_cols(plan, tree).second;
  require(view.rows * view.cols == db.R, "m32 view must cover every record");

  // 复合配置只有一个 RNS limb（q = q1·q2 装在 rns_mods[0]），NTT 就按它做。
  const uint64_t q = scheme.get_rns_mods()[0];
  view.lo.assign(N * view.rows * view.cols, 0);
  view.hi.assign(N * view.rows * view.cols, 0);
  std::vector<uint64_t> ntt(N);
  for (size_t row = 0; row < view.rows; ++row) {
    for (size_t col = 0; col < view.cols; ++col) {
      // 明文下标映射：AlphaBeta 消费 §6.2 矩阵视图 D[col·2^d + row]
      // （col=k 扫首维、row=δ 是候选）；单行情形按记录顺序 p = col 扫描。
      const size_t p = plan.select_case == SelectCase::AlphaBeta
                           ? col * stride + row
                           : col;
      // 该明文做一次 mod q 前向 NTT（预处理期一次性成本）。
      std::copy(db.plaintexts[p].begin(), db.plaintexts[p].end(), ntt.begin());
      utils::ntt_fwd(ntt.data(), N, q);
      // 逐 NTT 系数按 q1/q2 取余得到两个 32 位 CRT limb，写入
      // coefficient-major 位置：这一步既是 CRT 拆分也是布局转置。
      for (size_t coeff = 0; coeff < N; ++coeff) {
        const size_t at = (coeff * view.rows + row) * view.cols + col;
        view.lo[at] = static_cast<uint32_t>(ntt[coeff] % crt.q1);
        view.hi[at] = static_cast<uint32_t>(ntt[coeff] % crt.q2);
      }
    }
  }
  return view;
}

// 金字塔的 m32 拆分（查询期一次，所有层共享）：把 NTT 形式金字塔的每条密文
// 按 q1/q2 取余成两组 u32，并排成矩阵核 B 操作数的布局
// data[(coeff·cols + col)·2 + comp]——col 对应金字塔条目 k（矩阵乘的求和维），
// comp∈{0,1} 对应 c0/c1（作为 B 的两个输出通道一起被乘）。
AlphaPyramidM32 pyramid_to_m32(const AlphaPyramid &pyramid_ntt,
                               const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  const CompositeRnsTables &crt = scheme.get_composite_rns();
  // 守卫：CRT 拆分表只在复合模数配置下可用。
  require(crt.enabled, "the m32 pyramid needs a composite configuration");
  AlphaPyramidM32 out;
  out.lo.reserve(pyramid_ntt.size());
  out.hi.reserve(pyramid_ntt.size());
  // 每个金字塔行独立生成一对 (lo, hi) 缓冲：行 c 的 cols = row.size()，
  // 与该行被消费时的选择宽度一致。
  for (const std::vector<RlweCt> &row : pyramid_ntt) {
    std::vector<uint32_t> lo(N * row.size() * 2), hi(N * row.size() * 2);
    for (size_t k = 0; k < row.size(); ++k) {
      // 守卫：必须消费 pyramid_to_ntt 的输出（系数形式在此无意义）。
      require(row[k].ntt_form, "the m32 pyramid consumes the NTT-form pyramid");
      // 逐 NTT 系数、逐分量取 mod q1 / mod q2，写入 B 布局位置。
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

// Milestone-6 完整矩阵核版 SelectLevel：与标量/NTT 路径求同一个环表达式
// Y[row] = Σ_col D[row,col]·A_col，但把 NTT 域点乘累加改写成每个 CRT limb
// 一次 32×32→64 的矩阵乘（延迟规约），随后 CRT 合成回 mod q、每候选一次
// INTT。mod-q 算术精确 + CRT 合成返回规范代表元 ⇒ 输出与另两条路径按位一致。
RlweCt select_level_m32(const TreeLevelDatabaseM32 &db, const LevelPlan &plan,
                        const AlphaPyramidM32 &pyramid_m32,
                        std::span<GSWCt> beta_selectors, PirServer &mux,
                        const TreePirParams &tree, const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  const CompositeRnsTables &crt = scheme.get_composite_rns();
  // 守卫组：复合配置才有 m32 核；视图与 plan 必须同层；金字塔行号、行宽都
  // 要与视图的列宽一致（防止拿错分辨率或形状不匹配的缓冲相乘）。
  require(crt.enabled, "select_level_m32 needs a composite configuration");
  require(db.level == plan.level && db.R == plan.R,
          "level m32 view does not match the plan");
  const auto [pyramid_row, cols] = plan_row_and_cols(plan, tree);
  require(cols == db.cols && pyramid_row < pyramid_m32.lo.size(),
          "pyramid row does not match the m32 view");
  require(pyramid_m32.lo[pyramid_row].size() == N * cols * 2,
          "pyramid row width does not match the m32 view");

  // 每个 CRT limb 跑一次 level_mat_mat_32：对全部 N 个 NTT 系数一次性完成
  // rows×cols 与 cols×2 的 32×32→64 矩阵乘（内部延迟规约到 mod q1 / q2）。
  // 输出布局与金字塔 B 布局同构：out[(coeff·rows + row)·2 + comp]。
  TIME_START(TREE_SCAN_TIME);
  const size_t out_elems = N * db.rows * 2;
  std::vector<uint64_t> out_lo(out_elems), out_hi(out_elems);
  level_mat_mat_32(db.lo.data(), pyramid_m32.lo[pyramid_row].data(),
                   out_lo.data(), db.rows, db.cols, N, crt.q1);
  level_mat_mat_32(db.hi.data(), pyramid_m32.hi[pyramid_row].data(),
                   out_hi.data(), db.rows, db.cols, N, crt.q2);

  // 复合配置下唯一的 RNS limb 就是 q = q1·q2，INTT 按它做。
  const uint64_t q = scheme.get_rns_mods()[0];
  std::vector<RlweCt> candidates;
  candidates.reserve(db.rows);
  // 逐候选行做 CRT 合成 + INTT，还原成系数形式的 RLWE 密文。
  for (size_t row = 0; row < db.rows; ++row) {
    RlweCt ct;
    ct.c0.assign(N, 0);
    ct.c1.assign(N, 0);
    ct.ntt_form = false;
    for (size_t coeff = 0; coeff < N; ++coeff) {
      for (size_t comp = 0; comp < 2; ++comp) {
        // 取出该 (系数, 候选, 分量) 在两个 limb 下的残差 x1 = x mod q1、
        // x2 = x mod q2。
        const size_t at = (coeff * db.rows + row) * 2 + comp;
        const uint64_t x1 = out_lo[at];
        const uint64_t x2 = out_hi[at];
        // Garner 式 CRT 合成：x = x1 + q1·((x2 − x1)·q1^{-1} mod q2)。
        // diff 先把 x1 约减到 mod q2 再做非负减法；乘 q1^{-1} (mod q2) 用
        // u128 防溢出。结果是 [0, q1·q2) 内的唯一规范代表元——正因为返回
        // 的是规范代表元，逐位一致性才能对标量路径成立。
        const uint64_t diff = (x2 + crt.q2 - x1 % crt.q2) % crt.q2;
        const uint64_t lift =
            static_cast<uint64_t>((static_cast<uint128_t>(diff) *
                                   crt.q1_inv_mod_q2) % crt.q2);
        const uint64_t value = x1 + crt.q1 * lift;
        (comp == 0 ? ct.c0 : ct.c1)[coeff] = value;
      }
    }
    // 每候选一次 INTT：与 NTT 路径同一收尾（INTT 线性保证求和可后置）。
    utils::ntt_inv(ct.c0.data(), N, q);
    utils::ntt_inv(ct.c1.data(), N, q);
    candidates.push_back(std::move(ct));
  }
  TIME_END(TREE_SCAN_TIME);

  // Single / CoarsenedAlpha 情形只有单行输出，直接就是 C_ℓ；
  // AlphaBeta 情形还需把 2^d 个候选做 MSB-first β 折叠。
  if (plan.select_case != SelectCase::AlphaBeta) {
    return std::move(candidates.front());
  }
  TIME_START(TREE_FOLD_TIME);
  RlweCt folded = fold_beta_dimension(std::move(candidates), plan,
                                      beta_selectors, mux);
  TIME_END(TREE_FOLD_TIME);
  return folded;
}

// NTT-u64 优化版 SelectLevel（Milestone-6，§6.3）：与 select_level 逐分支
// 对应、求同一个环表达式，只是每一项 PtCtMul 换成 NTT 域逐点乘累加，
// 每个候选只在收尾付一次 INTT。三种情形消费的金字塔行与标量路径一致。
RlweCt select_level_ntt(const TreeLevelDatabaseNtt &db, const LevelPlan &plan,
                        const AlphaPyramid &pyramid_ntt,
                        std::span<GSWCt> beta_selectors, PirServer &mux,
                        const TreePirParams &tree, const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  const size_t K = scheme.K();
  // 守卫：视图与 plan 必须同层；金字塔必须有全部 a+1 行且底行宽 N0。
  require(db.level == plan.level && db.R == plan.R,
          "level NTT view does not match the plan");
  require(pyramid_ntt.size() == tree.a + 1 &&
              pyramid_ntt[0].size() == tree.N0,
          "alpha pyramid does not match the tree parameters");

  NttAccumulator acc;
  TIME_START(TREE_SCAN_TIME);
  switch (plan.select_case) {
    case SelectCase::Single: {
      // R = 1：唯一明文乘塔顶 A^(a)_0（恒加密 1），一次点乘即完成选择。
      acc.reset(K * N);
      acc.add_product(db.plaintexts[0], pyramid_ntt[tree.a][0], scheme);
      RlweCt out = acc.finish(scheme);
      TIME_END(TREE_SCAN_TIME);
      return out;
    }
    case SelectCase::CoarsenedAlpha: {
      // 1 < R < N0：粗化行 c 恰是 R 维 one-hot，Σ_k D[k]·A^(c)_k 选出
      // 下标 ⌊α/2^c⌋ 的明文。
      const size_t c = plan.coarsen_count;
      require(pyramid_ntt[c].size() == db.R,
              "coarsened pyramid level does not match R");
      acc.reset(K * N);
      for (size_t k = 0; k < db.R; ++k) {
        acc.add_product(db.plaintexts[k], pyramid_ntt[c][k], scheme);
      }
      RlweCt out = acc.finish(scheme);
      TIME_END(TREE_SCAN_TIME);
      return out;
    }
    case SelectCase::AlphaBeta: {
      // R = N0·2^d：对每个 δ 用底行 A^(0) 做首维内积（同
      // evaluate_alpha_dimension 的矩阵视图），再 β 折叠收敛到单候选。
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
      TIME_END(TREE_SCAN_TIME);
      TIME_START(TREE_FOLD_TIME);
      RlweCt folded = fold_beta_dimension(std::move(candidates), plan,
                                          beta_selectors, mux);
      TIME_END(TREE_FOLD_TIME);
      return folded;
    }
  }
  TIME_END(TREE_SCAN_TIME);
  // 枚举值损坏时的兜底。
  throw std::invalid_argument("tree_select: unknown level plan case");
}

// Algorithm 4 SelectLevel（标量参考路径）：按公开 plan 的三个互斥情形返回
// 加密 D_ℓ[p_ℓ] 的密文 C_ℓ。它是 test_tree_kernel 逐位对拍的基准实现；
// 分支与循环次数只依赖公开量，私密坐标只经由金字塔/selector 密文进入。
RlweCt select_level(const TreeLevelDatabase &db, const LevelPlan &plan,
                    const AlphaPyramid &pyramid,
                    std::span<GSWCt> beta_selectors, PirServer &mux,
                    const TreePirParams &tree, const PirParams &scheme) {
  // 守卫：数据库与 plan 必须描述同一层；金字塔须有全部 a+1 行、底行宽 N0。
  require(db.level == plan.level && db.R == plan.R,
          "level database does not match the plan");
  require(pyramid.size() == tree.a + 1 && pyramid[0].size() == tree.N0,
          "alpha pyramid does not match the tree parameters");

  switch (plan.select_case) {
    case SelectCase::Single: {
      // §11.3 情形 R = 1：全层只有一个明文，无需任何选择。乘上塔顶
      // A^(a)_0（恒加密常数 1）即把明文"抬"成密文，且保持与其余分支
      // 一致的输出噪声形态。
      return tree_pt_ct_mul(db.plaintexts[0], pyramid[tree.a][0], scheme);
    }
    case SelectCase::CoarsenedAlpha: {
      // §11.3 情形 1 < R < N0：粗化行 c = a − log2(R) 恰是 R 维 one-hot，
      // 对 ⌊α/2^c⌋ 选一——内积 Σ_k D[k]·A^(c)_k 只留目标明文。
      const size_t c = plan.coarsen_count;
      require(pyramid[c].size() == db.R,
              "coarsened pyramid level does not match R");
      // k = 0 项作累加器初值，其余项逐个 PtCtMul + CtAdd。
      RlweCt acc = tree_pt_ct_mul(db.plaintexts[0], pyramid[c][0], scheme);
      for (size_t k = 1; k < db.R; ++k) {
        RlweCt term = tree_pt_ct_mul(db.plaintexts[k], pyramid[c][k], scheme);
        ct_add_inplace(acc, term, scheme);
      }
      return acc;
    }
    case SelectCase::AlphaBeta: {
      // §11.3 情形 R >= N0：先用完整 one-hot A^(0) 消掉 α 维得到 2^d 个
      // β 候选，再用 RGSW 选择器 MSB-first 折叠出唯一目标。
      std::vector<RlweCt> candidates =
          evaluate_alpha_dimension(db, pyramid[0], plan, tree, scheme);
      return fold_beta_dimension(std::move(candidates), plan, beta_selectors,
                                 mux);
    }
  }
  // 枚举值损坏时的兜底。
  throw std::invalid_argument("tree_select: unknown level plan case");
}
