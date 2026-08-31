#pragma once

#include "server.h"
#include "tree_index.h"
#include "tree_query.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>

// 本文件是 Binary Tree PIR 的"数据库打包 + 首维选择(SelectLevel) + β 折叠"层
// （蓝图 §6、§10、§11，Milestone-2）。此处声明的基础实现全部是标量/参考路径：
//   - 规范(canonical)系数形式的逐层数据库（系数取值 mod t）；
//   - α 维用朴素的 PtCtMul + CtAdd 循环逐项累加；
//   - β 维用"一次外积"的 CMux 逐位折叠。
// 优化核（NTT-u64 视图与 m32 矩阵核，§6.3，Milestone-6）在相同接口后面做
// drop-in 替换，输出与参考路径按位精确一致（test_tree_kernel 三方验证）。

// 一个打包后的层数据库（§6.1，推广到每节点 g 个槽位）：第 ℓ 层共
// R_ℓ = 2^max(ℓ-r,0) 个明文多项式。D_ℓ[p] 的记录槽位 u 存放节点
// M[ℓ][p + u·R_ℓ]，其 g 个 chunk 落在"跨步"系数 {u + j·ρ : j ∈ [0, g)} 上。
// 采用跨步布局的原因（g>1 的核心技巧）：一次旋转 X^{-γ_ℓ}（γ_ℓ < ρ）就能把
// 目标记录的全部 g 个 chunk 同时对齐到格位 {j·ρ}；而满深度投影的保留格
// {0, ρ, 2ρ, …} 恰好就是这些 chunk 所在的位置。g = 1 时退化为
// plaintexts[p][u] 的连续布局。
struct TreeLevelDatabase {
  // 该数据库对应的树层号 ℓ（0 = 根，L = 叶层）。
  size_t level = 0;
  // 本层明文多项式个数 R_ℓ = 2^max(ℓ-r,0)。
  size_t R = 0;
  // 规范系数形式的 Z_t 多项式，每个长度 n，系数均已约减到 [0, t)。
  std::vector<std::vector<uint64_t>> plaintexts;
};

// g = 1 专用的标量节点数据源：返回节点 M[level][index] 的值（已约减 mod t）。
using TreeNodeSource = std::function<uint64_t(size_t level, size_t index)>;
// 通用节点数据源：返回 M[level][index] 的第 chunk 个（共 g 个）分片，
// 已约减 mod t；32 字节节点等多 chunk 负载走这条接口。
using TreeNodeChunkSource =
    std::function<uint64_t(size_t level, size_t index, size_t chunk)>;

// 确定性合成节点值（§18）：对 (level, index) 做固定常数的 SplitMix64 混合后
// 约减 mod t。仅供基准/测试当 oracle 用，不是密码学哈希。
uint64_t synthetic_tree_node_value(size_t level, size_t index, uint64_t t);

// 确定性合成 32 字节节点（真实场景的负载形态）及其小端 chunk 分解。
// chunk 宽度取方案槽位容量 floor(log2(t)) = bit_width(t)−1 位：chunk j 携带
// 256 位值的第 [w·j, w·(j+1)) 位，越过末端的位一律读作 0
// （12 位 chunk 时 g=32 中占用 22 个；39 位 chunk 时 g=8 中占用 7 个）。
std::array<uint8_t, 32> synthetic_tree_node_bytes(size_t level, size_t index);
uint64_t synthetic_tree_node_bytes_chunk(size_t level, size_t index,
                                         size_t chunk, uint64_t t);

// Algorithm 2 PreprocessTreeReference：打包单个层 / 全部层 0..L。
// TreeNodeSource 重载要求 g = 1（标量节点）；chunk 重载接受任何通过校验的 g。
TreeLevelDatabase pack_tree_level(size_t level, const TreePirParams &tree,
                                  const TreeNodeSource &source);
TreeLevelDatabase pack_tree_level(size_t level, const TreePirParams &tree,
                                  const TreeNodeChunkSource &source);
std::vector<TreeLevelDatabase> preprocess_tree_reference(
    const TreePirParams &tree, const TreeNodeSource &source);
std::vector<TreeLevelDatabase> preprocess_tree_reference(
    const TreePirParams &tree, const TreeNodeChunkSource &source);

// 参考实现的 BFV 明文-密文乘：把一个 Z_t 多项式与密文两个分量 (c0, c1) 在
// 每个 RNS limb 下做负循环多项式乘。输入/输出均为系数形式的全 q 密文。
RlweCt tree_pt_ct_mul(const std::vector<uint64_t> &pt, const RlweCt &ct,
                      const PirParams &scheme);

// 粗化 α 金字塔（§10）：pyramid[c][j] 加密指示值 [⌊α/2^c⌋ == j]，由展开得到
// 的 one-hot 只用密文加法逐层构建（无密文-明文乘、无第二次展开、无额外密钥）。
// pyramid[0] 即 A^(0)（长度 N0）；塔顶 pyramid[a][0] 恒加密常数 1。
using AlphaPyramid = std::vector<std::vector<RlweCt>>;
AlphaPyramid build_alpha_pyramid(std::span<const RlweCt> alpha_cts,
                                 const TreePirParams &tree,
                                 const PirParams &scheme);

// AlphaBeta 情形的首维求值（§11.2）：Y[δ] = Σ_k D_ℓ[k, δ] · A^(0)_k，其中
// §6.2 的矩阵视图取 D_ℓ[k, δ] = D_ℓ[k·2^d + δ]，d = plan.beta_count。
// 返回按 δ 自然整数序排列的 2^d 个候选密文——这一顺序正是后续 β 折叠
// 必须 MSB-first 消耗的原因。
std::vector<RlweCt> evaluate_alpha_dimension(const TreeLevelDatabase &db,
                                             std::span<const RlweCt> alpha,
                                             const LevelPlan &plan,
                                             const TreePirParams &tree,
                                             const PirParams &scheme);

// β 折叠（§11.3 第 4.5 步）：按 MSB-first 顺序依次消耗活跃位
// β_{b−1}, …, β_{begin}，每步用 CMux(S^β_u, 下半, 上半) 把候选数组截半。
// beta_selectors 是完整的 b 长选择器数组，按全局位号索引；mux 提供仓库的
// "一次外积" CMux（ext_prod_mux），须与 scheme 兼容。
// 注意：改成 LSB-first 消耗顺序会配错候选对（test_tree_select 有
// "突变必死"回归守护此位序）。
RlweCt fold_beta_dimension(std::vector<RlweCt> candidates,
                           const LevelPlan &plan,
                           std::span<GSWCt> beta_selectors, PirServer &mux);

// Algorithm 4 SelectLevel：在三个互斥的 plan 情形（Single / CoarsenedAlpha /
// AlphaBeta）下返回加密 D_ℓ[p_ℓ] 的密文 C_ℓ。所有分支与循环次数只依赖公开的
// plan；私密信息只通过金字塔与 selector 密文进入——访问模式对查询零泄漏。
RlweCt select_level(const TreeLevelDatabase &db, const LevelPlan &plan,
                    const AlphaPyramid &pyramid,
                    std::span<GSWCt> beta_selectors, PirServer &mux,
                    const TreePirParams &tree, const PirParams &scheme);

// ---- Milestone-6 优化视图（§6.3 第 1-2 步）----
// 预处理时把每个打包明文提升到全部 RNS limb 并各做一次前向 NTT，之后每次
// 查询的首维工作只剩 NTT 域逐点乘累加 + 每个候选一次 INTT（NTT 次数约降
// 99%）。协议语义不依赖这种表示：mod-q 算术精确、INTT 线性
// （INTT(Σ) = Σ(INTT)），故优化输出与标量参考路径按位一致。
struct TreeLevelDatabaseNtt {
  // 对应的树层号 ℓ 与明文个数 R_ℓ（同 TreeLevelDatabase）。
  size_t level = 0;
  size_t R = 0;
  // 每个明文的 NTT 域值：K·N 个 u64，按 limb 优先（limb-major）排列。
  std::vector<std::vector<uint64_t>> plaintexts;
};
// 由规范层数据库构建 NTT-u64 优化视图（预处理期一次性完成）。
TreeLevelDatabaseNtt build_level_ntt_view(const TreeLevelDatabase &db,
                                          const PirParams &scheme);

// Milestone-6 完整矩阵核视图（仅复合模数配置可用）：把本层 NTT 值按
// q = q1·q2 拆成两组 32 位 CRT limb，并重排成 matrix.h 的 level_mat_mat_32
// 所需的 coefficient-major 布局 data[(coeff·rows + row)·cols + col]——
// row 索引候选（AlphaBeta 情形是 δ，其余情形只有单一输出行），col 索引选择
// 向量分量。数学上与 u64 逐点路径完全相同：拆分、每 limb 一次 32×32→64
// matmul（延迟规约）、CRT 合成、每候选一次 INTT。
struct TreeLevelDatabaseM32 {
  // 对应的树层号 ℓ 与明文个数 R_ℓ（同 TreeLevelDatabase）。
  size_t level = 0;
  size_t R = 0;
  // matmul 输出行数 = 候选个数（AlphaBeta 为 2^d，其余情形为 1）。
  size_t rows = 0;
  // matmul 列数 = 选择向量宽度（Single 为 1、CoarsenedAlpha 为 R、
  // AlphaBeta 为 N0）；恒有 rows·cols = R。
  size_t cols = 0;
  // 两个 CRT limb 的 u32 矩阵，各含 n·rows·cols 个元素：
  // lo 存 mod q1 的值、hi 存 mod q2 的值。
  std::vector<uint32_t> lo, hi;
};
// 由规范层数据库 + 公开 plan 构建 m32 矩阵核视图（预处理期一次性完成）。
TreeLevelDatabaseM32 build_level_m32_view(const TreeLevelDatabase &db,
                                          const LevelPlan &plan,
                                          const TreePirParams &tree,
                                          const PirParams &scheme);

// 规范视图 + 优化视图 + 公开 plan 的打包集合，供应答路径使用（蓝图 §19
// PreprocessedTree）。当方案启用复合模数首维拆分时，preprocess_tree_mvp 构建
// m32 视图并让 ntt 留空——两种视图等大（8 B/系数），都保留会让内存翻倍；
// 否则构建 ntt、m32 留空。
struct PreprocessedTree {
  // 规范系数形式层数据库（测试对拍与任何回退路径都要用它）。
  std::vector<TreeLevelDatabase> canonical;
  // NTT-u64 优化视图（非复合模数配置时填充，每层一个）。
  std::vector<TreeLevelDatabaseNtt> ntt;
  // m32 矩阵核视图（复合模数配置时填充，每层一个）。
  std::vector<TreeLevelDatabaseM32> m32;
  // 每层的公开选择计划（共 L+1 个，只依赖公开参数）。
  std::vector<LevelPlan> plans;
};
// 打包全部层并按方案配置构建对应的优化视图；标量重载要求 g = 1。
PreprocessedTree preprocess_tree_mvp(const TreePirParams &tree,
                                     const TreeNodeSource &source,
                                     const PirParams &scheme);
PreprocessedTree preprocess_tree_mvp(const TreePirParams &tree,
                                     const TreeNodeChunkSource &source,
                                     const PirParams &scheme);

// 每次查询对金字塔的全部密文只做一次前向 NTT，之后所有层都直接消费 NTT 域
// 乘积——把每层重复的前向变换摊销成一次。
AlphaPyramid pyramid_to_ntt(const AlphaPyramid &pyramid,
                            const PirParams &scheme);

// 优化版 SelectLevel：在 NTT 视图上执行与 select_level 完全相同的环运算；
// 消费 NTT 形式的金字塔，返回与标量路径按位相等的系数形式结果。
RlweCt select_level_ntt(const TreeLevelDatabaseNtt &db, const LevelPlan &plan,
                        const AlphaPyramid &pyramid_ntt,
                        std::span<GSWCt> beta_selectors, PirServer &mux,
                        const TreePirParams &tree, const PirParams &scheme);

// NTT 形式金字塔的每查询 CRT-limb 拆分，采用矩阵核 B 操作数的布局
// data[(coeff·cols + col)·2 + component]（component 0/1 对应 c0/c1）；
// 每次查询只构建一次，所有层共享。
struct AlphaPyramidM32 {
  // 每个金字塔行一个缓冲区：lo 存 mod q1、hi 存 mod q2 的 u32 值。
  std::vector<std::vector<uint32_t>> lo, hi;
};
AlphaPyramidM32 pyramid_to_m32(const AlphaPyramid &pyramid_ntt,
                               const PirParams &scheme);

// Milestone-6 完整矩阵核：同一选择运算改在 m32 视图上执行——每个 CRT limb
// 一次 level_mat_mat_32（32×32→64，延迟规约），随后 CRT 合成、每候选一次
// INTT。输出与另外两条路径按位一致。仅复合模数配置可用。
RlweCt select_level_m32(const TreeLevelDatabaseM32 &db, const LevelPlan &plan,
                        const AlphaPyramidM32 &pyramid_m32,
                        std::span<GSWCt> beta_selectors, PirServer &mux,
                        const TreePirParams &tree, const PirParams &scheme);
