#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

// 满二叉树 PIR 的 (γ, α, β) 索引层。本头文件是纯算术层：不依赖环、密钥或
// 密文类型，因此索引恒等式可以在极小的合成配置（蓝图 §25）上逐叶穷举验证
// ——那些微型配置用方案固定的环参数根本无法实例化。
//
// 坐标模型（蓝图 §3/§5；草稿论文 §3.1/§3.3）。树有 N = 2^L 片叶子；第 0 层
// 是根，第 L 层是叶。g = 1 时每个节点是一个 Z_t 标量，ρ = n/g = n 条记录装进
// 一个明文多项式，并有
//   P = N / ρ,  B = P / N₀ = 2^b,  b = L - r - a,  r = log₂ ρ,  N₀ = 2^a。
// 叶索引 i 只分解一次：γ = ⌊i/P⌋ 是打包记录坐标（定位明文内的系数槽），
// p = i mod P 再分成 α = ⌊p/B⌋ 与 β = p mod B（共同定位是哪个明文多项式）。
// 只有 (α, β 的各位, γ 的各位) 进入查询生成；每层的具体目标值都由服务端从
// 公开的 LevelPlan 加上这些加密坐标推导——这正是"一条打包查询服务全部
// L+1 层"的跨层坐标复用（实现技巧手册 §1.1，草稿论文 Lemma 1/3/4）。

// 全套公开形状参数。所有字段都是由 (L, a, n, g, ...) 推出的派生量，
// 一经 validate_tree_params 通过便全程只读。
struct TreePirParams {
  // —— 树形状 ——
  size_t N = 0;   // 叶子数，恒等于 2^L
  size_t L = 0;   // 树高；层号取 0..L（含两端），共 L+1 层
  // —— 环 / 打包形状 ——
  size_t n = 0;    // 环维度（g = 1 时即每明文可装的记录数）
  size_t g = 1;    // 每节点占用的 Z_t 系数槽数；须为 2 的幂且整除 n，MVP 固定 g = 1
  size_t rho = 0;  // ρ = n / g：每个明文多项式容纳的记录数，须为 2 的幂且 ≥ 2
  size_t r = 0;    // r = log₂ ρ：γ 坐标的位数，同时是旋转/投影链的深度上限
  // —— 首维 / β 划分 ——
  size_t N0 = 0;  // 首维（α 维）大小，恒等于 2^a
  size_t a = 0;   // a = log₂ N₀：首维位数
  size_t P = 0;   // P = N / ρ：叶层明文多项式个数（每棵打包子树覆盖 P 条记录）
  size_t B = 0;   // B = P / N₀ = 2^b：每个 α 分组内的明文数
  size_t b = 0;   // b = L - r - a：β 选择位的个数（可为 0）
  // —— 打包查询布局 ——
  size_t ell_beta = 0;   // 每个 β 位的 gadget 行数（RGSW 分解长度）
  size_t ell_gamma = 0;  // 每个 γ 位的 gadget 行数
  size_t w = 0;          // w = N₀ + ell_beta·b + ell_gamma·r：打包的逻辑常数总数
  size_t h_q = 0;        // h_q = ⌈log₂ w⌉：查询展开树的高度
  size_t W = 0;          // W = 2^{h_q}：展开容量；展开使每槽被乘上 W，打包时须预乘 W⁻¹
  // —— 方案绑定 ——
  // 纯索引数学配置下 rns_moduli 可以为空，但 t 必须恒为奇数：W 是 2 的幂，
  // 只有奇模数才保证 W⁻¹ mod t 存在（客户端打包常数时要注入该逆元）。
  uint64_t t = 0;                       // 明文模数
  std::vector<uint64_t> rns_moduli;     // 全 q 的 RNS 素数肢（每个都须为奇数）
  size_t response_degree = 0;           // 响应环维度 n₂；MVP 固定同环，n₂ = n
  std::vector<uint64_t> response_moduli;  // 响应模数 q₂ 的 RNS 肢；MVP 固定 q₂ = q
};

// 参数工厂（g = 1 便捷重载）：由 (L, a) 加环/方案输入推出全部派生字段，
// 随后跑 validate_tree_params。没有任何 padding 回退：形状不兼容一律抛异常，
// 绝不静默改动 N、L 或节点编号（蓝图 §21.1 的硬失败纪律）。
TreePirParams make_tree_pir_params(size_t L, size_t a, size_t n,
                                   size_t ell_beta, size_t ell_gamma,
                                   uint64_t t,
                                   std::vector<uint64_t> rns_moduli);

// 一般 g 版本（蓝图 §23.1）：每个节点占 g 个系数槽，ρ = n/g 条记录装进一个
// 明文，r = log₂ ρ。g 必须是 2 的幂——只有这样 γ 的位分解和投影深度才保持
// 2 的幂结构（跨步 g-chunk 布局依赖 mod-ρ 残差格）；g = 1 精确复现标量 MVP。
TreePirParams make_tree_pir_params(size_t L, size_t a, size_t n, size_t g,
                                   size_t ell_beta, size_t ell_gamma,
                                   uint64_t t,
                                   std::vector<uint64_t> rns_moduli);

// 蓝图 §3.2 硬校验：命中第一条被违反的约束即抛 std::invalid_argument；
// 正常返回当且仅当全部约束成立。既复核工厂产物，也接受手工构造的 struct。
void validate_tree_params(const TreePirParams &params);

// 查询侧的私有坐标。这是唯一允许进入查询生成的索引派生结构；下方的
// LevelPlan 是公开的，LevelOracle 仅供测试。α 以整数形式保留（打包成
// one-hot 明文槽位），β / γ 则拆成位（每位各自加密成 RGSW 选择器）。
struct ClientCoordinates {
  size_t alpha = 0;                    // 首维下标 α = ⌊(i mod P)/B⌋，取值 [0, N₀)
  std::vector<uint8_t> beta_bits_le;   // 小端位串：beta_bits_le[u] = β 的第 u 位，长 b
  std::vector<uint8_t> gamma_bits_le;  // 小端位串：gamma_bits_le[v] = γ 的第 v 位，长 r
};

// 每层的选择情形，按该层打包明文数 R_ℓ = 2^{max(ℓ-r,0)} 与 N₀ 的关系三分。
enum class SelectCase {
  Single,          // R_ℓ = 1：整层只有一个明文，无需 α/β 选择（取金字塔塔顶常量 1）
  CoarsenedAlpha,  // 1 < R_ℓ < N₀：α 位数不足 a 位，用 ⌊α/2^{coarsen_count}⌋ 的粗化 one-hot
  AlphaBeta,       // R_ℓ ≥ N₀：完整 α one-hot，再加 beta_count 次 β 位 CMux 折叠
};

// 公开的逐层执行计划。每个字段只依赖公开参数与层号，从不依赖具体查询，
// 因此服务端可以自由据此分支而不泄露任何私有信息。配合不变量
// j_ℓ = γ_ℓ·R_ℓ + p_ℓ：本计划告诉服务端如何由加密坐标算出 p_ℓ 并取出槽 γ_ℓ。
struct LevelPlan {
  size_t level = 0;  // 层号 ℓ ∈ [0, L]
  size_t R = 0;  // R_ℓ = 2^{max(ℓ-r,0)}：该层打包后的明文数（2^ℓ 个节点 / 每明文 ρ 个）

  SelectCase select_case = SelectCase::Single;  // 三分情形，见 SelectCase
  size_t coarsen_count = 0;  // 粗化步数 c = a - log₂R_ℓ（Single 情形取满深度 a）

  size_t beta_begin = 0;  // 活跃 β 位窗口起点（小端、含端点）；空窗口用哨兵值 b
  size_t beta_count = 0;  // 活跃 β 位数 d_ℓ；折叠按位下标降序消费（MSB-first）

  size_t gamma_begin = 0;  // 活跃 γ 位窗口起点（小端、含端点）；ℓ<r 时只用高 ℓ 位
  size_t gamma_count = 0;  // 活跃 γ 位数：ℓ≥r 时为全部 r 位，否则为 ℓ 位

  size_t projection_depth = 0;  // 投影深度 min(r, ℓ)：杀掉非目标记录所需的最小轮数
};

// 测试专用的目标元数据（蓝图 §5.6）。node_index 即 j_ℓ；该节点存放在打包
// 明文 D_ℓ[packed_plaintext_index] 的系数槽 record_position 上，满足恒等式
// j_ℓ = record_position · R_ℓ + packed_plaintext_index（Invariant 1）。
// 绝不序列化、绝不被生产服务端入口接受——它直接暴露目标坐标。
struct LevelOracle {
  size_t node_index = 0;              // j_ℓ：leaf 在第 ℓ 层的祖先编号
  size_t packed_plaintext_index = 0;  // p_ℓ：层内明文下标，取值 [0, R_ℓ)
  size_t record_position = 0;         // γ_ℓ：明文内的系数槽（记录位置）
};

// Algorithm 1 ClientIndex：把一个叶索引分解成查询坐标（详见 .cpp）。
ClientCoordinates client_index(size_t leaf, const TreePirParams &params);

// 为第 0..L 层各生成一份公开计划（共 L+1 项）。
std::vector<LevelPlan> build_level_plans(const TreePirParams &params);

// 测试专用 oracle：直接由 (leaf, level) 算出该层目标位置，与主路径交叉验证。
LevelOracle build_level_oracle_for_test(size_t leaf, size_t level,
                                        const TreePirParams &params);

// Invariant 2（蓝图 §16）：仅凭跨层共享的 (α, β) 坐标重建第 ℓ 层的层内记录
// 位置 p_ℓ。定义域为 level ≥ r 的层；同一公式在 CoarsenedAlpha 层顺带给出
// 粗化 one-hot 下标 ⌊α/2^c⌋（两者都是对 p = α·B + β 的 2 幂截断）。
size_t level_record_position_from_coordinates(size_t alpha, size_t beta,
                                              size_t level,
                                              const TreePirParams &params);
