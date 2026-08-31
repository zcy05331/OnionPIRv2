#pragma once

#include "client.h"
#include "pir.h"
#include "server.h"
#include "tree_index.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

// ============================================================================
// 打包树查询的构造与解包（蓝图 §8 / §9）。
//
// 客户端把整条 Binary Tree PIR 查询压进 **一条** RLWE 密文。打包布局为：
//   [ α one-hot：N0 个槽位 ]
//   [ β[0]：ell 行 ] ... [ β[b-1]：ell 行 ]
//   [ γ[0]：ell 行 ] ... [ γ[r-1]：ell 行 ]
// 共 w = N0 + ell*(b+r) 个逻辑常数。每个逻辑槽位 j 实际写在多项式系数
// BitRev(j, h_q) 处——因为服务端现有的 ExpandBFV 是按堆序（heap walk）做
// 系数展开的，其输出叶顺序天然是位反转序；客户端预先做一次位反转，
// 展开叶 j 就恰好回收逻辑槽位 j。
//
// β/γ 两组 gadget 行都复用方案自带的 L_EP 长数据 gadget（即
// scheme.get_l() 行），这样服务端现成的 query_to_gsw 补全路径可以原封不动
// 地把它们组装成 RGSW；下面的 scheme 绑定因此把 ell_beta = ell_gamma =
// scheme.get_l() 冻结死，不允许各自取不同的 gadget 长度。
//
// 打包密文里混着 **两种不同尺度** 的常数（§8.2），二者刻意不共用 helper：
//   - α one-hot 是 BFV 明文值：走完整 Q 的 Δ 提升，调用方预先乘上
//     W^{-1} mod t（W = 2^{h_q} 是展开过程引入的乘积因子）；
//   - β/γ gadget 行是 RLWE*（RLWE'）风格常数，**不带 Δ 因子**：逐 RNS limb
//     写入，调用方预先乘上 W^{-1} mod q_k。
//   一个在 mod-t 域、一个在逐 limb 的 mod-q_k 域，若共用一个"通用标量加"
//   helper 会静默产生错误缩放，故 §8.2 明令拆开。

// 把树形参 (L, a) 绑定到当前 OnionPIRv2 方案：n = PolyDegree、
// ell_beta = ell_gamma = scheme.get_l()、t 与 RNS 模数取自 `scheme`、
// 同环响应。任何违反蓝图 §3.2 约束的形状都会抛异常。
// （2 参数版：g = 1 的冻结 MVP 形状。）
TreePirParams make_tree_pir_params_for_scheme(size_t L, size_t a,
                                              const PirParams &scheme);
// 同上，但显式指定每节点槽数 g（§23.1）。
TreePirParams make_tree_pir_params_for_scheme(size_t L, size_t a, size_t g,
                                              const PirParams &scheme);
// 完整形式：额外接受 session_key_height，作为运行时能力上界检查
// h_q <= session_key_height——会话实际注册的 BV Galois 密钥只覆盖到
// create_session_keys(height) 给定的高度。前两个短重载保守地取方案默认
// 展开高度。若注册满 log2(n) 高的密钥（树协议的惯例，投影反正也需要它们），
// h_q 可以用满整个环（W = n），从而在同一 L 下允许更大的 N0，把 β 折叠的
// 工作量减半。
TreePirParams make_tree_pir_params_for_scheme(size_t L, size_t a, size_t g,
                                              const PirParams &scheme,
                                              size_t session_key_height);

// 为树查询派生一套"仅供展开使用"的 PirParams 视图：fst_dim_sz = N0、
// num_other_dims = b + r、expansion_height = h_q。经
// PirParams::with_query_shape({N0, b+r, h_q}) 构造，只喂 fast_expand_qry
// 和会话密钥校验，**不是**数据库布局（见 pir.h）——树查询形状不可能由
// 数据库规划器反推出来，只能这样直接写入。
PirParams tree_query_expansion_params(const TreePirParams &tree,
                                      const PirParams &scheme);

// α 部分的写入 helper：把 `value_mod_t` 的完整 Q 域 BFV 提升（Δ·value，
// value 应已含 W^{-1} mod t 预缩放）加到消息相关分量的系数
// BitRev(logical_coeff, h_q) 处。密文必须是系数形式、完整 q。
void add_bfv_query_constant(RlweCt &ct, const PirParams &scheme,
                            size_t logical_coeff, size_t h_q,
                            uint64_t value_mod_t);

// β/γ 部分的写入 helper（蓝图 §8.3 的语义化封装）：把一个 RLWE* 风格常数
// （每个 RNS limb 一个值，应已含 W^{-1} mod q_k 预缩放，**无 Δ 因子**）加到
// 消息相关分量的系数 BitRev(logical_coeff, h_q) 处。密文分量约定由本 helper
// 独占：在本仓库 (c0, c1) = (-as + e + Delta*m, a) 的布局下它修改 c0——
// 调用方不得自行硬编码这一选择。
void add_rlwe_star_constant(RlweCt &ct, const PirParams &scheme,
                            size_t logical_coeff, size_t h_q,
                            std::span<const uint64_t> value_per_limb);

// Algorithm 3 QueryGen（客户端）：在客户端长期密钥下为目标叶 `leaf` 打包
// 一条树查询；每次调用都从客户端 RNG 抽取新鲜加密随机性。组装顺序遵循
// §8.5：零加密 → 叠加 α one-hot 的 BFV 提升 → 叠加 β、γ 的 gadget 行——
// 全程只有这一次编码，没有第二个独立的 BFV/RLWE 编码器。返回值中唯一与
// 查询相关的就是这条密文；从中无法读出任何逐层值或 oracle 类型。
RlweCt make_tree_query(PirClient &client, const PirParams &scheme,
                       const TreePirParams &tree, size_t leaf);

// 服务端解包结果（蓝图 §9.1/§9.2）。展开出的前 N0 个叶保持 BFV 密文形态，
// 加密 α one-hot 向量 A^(0)；每个 β/γ gadget 行组则用客户端注册的 RGSW(s)
// 补全密钥合成为一个完整 RGSW selector。selector 顺序与打包布局一致：
// beta_selectors[u] = RGSW(beta_u)、gamma_selectors[v] = RGSW(gamma_v)。
struct ExpandedTreeQuery {
  // 首维选择向量：N0 条 BFV 密文，第 α 条加密 1，其余加密 0（A^(0)）。
  std::vector<RlweCt> alpha;
  // b 个 β 位的 RGSW selector（CMux 折叠用），下标 u 对应 β 的第 u 个二进制位。
  std::vector<GSWCt> beta_selectors;
  // r 个 γ 位的 RGSW selector（旋转/投影选择用），下标 v 对应 γ 的第 v 位。
  std::vector<GSWCt> gamma_selectors;
};

// Algorithm "QueryUnpack"（服务端，§9）：跑现成的系数展开树（ExpandBFV，
// 带 useful-leaf 剪枝），α 区间原样保留为 BFV，selector 组经
// PirServer::complete_selectors 补全成 RGSW——这与 flat 生产路径 make_query
// 调用的是同一份实现，行布局约定因此不可能在两条路径间漂移。
// `server` 必须构造自 tree_query_expansion_params(tree, scheme) 并已持有该
// 客户端的会话密钥；形状或方案不匹配的 server 会在任何同态运算之前被拒绝。
// 打包查询只被读取；server 取非 const 是因为补全会复用其内部转换状态。
ExpandedTreeQuery unpack_tree_query(PirServer &server,
                                    const PirParams &scheme,
                                    const TreePirParams &tree,
                                    size_t client_id, RlweCt &query);
