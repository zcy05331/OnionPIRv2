#pragma once

#include "client.h"
#include "server.h"
#include "tree_compress.h"
#include "tree_index.h"
#include "tree_query.h"
#include "tree_select.h"

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

// ============================================================================
// 本文件：Binary Tree PIR 的"整条路径响应"流水线 + 客户端提取（蓝图 §14-15，
// Milestone-4 同环打包，泛化到每节点 g 个 chunk；M5 small_q 切换；M7 环切换压缩）。
//
// 核心打包不变量：每层经过 select → private_rotate → project_keep_stride 之后，
// 密文的非零载荷只落在跨步格 {j * rho : j < g}（rho = n/g），其余系数全为零。
// 因此一条主环密文最多可容纳 rho 个路径节点：把第 z 层乘公开单项式 X^z 移到
// 偏移 z，其载荷落在 {z + j * rho}；不同层占据互不相同的 mod rho 残差位置，
// 加法叠加既不重叠也不回绕（X^n = -1 的负循环回绕不会发生，因为偏移 < rho）。
// MVP 不做降次、不做小环 key switch、不做向量化——这些是 M7 之后的事。
// ============================================================================

// 整条根到叶路径的加密响应（MVP 形态：主环密文，未做环切换压缩）。
struct TreePathResponse {
  // 响应密文数组：共 ceil((L+1)/rho) 条主环密文，每条容纳最多 rho 个层槽位。
  std::vector<RlweCt> chunks;
  // 打包的路径节点总数 = L + 1（含根），按根在前、叶在后的顺序编号。
  size_t level_count = 0;
  // 公开的"每层槽位偏移"放置图：第 l 层的第 j 个 chunk 位于其所在响应密文的
  // 系数 level_offsets[l] + j * rho 处。偏移只依赖公开参数（层号、rho），不泄露
  // 任何私密信息。顺序打包器填的是层在 chunk 内的位置 z；把放置图显式记录下来，
  // 是为了让未来的打包器（如 M7 的偶对齐 2z 方案）可以自由改放置策略而完全不必
  // 改动提取端——提取统一按 offset + j * rho 读数（见 §4.2 放置图设计）。
  std::vector<size_t> level_offsets;
  // Milestone 5 标志：末端同环模数切换（全 q -> 22-bit small q）是否已执行。
  // 只要配置定义了更窄的 small q 就会执行；客户端据此选择 decrypt_mod_q 或
  // 常规 decrypt_ct。
  bool small_q = false;
};

// 把 level_count 个路径槽位按每密文容量 capacity（生产中取 rho）连续分组：
// 返回每条响应密文覆盖的 (first_level, size)。单独拆成纯算术函数，是为了让
// "不重叠 / 不回绕"的分组算术能用极小容量做单元测试（§21.8，见 test_tree_e2e）。
std::vector<std::pair<size_t, size_t>> path_chunk_bounds(size_t level_count,
                                                         size_t capacity);

// Algorithm 7 AnswerPathMVP：服务端全流水线。对每一层依次执行
//   SelectLevel（Milestone-6 NTT 视图或复合模数 m32 核，内部含 α 首维 matmul 与
//   β 维 CMux fold）→ PrivateRotateLevel（乘加密的 X^{-γ} 把目标记录对齐到跨步格）
//   → ProjectRecord（project_keep_stride 深度 min(r, l) 的迹式投影，清掉格外杂项），
// 再按根到叶顺序把各层打包进响应密文，最后每条密文执行 Milestone-5 同环模数切换。
// `server` 提供 CMux 求值器与模数切换实现，且必须持有该客户端的会话密钥；其 BV
// Galois 密钥覆盖需达到 max(h_q, r) 个替换密钥——client.create_session_keys(log2 n)
// 恰好提供这一覆盖（§5.1）。
//
// 【负结果知识，保留勿删】关于"投影 + 打包融合"的三个被推翻方案（§4.4）：
// 曾尝试跨层摊销每层的旋转/投影 keyswitch 开销，推导出三个候选调度，均被证明对
// stride-rho 多 chunk 载荷不健全：
//   1. 细→粗 PackPair 树（C = A + X^{2^u} B + τ(A − X^{2^u} B)）：放在奇 2^u 格位
//      的内容会被下一轮更粗的 τ 自同构映射出位于 e + n/2 处的"幽灵项"——n/2 是
//      rho 的倍数，鬼影恰好落回载荷格上，污染其他层的槽位。
//   2. CDKS PackLWEs 直接套用：其健全级联要求输入已经落在 stride-rho 格上（等价于
//      每个输入仍需先做全深度投影，keyswitch 总量不降反增）；且其放置格距
//      n / 2^m = rho 与多 chunk 载荷的 j * rho 槽位发生别名（aliasing）冲突。
//   3. 先打包后共享 γ 旋转链：每层有 rho / 2^{d_0} 个与 γ 同余的非目标记录会留在
//      共享投影的保留格上，与其他层的槽位碰撞——结论是"私有对齐（乘 X^{-γ}）必须
//      先于公开的 stride 过滤（投影）"，两者次序不可交换。
// 要打破按层付费的旋转+投影开销，需要"加密偏移投影"（保留格由私密偏移决定的投影
// 算子）这类本栈中不存在的新原语——目前是开放问题，故打包器保持逐层顺序执行。
TreePathResponse answer_path_mvp(const PreprocessedTree &db,
                                 ExpandedTreeQuery &query, PirServer &server,
                                 size_t client_id, const TreePirParams &tree,
                                 const PirParams &scheme);

// Milestone-7 压缩版答复路径：每层的 select/rotate/project 流水线与 MVP 完全相同，
// 差异全在打包与收尾：
//   * 打包器把第 z 层放在偏移 2z（§23.4 的偶对齐形态）——全部载荷落在偶子格
//     {2z + j * rho} 上，被 d = 2 环切换的偶部提取完整保留；奇系数只含噪声，
//     被丢弃也无害（实测压缩后噪声反而略优于未压缩）；
//   * 跳过大环 small_q 模数切换（顺序纪律 §4.3：环切换的 gadget-KS 必须在全 q 下做，
//     KS 噪声 ~2^{39} 远小于 Δ/2，之后的降模缩放才能把它压到 O(10)；若先降模则任何
//     KS 噪声都直接越界），改为把全 q 响应交给 compress_path_response 做 d = 2 环切换。
// 约束：必须单 chunk 且 2 * (L + 1) - 2 < rho（即 2L < rho），并要求客户端已注册环切换
// 密钥 TreeRingSwitchKeys。收益：响应从 2 n log q2 缩到 2 (n/2) log q2 比特（折半）。
CompressedPathResponse answer_path_compressed(
    const PreprocessedTree &db, ExpandedTreeQuery &query, PirServer &server,
    size_t client_id, const TreePirParams &tree, const PirParams &scheme,
    const TreeRingSwitchKeys &keys);

// Algorithm 8 ExtractPathMVP（客户端提取）：用原始密钥解密每条响应密文
// （Milestone-5 切换执行过时走 small-q 解密 decrypt_mod_q），按根到叶顺序读出路径。
// chunks 版每层返回 g 个系数值（层槽位 z 的第 j 个 chunk 在系数 z + j * rho 处，
// 实际按响应携带的 level_offsets 寻址）；flat 版是 g = 1 的标量便捷视图。
std::vector<std::vector<uint64_t>> extract_path_chunks_mvp(
    const TreePathResponse &response, PirClient &client,
    const TreePirParams &tree);
std::vector<uint64_t> extract_path_mvp(const TreePathResponse &response,
                                       PirClient &client,
                                       const TreePirParams &tree);
