#pragma once

#include "server.h"
#include "tree_index.h"

#include <cstddef>
#include <span>

// Milestone-3：私有负循环记录旋转（蓝图 §12）。
// 本文件的"旋转"专指系数域上乘单项式 X^e——即 Z_q[X]/(X^n + 1) 中带符号翻转的
// 负循环移位（回绕过 X^n 的系数变号，因为 X^n = -1）——与 BFV batching 的槽位
// 旋转完全无关。负指数一律按 mod 2n 表示：X^{-k} = X^{2n-k}。

// 逐 RNS limb 相加两条系数形式全 q 密文（acc += x）。RLWE 同态加法基础例程，
// 投影（T + Subs(T, η)）与路径打包两个阶段共用（旋转的 CMux 在
// ext_prod_mux 内部自带逐 limb 加减，不经此函数）。
void tree_ct_add_inplace(RlweCt &acc, const RlweCt &x, const PirParams &scheme);

// 密文两个分量同乘 X^{exponent}，指数按 mod 2n 解释（§12.1 的映射）。
// 输入输出均为系数形式；负指数由调用方编码为 X^{-k} = X^{2n-k} 后传入。
RlweCt mul_x_pow(const RlweCt &ct, size_t exponent_mod_2n,
                 const PirParams &scheme);

// 加密移位选择器（§12.2）：
//   RotSelect(S, C, k) = C + ExtPdt(MulXPow(C, -k) - C, S)
// 即当且仅当 RGSW 位 S 加密 1 时密文被乘 X^{-k}；S 加密 0 时原样保留。
// 由 mul_x_pow 与仓库现成的 CMux（RGSW 外积选择器 ext_prod_mux）组合，无需新原语。
RlweCt rot_select(const RlweCt &ct, GSWCt &encrypted_bit, size_t shift,
                  PirServer &mux, const PirParams &scheme);

// Algorithm 5 PrivateRotateLevel：按层计划 plan 的 γ 调度串接 rot_select，
// 使明文整体被乘 X^{-γ_ℓ}，目标记录落到系数 0 所在的跨步格上。
// 活跃选择器是全局位号 v ∈ [gamma_begin, gamma_begin + gamma_count) 的 γ 位，
// 位 v 的移位量为 2^{v - gamma_begin}——层 ℓ >= r 用完整 γ，其上各层只用高位前缀。
// `gamma_selectors` 是按全局位号索引的完整 r 长选择器数组，各层复用同一份。
RlweCt private_rotate_level(RlweCt ct, const LevelPlan &plan,
                            std::span<GSWCt> gamma_selectors, PirServer &mux,
                            const PirParams &scheme);
