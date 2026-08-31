#pragma once

#include "bv_keyswitch.h"
#include "pir.h"
#include "rlwe.h"

#include <cstddef>

// Milestone-3：单边系数投影（蓝图 §13）。投影映射
//   π_d(Σ f_e X^e) = Σ_{2^d | e} f_e X^e
// 只保留下标为 2^d 倍数的系数、其余清零。它由递推
//   2·π_{u+1}(f) = π_u(f) + τ_{η_u}(π_u(f))，η_u = n/2^u + 1
// 实现：d 轮"Galois 代换 + keyswitch"每轮把幸存指数集减半、同时把保留系数翻倍，
// 预先给密文乘 2^{-d} 恰好精确抵消这个翻倍。
// 关键性质（手册 §3.3 技巧一，"噪声也被投影"）：自同构和 Σᵢ σᵢ(e) = 2^d·π_d(e)
// ——噪声项经历与消息完全相同的投影，2^{-d} 与 2^d 精确相消，故输出噪声
// ≈ |π(e)| + d 次 keyswitch 噪声，而不会被 2^{-d} mod q 炸成均匀大数。
//
// Algorithm 6 ProjectRecord：先对两个分量逐 RNS limb 乘 2^{-depth} 预缩放，
// 再对 j = 0..depth-1 做 T <- T + Subs(T, η_j)。Galois 密钥必须覆盖每个
// η_j = (n >> j) + 1（j < depth），即密钥束注册高度 >= depth
//（高度 log2(n) 可覆盖一切合法投影深度）。输入输出均为系数形式。
// 私有旋转正确完成后，depth = min(r, level) 已足够：目标记录的 g 个 chunk
// 留在系数 0 所在的跨步格 {j·ρ} 上，格外系数全部清零（g = 1 时即仅系数 0
// 非零）（§13.2；手册 §3.3 技巧二——ℓ < r 层的非目标记录旋转后
// 位于非零残差 u - γ_ℓ (mod 2^ℓ)，深度 ℓ 已全部杀掉）。
RlweCt project_keep_stride(RlweCt ct, size_t depth,
                           const bvks::BvGaloisKeys &keys,
                           const PirParams &scheme);
