#include "tree_project.h"

#include "tree_rotate.h"
#include "utils.h"

#include "hexl/hexl.hpp"

#include <bit>
#include <stdexcept>
#include <string>

// Algorithm 6 ProjectRecord：实现 π_depth，只保留跨步 2^depth 格上的系数。
// 流水线位置：每层三步（选层 → 私有旋转 → 本投影）的第三步。私有旋转已把目标
// 记录对齐到系数 0 的跨步格；本函数按公开 stride 把其余所有残留记录清零——
// 满深度 r 的保留格 = ρ 的倍数格，恰是目标记录 g 个 chunk 所在的位置。
// 输入：系数形式全 q 密文 ct、投影深度 depth（层计划给 min(r, level)）、
// 覆盖 η_0..η_{depth-1} 的 BV Galois 密钥束。
// 输出：系数形式密文，解密 = π_depth(原明文)，保留系数保持原尺度不变。
RlweCt project_keep_stride(RlweCt ct, size_t depth,
                           const bvks::BvGaloisKeys &keys,
                           const PirParams &scheme) {
  // 环维数 n、RNS 模数组 {q_k} 与 limb 数 K。
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs = scheme.get_rns_mods();
  const size_t K = qs.size();
  // 守卫：投影按系数下标操作，只对系数形式的完整全 q 密文有定义；
  // NTT 形式或残缺缓冲直接拒绝，防止静默算错。
  if (ct.ntt_form || ct.c0.size() != K * N || ct.c1.size() != K * N) {
    throw std::invalid_argument(
        "tree_project: projection needs a coefficient-form full-q ciphertext");
  }
  // 守卫：深度上限 log2(n)——递推最多做 log2(n) 轮（此时只剩系数 0），
  // 再深则 η_j = n/2^j + 1 失去意义。
  const size_t max_depth = std::bit_width(N) - 1;
  if (depth > max_depth) {
    throw std::invalid_argument(
        "tree_project: depth exceeds log2 of the ring degree");
  }
  // depth = 0 时 π_0 = id：无需缩放也无需代换，原样返回。
  if (depth == 0) return ct;

  // 第 1-2 步（预缩放）：两个分量逐 limb 乘 u_k = 2^{-depth} mod q_k。
  // 后面 depth 轮 T + τ(T) 每轮把保留系数翻倍，预乘 2^{-depth} 恰好抵消 2^{depth}；
  // 又因噪声被同样投影（Σᵢσᵢ(e) = 2^d·π(e)），这次模逆缩放不会放大噪声。
  // 缩放放在最前而不是最后，正是"先乘逆再展开"构造的标准形态（手册 §3.3）。
  for (size_t k = 0; k < K; ++k) {
    // 求 2^depth 在 q_k 下的乘法逆元；q_k 为奇素数时必可逆，失败说明参数配置有误。
    uint64_t inv = 0;
    if (!utils::try_invert_uint_mod(uint64_t{1} << depth, qs[k], inv)) {
      throw std::invalid_argument(
          "tree_project: 2^depth is not invertible modulo a RNS limb");
    }
    // c0、c1 就地逐点乘 inv（HEXL EltwiseFMAMod 的加数指针传 nullptr，即纯乘法）。
    intel::hexl::EltwiseFMAMod(ct.c0.data() + k * N, ct.c0.data() + k * N,
                               inv, nullptr, N, qs[k], 1);
    intel::hexl::EltwiseFMAMod(ct.c1.data() + k * N, ct.c1.data() + k * N,
                               inv, nullptr, N, qs[k], 1);
  }

  // 第 3 步（Galois 迹）：对 j = 0..depth-1 执行 T <- T + Subs(T, η_j)。
  // 对第 j 轮输入（幸存指数已全是 2^j 的倍数），τ_{η_j}(X^e) = (-1)^{e/2^j}·X^e：
  // e/2^j 为奇的系数在相加中正负抵消，为偶（即 2^{j+1} | e）的系数翻倍——
  // 这正是递推 2π_{u+1} = π_u + τ_{η_u}(π_u)，幸存指数集逐轮减半。
  // 与查询展开机制相比，这里只取"加法分支"、没有减法分支，故只留偶格不分裂奇格。
  for (size_t j = 0; j < depth; ++j) {
    // 本轮自同构指数 η_j = n/2^j + 1（与查询展开共用同一密钥族 (n >> u) + 1）。
    const uint32_t eta = static_cast<uint32_t>((N >> j) + 1);
    // 复制一份并施加 Galois 自同构：tau = τ_{η_j}(T)。bv_apply_galois_inplace 在
    // 代换后用 η_j 对应的 BV keyswitch 密钥把密钥分量切回 s，每轮引入一次 KS 噪声。
    RlweCt tau = ct;
    bvks::bv_apply_galois_inplace(tau, eta, keys.get(eta), scheme);
    // 累加回原密文：T <- T + τ_{η_j}(T)，完成本轮指数集减半。
    tree_ct_add_inplace(ct, tau, scheme);
  }
  // 此时解密 = π_depth(原明文)：非 stride 系数全零，保留系数尺度与输入一致。
  return ct;
}
