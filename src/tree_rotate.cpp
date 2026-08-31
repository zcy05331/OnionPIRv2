#include "tree_rotate.h"

#include "utils.h"

#include "hexl/hexl.hpp"

#include <stdexcept>
#include <string>

namespace {

// 本文件统一的参数守卫：条件不满足即抛 invalid_argument，
// 消息加 "tree_rotate: " 前缀便于定位出错阶段。
void require(bool condition, const char *message) {
  if (!condition) {
    throw std::invalid_argument(std::string("tree_rotate: ") + message);
  }
}

}  // namespace

// RLWE 同态加法 acc += x（系数形式、全 q）。
// 流水线位置：project_keep_stride 的 T + Subs(T, η) 与路径打包
//（tree_response 的逐层累加）以它为基本积木；旋转的 CMux（ext_prod_mux）
// 内部另有自己的逐 limb 加减实现，不经本函数。
// 数学：Dec(c0 + c1·s) 对加法线性，(c0, c1) 逐分量、逐 RNS limb 模加即可，
// 噪声只按加法叠加，不放大。
void tree_ct_add_inplace(RlweCt &acc, const RlweCt &x,
                         const PirParams &scheme) {
  // 环维数 n 与 RNS 模数组 {q_k}；密文按 limb 主序存放，第 k 段是 mod q_k 的 n 个系数。
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs = scheme.get_rns_mods();
  // 守卫：两输入必须都是系数形式且长度恰为 K·n——防止把 NTT 域数据或残缺缓冲误当
  // 系数域密文相加（两种表示下逐点加的数值含义不同，混用会静默出错）。
  require(!acc.ntt_form && !x.ntt_form && acc.c0.size() == x.c0.size() &&
              acc.c0.size() == qs.size() * N,
          "ciphertext addition needs matching coefficient-form inputs");
  // 逐 limb 调 HEXL 向量化模加：c0、c1 各加一次，即 (c0, c1) += (x.c0, x.c1) (mod q_k)。
  for (size_t k = 0; k < qs.size(); ++k) {
    intel::hexl::EltwiseAddMod(acc.c0.data() + k * N, acc.c0.data() + k * N,
                               x.c0.data() + k * N, N, qs[k]);
    intel::hexl::EltwiseAddMod(acc.c1.data() + k * N, acc.c1.data() + k * N,
                               x.c1.data() + k * N, N, qs[k]);
  }
}

// MulXPow：密文乘单项式 X^{exponent}（§12.1；实现技巧手册 §3.1"mod 2n 符号位技巧"）。
// 输入：系数形式全 q 密文 ct、指数 exponent_mod_2n ∈ [0, 2n)。
// 输出：新密文，解密结果 = 原明文 × X^{exponent}（负循环意义下，回绕系数变号）。
// 原理：解密相位 c0 + c1·s 对"乘固定多项式"是线性的，故给 c0、c1 同乘 X^e 即可让
// 明文与噪声同乘 X^e——单项式乘法只是系数置换加变号，噪声幅度不变、零成本。
RlweCt mul_x_pow(const RlweCt &ct, size_t exponent_mod_2n,
                 const PirParams &scheme) {
  // 取环维数 n、RNS 模数组 {q_k} 与 limb 数 K。
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs = scheme.get_rns_mods();
  const size_t K = qs.size();
  // 守卫：负循环移位是系数域上的置换，输入必须是系数形式且缓冲完整；
  // NTT 域的数据做同样的下标搬移会得到毫无意义的结果。
  require(!ct.ntt_form && ct.c0.size() == K * N && ct.c1.size() == K * N,
          "MulXPow needs a coefficient-form full-q ciphertext");
  // 守卫：指数须已归约到 [0, 2n)；负指数由调用方按 X^{-k} = X^{2n-k} 折算后传入。
  require(exponent_mod_2n < 2 * N, "MulXPow exponent must be below 2n");

  // 预分配全零输出缓冲并标记为系数形式；移位例程按"读一处写一处"填满全部系数。
  RlweCt result;
  result.c0.assign(K * N, 0);
  result.c1.assign(K * N, 0);
  result.ntt_form = false;
  // 逐 limb 复用共享负循环移位例程（§12.1 的映射）：内部 index_raw = shift + i，
  // 其低 log2(n) 位给出新位置，与 n 相与的那一位给出符号——一个位运算同时处理
  // 下标回绕与 X^n = -1 的变号。c0、c1 各移一次，即整条密文乘 X^{exponent}。
  for (size_t k = 0; k < K; ++k) {
    utils::negacyclic_shift_poly_coeffmod(ct.c0.data() + k * N, N,
                                          exponent_mod_2n, qs[k],
                                          result.c0.data() + k * N);
    utils::negacyclic_shift_poly_coeffmod(ct.c1.data() + k * N, N,
                                          exponent_mod_2n, qs[k],
                                          result.c1.data() + k * N);
  }
  return result;
}

// RotSelect（§12.2；手册 §3.2"旋转即 CMux"）：
//   RotSelect(S, C, k) = C + ExtPdt(X^{-k}·C - C, S)
// encrypted_bit S 加密 0 ⇒ 输出解密为原明文；S 加密 1 ⇒ 输出解密为 X^{-k}·明文。
// 服务器全程看不到 S 的值，"转了没转"对服务器保密——私有旋转的单步选择器。
// 代价：一次 RGSW 外积的噪声增长；旋转本身（mul_x_pow）不加噪声。
RlweCt rot_select(const RlweCt &ct, GSWCt &encrypted_bit, size_t shift,
                  PirServer &mux, const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  // 守卫：shift 限定在 (0, n)——shift = 0 的选择没有意义，>= n 的移位量
  // 不会出现（上层按位分解保证每步移位是 2^idx < n）。
  require(shift > 0 && shift < N, "RotSelect shift must be in (0, n)");

  // 准备 CMux 的两条候选分支：unrotated = C 本身，rotated = X^{-shift}·C
  //（负指数编码为 X^{2n - shift}）。位为 0 保留前者，位为 1 选中后者。
  RlweCt unrotated = ct;
  RlweCt rotated = mul_x_pow(ct, 2 * N - shift, scheme);
  // 输出缓冲清零后交给选择器填写。
  RlweCt result;
  result.c0.assign(ct.c0.size(), 0);
  result.c1.assign(ct.c1.size(), 0);
  // 仓库现成的 RGSW 外积选择器：result = unrotated + ExtPdt(rotated - unrotated, S)，
  // 展开正是 RotSelect 公式——旋转选择完全复用 CMux，无需新原语。
  mux.ext_prod_mux(unrotated, rotated, encrypted_bit, result);
  return result;
}

// Algorithm 5 PrivateRotateLevel：把选层输出私有地乘 X^{-γ_ℓ}。
// 流水线位置：每层三步（选层 select_level → 本函数私有旋转 → project_keep_stride
// 投影）中的第二步，负责把目标记录对齐到"系数 0 所在的跨步格"，随后投影才能按
// 公开 stride 过滤掉其余记录。
// 输入：选层后的密文 ct、该层公开计划 plan（γ 活跃位窗口）、完整 r 长 γ 位 RGSW
// 选择器数组（按全局位号索引，所有层复用同一份）。输出：旋转后的密文。
// 数学：层截断 γ_ℓ = Σ_idx bit_v·2^idx（v = gamma_begin + idx），故
// X^{-γ_ℓ} = Π_idx (X^{-2^idx})^{bit_v}——按位串接"乘 X^{-2^idx} 与否"的私有选择
// 即得整体旋转，每步选择位始终加密，服务器学不到 γ 的任何位。
RlweCt private_rotate_level(RlweCt ct, const LevelPlan &plan,
                            std::span<GSWCt> gamma_selectors, PirServer &mux,
                            const PirParams &scheme) {
  // 守卫：plan 声明的活跃 γ 位窗口必须整个落在选择器数组之内
  //（gamma_count == 0 表示本层无需旋转，此时不作要求）。
  require(plan.gamma_begin + plan.gamma_count <= gamma_selectors.size() ||
              plan.gamma_count == 0,
          "rotation needs a selector for every active gamma bit");
  // Algorithm 5 主循环：第 idx 个活跃位（全局位号 v = gamma_begin + idx）贡献一次
  // 乘 X^{-2^idx} 的私有选择——移位量 2^idx 是位在"窗口内"的权重，而选择器按全局
  // 位号 v 取：层 ℓ >= r 用完整 γ，其上各层正是靠这个错位复用同一数组的高位前缀段。
  for (size_t idx = 0; idx < plan.gamma_count; ++idx) {
    const size_t v = plan.gamma_begin + idx;
    ct = rot_select(ct, gamma_selectors[v], size_t{1} << idx, mux, scheme);
  }
  // 组合完成：密文等于选层输出乘 X^{-γ_ℓ}，目标记录已移到系数 0 的跨步格上。
  return ct;
}
