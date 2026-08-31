#include "tree_compress.h"

#include "utils.h"

#include <stdexcept>
#include <string>

namespace {

// 统一的入参守卫：条件不满足时抛 std::invalid_argument，前缀标注模块名，
// 让调用错误（而非算术错误）在进入任何环运算之前就被拦下。
void require(bool condition, const char *message) {
  if (!condition) {
    throw std::invalid_argument(std::string("tree_compress: ") + message);
  }
}

// gadget 数字分解：把多项式每个系数按无符号 base-2^{base_log2} 拆成 l2 个数字，
// 即 poly[i] = sum_t digits[t][i] * B^t（B = 2^{base_log2}，|digit| < B）。
// 这是 gadget 密钥切换的标准第一步：digit 变小后，digit × e_ksk 的噪声才可控。
std::vector<std::vector<uint64_t>> decompose_poly(
    const std::vector<uint64_t> &poly, size_t base_log2, size_t l2) {
  // digits[t] 是第 t 位数字组成的多项式，先全部置 0。
  std::vector<std::vector<uint64_t>> digits(
      l2, std::vector<uint64_t>(poly.size(), 0));
  // 低 base_log2 位的掩码；base_log2 >= 64 时移位是 UB，退化为全 1 掩码。
  const uint64_t mask = (base_log2 >= 64) ? ~uint64_t{0}
                                          : ((uint64_t{1} << base_log2) - 1);
  // 逐系数取低位、右移，得到从低到高的 l2 个数字。
  for (size_t i = 0; i < poly.size(); ++i) {
    uint64_t value = poly[i];
    for (size_t t = 0; t < l2; ++t) {
      digits[t][i] = value & mask;
      value >>= base_log2;
    }
  }
  return digits;
}

// acc += x (mod q)，逐系数原地累加：密钥切换里 digit × KSK 行的累加器。
// 两个输入都已在 [0, q)，和 < 2q，一次取模即可。
void add_inplace_mod(std::vector<uint64_t> &acc,
                     const std::vector<uint64_t> &x, uint64_t q) {
  for (size_t i = 0; i < acc.size(); ++i) {
    acc[i] = (acc[i] + x[i]) % q;
  }
}

}  // namespace

// R_{n2} = Z_q[Y]/(Y^{n2}+1) 的负循环乘法参考核。
// 流水线位置：压缩路径里所有小环乘法（digit × KSK 行、客户端 c1 × s2）都走这里。
// 输入：系数形式的 a、b（系数已在 [0, q)），模数 q；输出：a*b 的系数形式。
// 设计动机：q 是合成模数（两个 ~29 位 NTT 友好素数之积，见 CompositeRnsTables），
// schoolbook 免去为小环再注册 2*n2 次单位根的一步（无需，并非不可——
// init_composite_rns 的 CRT 合根手法同样适用）；"正负分桶 + 每个输出一次
// u128 规约"换取正确性优先的实现，NTT 化留作优化。
std::vector<uint64_t> small_ring_mul(const std::vector<uint64_t> &a,
                                     const std::vector<uint64_t> &b,
                                     uint64_t q) {
  // 以 a 的长度为环维度；守卫防止两输入长度不一致或空输入。
  const size_t n2 = a.size();
  require(b.size() == n2 && n2 > 0, "ring product needs equal-length inputs");
  // 溢出前提（免中途取模的关键）：每个乘积 < q^2 < 2^116，每个符号桶最多累加
  // n2 <= 2^11 个乘积，故桶值 < 2^127，uint128 不溢出——每个输出系数只需在
  // 循环结束后做一次 % q。
  std::vector<uint64_t> out(n2, 0);
  for (size_t k = 0; k < n2; ++k) {
    // 负循环卷积按符号拆两桶：Y^{i+j}，i+j < n2 时贡献 +（positive 桶），
    // i+j >= n2 时 Y^{i+j} = -Y^{i+j-n2} 贡献 -（negative 桶）；
    // 最后统一做 pos - neg，避免在无符号域里逐项处理负数。
    uint128_t positive = 0, negative = 0;
    for (size_t i = 0; i < n2; ++i) {
      // 稀疏跳过：digit 多项式与三值密钥都有大量零系数，先判 0 再乘。
      const uint64_t ai = a[i];
      if (ai == 0) continue;
      // 固定输出下标 k，找配对下标 j 使 i + j ≡ k (mod n2)：
      // k >= i 时 j = k - i（不回绕），否则 j = n2 + k - i（回绕一圈）。
      const size_t j = k >= i ? k - i : n2 + k - i;
      const uint64_t bj = b[j];
      if (bj == 0) continue;
      const uint128_t product = static_cast<uint128_t>(ai) * bj;
      if (k >= i) {
        positive += product;
      } else {
        // 回绕情形 i + j = n2 + k：X^{n2+k} = -X^k，故进 negative 桶。
        negative += product;
      }
    }
    // 每桶一次规约，再在 Z_q 里做减法（+q 防下溢），得到最终系数。
    const uint64_t pos = static_cast<uint64_t>(positive % q);
    const uint64_t neg = static_cast<uint64_t>(negative % q);
    out[k] = (pos + q - neg) % q;
  }
  return out;
}

// 服务端压缩入口（M7 流水线最后一步之前的环切换）。位置：answer_path_compressed
// 在完成打包、但尚未降模时调用它，替代大环的 switch_response_to_small_q。
// 输入：全 q、系数形式的打包大环响应 packed_full_q（载荷全在偶系数），打包端的
// 每层大环偏移 big_offsets，层数 level_count，注册的环切换密钥 keys，方案参数。
// 输出：R_{n2} 上、模数 q2 的单条压缩密文及其小环偏移表。
// 数学流程：偶奇拆分 → Y·a_o 移位 → base-B gadget 分解 → digit × KSK 累加
// （全 q 下切到 s2）→ 居中降模到 q2。顺序纪律：切换必须在全 q 做，否则
// q2 下的 KS 噪声（>= 2^10）会淹没 Delta2 = 2^9。
CompressedPathResponse compress_path_response(
    const RlweCt &packed_full_q, const std::vector<size_t> &big_offsets,
    size_t level_count, const TreeRingSwitchKeys &keys,
    const PirParams &scheme) {
  constexpr size_t N = DBConsts::PolyDegree;
  // 守卫：偶奇相位分解与 KSK 语义按单模数（K=1）推导，多 limb 需另行推导
  //（与 create_ring_switch_bundle 的同款守卫对应）。schoolbook 的不溢出
  // 前提 n2·q² < 2^127 由参数点保证，见 small_ring_mul。
  require(scheme.K() == 1,
          "the d = 2 ring switch is implemented for single-limb schemes");
  // 守卫：必须是系数形式（偶奇拆分按系数下标进行）且尚未降模的全尺寸密文。
  require(!packed_full_q.ntt_form && packed_full_q.c0.size() == N &&
              packed_full_q.c1.size() == N,
          "compression consumes the coefficient-form full-q response");
  // 守卫：密钥的目标环必须恰是半环（d = 2）。
  require(keys.n2 * 2 == N, "keys must target n2 = n / 2");
  // 守卫：s_e、s_o 两个分量各需一整组 l2 行 gadget KSK，缺一则切换不完整。
  require(keys.rows.size() == 2 && keys.rows[0].size() == keys.l2 &&
              keys.rows[1].size() == keys.l2,
          "one gadget row set per secret component is required");
  // 守卫：偶对齐前提——载荷若落在奇系数上会被压缩映射直接丢掉，必须提前拒绝。
  for (size_t offset : big_offsets) {
    require(offset % 2 == 0,
            "compression needs the payload on even coefficients");
  }

  // 小环维度与全 q（K=1 时 RNS 只有一个 limb，即完整模数）。
  const size_t n2 = keys.n2;
  const uint64_t q = scheme.get_rns_mods()[0];

  // 偶奇拆分 f(X) = f_e(X^2) + X f_o(X^2)：取大环相位 c0 + c1 s 的偶部。
  // c0_e（c0 的偶系数）直接携带载荷相位；c1 拆出的 (a_e, a_o) 是与密钥相关的部分，
  // 偶部相位 = c0_e + a_e s_e + Y a_o s_o —— 一条 {s_e, s_o} 下的 2-秩 MLWE 密文。
  std::vector<uint64_t> c0_e(n2), a_e(n2), a_o(n2);
  for (size_t k = 0; k < n2; ++k) {
    c0_e[k] = packed_full_q.c0[2 * k];
    a_e[k] = packed_full_q.c1[2 * k];
    a_o[k] = packed_full_q.c1[2 * k + 1];
  }
  // 计算 Y * a_o：小环里 Y 是 X^2 的像，乘 Y 即负循环移位——
  // 系数整体右移一位，最高位系数回绕到常数项并取负（Y^{n2} = -1）。
  // 这样 KSK 只需针对 s_o 本身生成：c1 与 s 两个奇部各带的 X 相乘出的
  // Y = X² 因子，在此显式吸收进 a_o。
  std::vector<uint64_t> ya_o(n2);
  ya_o[0] = a_o[n2 - 1] == 0 ? 0 : q - a_o[n2 - 1];
  for (size_t k = 1; k < n2; ++k) ya_o[k] = a_o[k - 1];

  // 全 q 下的 gadget 密钥切换：out = (c0_e, 0) + sum_{c,t} digit_{c,t} * KSK_c[t]。
  // KSK 行满足 c0 = -c1 s2 + e + B^t s_c，故累加后 out 的相位（关于 s2）
  // = c0_e + a_e s_e + Y a_o s_o + 小噪声，即偶部相位原样保留、密钥换成 s2。
  // c0_e 无密钥依赖，直接作为累加器初值搬进 out_c0。
  std::vector<uint64_t> out_c0 = c0_e, out_c1(n2, 0);
  // 两个待切换分量：c = 0 对应 a_e（配 s_e 的 KSK），c = 1 对应 Y a_o（配 s_o 的）。
  const std::vector<uint64_t> *components[2] = {&a_e, &ya_o};
  for (size_t c = 0; c < 2; ++c) {
    // base-B（B = 2^{base_log2}）数字分解：digit 变小，digit × e_ksk 的噪声
    // 才被控制在 ~d*l2*B*|e_fresh|*sqrt(n2) ~ 2^39 << Delta/2 ~ 2^44。
    const auto digits =
        decompose_poly(*components[c], keys.base_log2, keys.l2);
    // 逐数字位累加 digit[t] × (KSK 行的 c0, c1)，全部运算保持在全 q 下。
    for (size_t t = 0; t < keys.l2; ++t) {
      add_inplace_mod(out_c0,
                      small_ring_mul(digits[t], keys.rows[c][t].first, q), q);
      add_inplace_mod(out_c1,
                      small_ring_mul(digits[t], keys.rows[c][t].second, q),
                      q);
    }
  }

  // 最后一步：居中降模到小响应模数 q2（小环版的 Milestone-5 模切换）：
  // x -> round(x * q2 / q)。缩放因子 q2/q ~ 2^-36 把携带噪声压回 ~100、
  // KS 项压到 O(10)，取整误差另加 ~|s2|/2——这正是"先全 q 切换、后 rescale"
  // 能保住 Delta2 = 2^9 解码余量的原因。
  const uint64_t q2 = scheme.get_small_q();
  // 守卫：q2 必须严格小于 q，否则谈不上"压缩"且下面的舍入公式前提不成立。
  require(q2 < q, "compression expects a narrower response modulus");
  // 逐系数四舍五入缩放：x*q2 < 2^80 在 u128 内不溢出，+q/2 实现最近整数舍入，
  // 末尾 % q2 处理 x 贴近 q 时舍入到 q2 的边界情形。
  const auto rescale = [&](std::vector<uint64_t> &poly) {
    for (uint64_t &x : poly) {
      x = static_cast<uint64_t>(
          (static_cast<uint128_t>(x) * q2 + q / 2) / q) % q2;
    }
  };
  rescale(out_c0);
  rescale(out_c1);

  // 组装响应：密文本体 + 解码所需的公开元数据（模数、层数、小环偏移表）。
  CompressedPathResponse response;
  response.n2 = n2;
  response.c0 = std::move(out_c0);
  response.c1 = std::move(out_c1);
  response.modulus = q2;
  response.level_count = level_count;
  // 大环偶系数 2k 被映到小环系数 k，故每层偏移整除 2 即为小环偏移。
  response.level_offsets.reserve(big_offsets.size());
  for (size_t offset : big_offsets) {
    response.level_offsets.push_back(offset / 2);
  }
  return response;
}

// 客户端解码（M7 流水线终点）：在小环、小模数 q2 下用 s2 解密压缩响应，
// 再按小环放置图逐层读出路径节点的 g 个 chunk。
// 输入：压缩响应、客户端私钥 s2、明文模数 t = plain_mod、每节点 chunk 数 g、
// 大环记录跨步 rho。输出：path[level][j] = 第 level 层节点的第 j 个 chunk 值。
// 数学：phase = c0 + c1 s2 (mod q2)，message = round(phase * t / q2)；
// 层 z 的 chunk j 位于小环系数 offset_z + j * (rho/2)（跨步随环减半）。
std::vector<std::vector<uint64_t>> decode_compressed_path(
    const CompressedPathResponse &response,
    const TreeRingSwitchSecret &secret, uint64_t plain_mod, size_t g,
    size_t rho) {
  const size_t n2 = response.n2;
  // 守卫：密钥与响应必须属于同一个小环，防止拿错 bundle 解错响应。
  require(secret.n2 == n2 && secret.s2.size() == n2,
          "decoding secret does not match the response ring");
  // 守卫：偏移表必须逐层齐全，否则放置图无从谈起。
  require(response.level_offsets.size() == response.level_count,
          "compressed response is missing its offset map");
  // 守卫：rho 为奇数时 rho/2 会截断、chunk 落点错位——d = 2 切换要求偶跨步。
  require(rho % 2 == 0, "record stride must be even for the d = 2 switch");

  // s2 以全 q 编码存放（-1 == q-1 > 1），这里按响应模数 q2 重新编码三值：
  // 大于 1 的值必是全 q 下的 -1，映到 q2 - 1；0/1 原样保留。
  const uint64_t q2 = response.modulus;
  std::vector<uint64_t> s2_q2(n2);
  for (size_t i = 0; i < n2; ++i) {
    s2_q2[i] = secret.s2[i] > 1 ? q2 - 1 : secret.s2[i];
  }
  // 解密：phase = c0 + c1 * s2 (mod q2)。乘法复用小环 schoolbook 核，
  // c0 补一次 % q2 是防御性的（构造上已在 [0, q2)）。
  std::vector<uint64_t> phase = small_ring_mul(response.c1, s2_q2, q2);
  for (size_t i = 0; i < n2; ++i) {
    phase[i] = (phase[i] + response.c0[i] % q2) % q2;
  }

  // 逐系数取整解码并顺带量测噪声余量（诊断用，不影响返回值）。
  uint64_t max_noise = 0;
  std::vector<uint64_t> values(n2);
  for (size_t i = 0; i < n2; ++i) {
    // 消缩放：m = round(phase * t / q2) mod t，即除以 Delta2 = q2/t 后取整。
    const uint64_t m =
        utils::round_div_u128(static_cast<uint128_t>(phase[i]) * plain_mod,
                              q2) % plain_mod;
    values[i] = m;
    // 反推该消息的无噪相位 approx = round(q2 * m / t)，与实际相位的
    // 环上距离（取 ±q2/2 内的居中代表）就是这枚系数的残余噪声。
    const uint64_t approx =
        utils::round_div_u128(static_cast<uint128_t>(q2) * m, plain_mod) % q2;
    const uint64_t up = phase[i] >= approx ? phase[i] - approx
                                           : q2 - approx + phase[i];
    const uint64_t noise = up > q2 / 2 ? q2 - up : up;
    if (noise > max_noise) max_noise = noise;
  }
  // 打印到最近码字的最大距离与半步长界 q2/(2t)：解码正确时它等于真实噪声，
  // 远低于界即余量健康。注意该量测构造上不会超过界（取的就是最近码字），
  // 逼近界是危险信号，不能由"低于界"反推全部系数解码正确。
  BENCH_PRINT("Compressed-response noise: max " << max_noise << " of bound "
              << q2 / (2 * plain_mod));

  // 按小环放置图收集路径：层 level 的 chunk j 在系数 offset + j * (rho/2)。
  // 大环跨步 rho 经偶奇压缩后减半——这正是偏移/跨步同除以 2 的对齐结果。
  const size_t rho2 = rho / 2;
  std::vector<std::vector<uint64_t>> path;
  path.reserve(response.level_count);
  for (size_t level = 0; level < response.level_count; ++level) {
    std::vector<uint64_t> chunks(g);
    for (size_t j = 0; j < g; ++j) {
      chunks[j] = values[response.level_offsets[level] + j * rho2];
    }
    path.push_back(std::move(chunks));
  }
  return path;
}
