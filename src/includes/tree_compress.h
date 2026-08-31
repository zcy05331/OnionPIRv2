#pragma once

#include "pir.h"
#include "rlwe.h"

#include <cstddef>
#include <cstdint>
#include <vector>

// Milestone-7 小环响应压缩（蓝图 §23.3）：实现 d = n / n2 = 2 的环切换，并配合
// §23.4 的"对齐"半边——打包端把每个路径槽位都放到偶系数子格上，使整个载荷都能
// 完整穿过压缩映射（奇系数只剩噪声，丢弃无害）。
//
// 构造（偶奇分解 → MLWE 视角 → gadget 密钥切换）：
//   把 f(X) = f_e(X^2) + X f_o(X^2) 分解为偶部/奇部，f_e, f_o 属于小环
//   R_{n2} = Z_q[Y]/(Y^{n2} + 1)（Y = X^2；Y^{n2} = X^n = -1，故小环仍是负循环）。
//   大环相位 c0 + c1 s 的偶部等于
//     c0_e + a_e s_e + Y a_o s_o,
//   即以大密钥的两个小环分量 {s_e, s_o} 为密钥的 2-秩 MLWE 密文。客户端注册一个
//   独立的三值目标密钥 s2，并给出 gadget 密钥切换行
//     KSK_c[t] = RLWE_{n2,q}(B^t s_c) under s2,  c ∈ {e, o};
//   服务端把 a_e 与 Y a_o 做 base-B 数字分解，digit × KSK 累加后就得到一条载荷
//   不变、密钥换成 s2 的 R_{n2} 普通 RLWE 密文。
//
// 噪声分析（k1_comp 参数点：q ~ 2^58，B = 2^29，l2 = 2，n2 = 1024）。切换必须在
// 全 q 下进行，此时 Delta = q/t ~ 2^45：
//   e_out = e_big + sum_{c,t} digit_{c,t} * e_ksk[c,t]
// 由于 |digit| < B，密钥切换项约为 d * l2 * B * |e_fresh| * sqrt(n2) ~ 2^39，
// 远低于 Delta/2 ~ 2^44。最后再做居中降模到 22 位小模数 q2，整体缩放 q2/q ~ 2^-36：
// 携带的路径噪声（~2^42.6）回到常规的 ~100，KS 项被压到 O(10)，取整再加 ~|s2|/2
// ——与未压缩响应有相同的解码余量（测试中实测）。
// 关键教训：若直接在 q2（Delta2 = 2^9）下做 gadget-KS，KS 噪声 ≥ 2^10 会直接越界，
// 所以顺序纪律是"先在全 q 切换、后 rescale"。
//
// 小环乘法用系数域负循环 schoolbook，每个输出系数只做一次 uint128 规约
// （n2 * q^2 < 2^127 不溢出），因此合成模数 q 无需注册 2*n2 次单位根（免 NTT）；
// 素数模数下的 NTT 化留作后续优化。

// 服务端持有的环切换密钥（客户端一次性生成并注册，~58 KB）。
struct TreeRingSwitchKeys {
  // 小环维度 n2 = n / 2（d = 2 切换要求 n2 * 2 == PolyDegree）。
  size_t n2 = 0;
  // gadget 基的位宽 log2(B)（运行点 B = 2^29）。
  size_t base_log2 = 0;
  // gadget 数字个数 l2（运行点 l2 = 2，覆盖 ~58 位的全 q）。
  size_t l2 = 0;
  // rows[c][t] = (c0, c1)：R_{n2} 上、全 q 下加密 B^t * s_c 于 s2 之下的 RLWE 行，
  // 即 c0 = -c1 * s2 + e + B^t * s_c。c = 0 对应偶分量 s_e，c = 1 对应奇分量 s_o；
  // 两个分量各配一组 l2 行，服务端用 digit × 行 的累加完成密钥切换。
  std::vector<std::vector<std::pair<std::vector<uint64_t>,
                                    std::vector<uint64_t>>>> rows;
};

// 客户端持有的压缩响应解码密钥：独立于大环密钥采样的小环目标密钥 s2。
struct TreeRingSwitchSecret {
  // 小环维度，须与 TreeRingSwitchKeys::n2 一致。
  size_t n2 = 0;
  // 三值密钥 s2 ∈ {-1, 0, 1}^{n2}，以全 q 下的系数形式存放（-1 表示为 q-1）；
  // 解码时会按当时的响应模数重新编码，见 decode_compressed_path。
  std::vector<uint64_t> s2;
};

// 把"注册给服务端的公钥材料"和"留在客户端的私钥"打包在一起，方便一次生成。
struct TreeRingSwitchBundle {
  TreeRingSwitchKeys keys;     // 注册给服务端（KSK 行，本身是密文，可公开）
  TreeRingSwitchSecret secret; // 只留在客户端（解码用的 s2）
};

// 一条压缩后的路径响应：单个 R_{n2} 密文（响应 11,264 B → 5,632 B）。
// 偏移是大环各层偏移除以 d = 2（大环偶系数 2k 落到小环系数 k）；层槽位 z 的
// 第 j 个 chunk 位于小环系数 z + j * (rho / 2)——跨步也随环减半。
struct CompressedPathResponse {
  // 小环维度 n2 = n / 2。
  size_t n2 = 0;
  // 密文两分量，系数形式，长度均为 n2，系数已落在 [0, modulus)。
  std::vector<uint64_t> c0, c1;
  // 最终居中降模后的小模数 q2（Milestone-5 的 22 位响应模数）。
  uint64_t modulus = 0;
  // 路径层数 L + 1（根到叶）。
  size_t level_count = 0;
  // 每层在小环里的槽位偏移（= 大环偏移 / 2，只依赖公开参数）。
  std::vector<size_t> level_offsets;
};

// R_{n2} = Z_q[Y]/(Y^{n2}+1) 上的负循环乘法（schoolbook 参考核，免 NTT 根注册）。
std::vector<uint64_t> small_ring_mul(const std::vector<uint64_t> &a,
                                     const std::vector<uint64_t> &b,
                                     uint64_t q);

// 服务端：输入是*尚未降模*的全 q 打包大环响应（载荷全部在偶系数上），先在全 q 下
// 用注册的 KSK 把它环切换到 R_{n2} / s2，再居中降模到小模数 q2。
// `big_offsets` 是打包端的每层偏移（必须全为偶数）。
CompressedPathResponse compress_path_response(
    const RlweCt &packed_full_q, const std::vector<size_t> &big_offsets,
    size_t level_count, const TreeRingSwitchKeys &keys,
    const PirParams &scheme);

// 客户端：用 s2 解密压缩响应，按跨步 rho / 2 每层读出 g 个 chunk（并打印噪声余量）。
std::vector<std::vector<uint64_t>> decode_compressed_path(
    const CompressedPathResponse &response,
    const TreeRingSwitchSecret &secret, uint64_t plain_mod, size_t g,
    size_t rho);
