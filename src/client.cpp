#include "client.h"
#include "pir.h"
#include "utils.h"
#include "gsw.h"
#include "rlwe.h"
#include "hexl/hexl.hpp"
#include <cassert>
#include <memory>
#include <random>
#include <stdexcept>


// Build the K-limb sk lazily because its construction depends on PirParams.
static RlweSk make_client_sk(const PirParams &pir_params, std::mt19937_64 &rng) {
  const auto &qs_arr = pir_params.get_rns_mods();
  const std::vector<uint64_t> qs(qs_arr.begin(), qs_arr.end());
  return gen_secret_key_rns(DBConsts::PolyDegree, qs, rng);
}

PirClient::PirClient(const PirParams &pir_params)
    : client_id_(rand()), pir_params_(pir_params),
      rng_(std::random_device{}()),
      rlwe_sk_(make_client_sk(pir_params, rng_)) {}

GSWCt PirClient::generate_gsw_from_key() {
  constexpr size_t N = DBConsts::PolyDegree;

  // Recover ternary sk in coefficient form under q_0, then re-canonicalise
  // {-1 ↔ q_0-1} → {-1 ↔ q_k-1} for each limb. We pass the q_0 form to
  // plain_to_gsw, which re-encodes -1 per limb as the matching q_k-1.
  const uint64_t q0 = pir_params_.get_rns_mods()[0];
  std::vector<uint64_t> sk_coef(rlwe_sk_.data.begin(),
                                rlwe_sk_.data.begin() + N);
  utils::ntt_inv(sk_coef.data(), N, q0);

  GSWEval key_gsw(pir_params_, pir_params_.get_l_key(), pir_params_.get_base_log2_key());
  return key_gsw.plain_to_gsw(sk_coef, rlwe_sk_, rng_);
}

SharedPirSessionKeys PirClient::create_session_keys() {
  auto keys = std::make_shared<PirSessionKeys>();
  keys->bv_galois_keys = create_bv_galois_keys();
  keys->gsw_key = generate_gsw_from_key();
  return keys;
}

// [Tree PIR 会话密钥（显式高度版）] 与无参版本相同的密钥束，但 BV Galois 覆盖高度由
// 调用方显式指定。动机（手册 §5.1）：树协议的投影 project_keep_stride 要对每个
// j < min(r, level) 应用 Subs(η_j = n/2^j + 1)，与查询展开高度无关地需要覆盖到
// log₂ n 的密钥；而默认参数只派生到编译期 TREE_HEIGHT，g=1 时 r=11 > 10 就不够用。
// 输入 bv_key_height 是本会话的能力上界：生成的密钥支持自同构 Subs((N >> i) + 1)，
// i < bv_key_height——同一密钥族同时服务查询展开与投影，无需第二套密钥。
// 输出 SharedPirSessionKeys = {BV Galois 密钥, RGSW(s) 补全密钥}，整束交给服务端注册。
SharedPirSessionKeys PirClient::create_session_keys(size_t bv_key_height) {
  // 用 with_query_shape({1, 0, bv_key_height}) 派生一个"仅展开"参数视图：scheme
  // 字段（模数、gadget、密钥参数）原样保留，三个形状字段全部覆写
  //（fst_dim_sz=1、selector 位数=0、expansion_height=指定高度）；
  // gen_bv_galois_keys 只消费其中的 expansion_height，据此逐个生成
  // (N >> i) + 1（i < bv_key_height）的密钥。
  // 该视图不承载数据库，这里只把它当高度的载体。
  auto keys = std::make_shared<PirSessionKeys>();
  keys->bv_galois_keys = bvks::gen_bv_galois_keys(
      pir_params_.with_query_shape({1, 0, bv_key_height}), rlwe_sk_);
  // RGSW(s) 补全密钥与展开高度无关，直接复用生产路径的生成逻辑
  // （Algorithm 3 补全 bottom half 所需的材料）。
  keys->gsw_key = generate_gsw_from_key();
  return keys;
}


// [Tree PIR M7 环切换密钥] 生成 d=2 环切换（n → n₂ = n/2）所需的全部材料（手册 §4.3）。
// 数学背景：把大环多项式按奇偶分解 f(X) = f_e(X²) + X·f_o(X²)，取 Y = X² 后小环仍是
// 负循环（Y^{n₂} = X^n = −1）。大密文相位的偶部 = c0_e + a_e·s_e + Y·a_o·s_o，即一条
// 以主密钥的偶/奇小环分量 {s_e, s_o} 为密钥的 2-秩 MLWE 密文。服务端要把它切到独立
// 小环密钥 s₂ 下，就需要每个分量 s_c（c ∈ {e, o}）的 gadget 密钥切换行
//   KSK_c[t] = RLWE_{n₂,q}(B^t · s_c) under s₂，t < l₂。
// 输出 bundle 分两半：keys（两组 KSK 行，交给服务端做切换）与 secret（s₂ 及 n₂，
// 客户端留作解码）。所有行都在全 q 下构造——切换必须先于降模（§4.3 顺序纪律）。
TreeRingSwitchBundle PirClient::create_ring_switch_bundle(size_t n2) {
  constexpr size_t N = DBConsts::PolyDegree;
  // 守卫：当前实现只支持一步 d=2 切换（n₂ = n/2）；其他比例的相位分解未实现。
  if (n2 * 2 != N) {
    throw std::invalid_argument(
        "ring switch bundle currently supports n2 = n / 2");
  }
  // 守卫：只支持单 limb（K=1）方案；多 limb 下偶部相位与 KSK 语义都需另行推导。
  if (pir_params_.K() != 1) {
    throw std::invalid_argument(
        "ring switch bundle supports single-limb schemes");
  }
  // 单 limb 模数 q 与加密噪声标准差；gadget 取 l₂ = 2 级、基宽
  // base_log2 = ⌈log₂ q / l₂⌉（q≈2^58 时 B = 2^29），向上取整保证 B^{l₂} 覆盖整个 q，
  // 最高 digit 不会溢出。
  const uint64_t q = pir_params_.get_rns_mods()[0];
  const double sigma = pir_params_.get_noise_std_dev();
  const size_t l2 = 2;
  const size_t base_log2 = (pir_params_.get_ct_mod_width() + l2 - 1) / l2;

  // 主密钥以 NTT 域存储；先把 limb0 INTT 回系数形式，才能按系数下标做偶奇拆分：
  // component[0][k] = s_{2k}（即 s_e），component[1][k] = s_{2k+1}（即 s_o），
  // 正对应 f(X) = f_e(X²) + X·f_o(X²) 中的两个小环分量。
  std::vector<uint64_t> sk_coef(rlwe_sk_.data.begin(),
                                rlwe_sk_.data.begin() + N);
  utils::ntt_inv(sk_coef.data(), N, q);
  std::vector<std::vector<uint64_t>> component(
      2, std::vector<uint64_t>(n2, 0));
  for (size_t k = 0; k < n2; ++k) {
    component[0][k] = sk_coef[2 * k];
    component[1][k] = sk_coef[2 * k + 1];
  }

  // secret 半：独立采样三值小环目标密钥 s₂（不是 s 的派生物，安全性独立），
  // 系数以 mod q 的规范代表元存放（-1 ↔ q-1）。
  TreeRingSwitchBundle bundle;
  bundle.secret.n2 = n2;
  bundle.secret.s2.assign(n2, 0);
  utils::sample_ternary(bundle.secret.s2.data(), n2, q, rng_);

  // keys 半的公共几何：小环度数、gadget 级数与基宽，服务端分解 a_e / Y·a_o 时
  // 必须使用与此一致的 (l₂, B)。rows[c] 是分量 s_c 的 l₂ 条 KSK 行。
  bundle.keys.n2 = n2;
  bundle.keys.l2 = l2;
  bundle.keys.base_log2 = base_log2;
  bundle.keys.rows.assign(2, {});
  std::vector<uint64_t> noise(n2), c1(n2);
  for (size_t c = 0; c < 2; ++c) {
    bundle.keys.rows[c].reserve(l2);
    for (size_t t = 0; t < l2; ++t) {
      // 每条 gadget 行都是 s₂ 下的"裸消息"RLWE 加密：
      //   c0 = −c1·s₂ + e + B^t·s_c，  c1 均匀随机，e 高斯。
      // 消息 B^t·s_c 不乘 Δ——密钥切换消费的是 gadget 尺度，不是 BFV 明文尺度。
      utils::sample_uniform_poly(c1.data(), n2, q, rng_);
      utils::sample_gaussian(noise.data(), n2, q, sigma, rng_);
      // 先算 c1·s₂：small_ring_mul 是 R_{n₂} 上的负循环 schoolbook 乘法
      // （u128 单次规约参考核，无需为合成模数注册 2n₂ 次根）。
      std::vector<uint64_t> c0 = small_ring_mul(c1, bundle.secret.s2, q);
      // B^t 本身放得进 u64（l₂=2 时移位量 ≤ 30）；取 uint128 是为了让下面
      // component·power 的乘积直接落在 128 位算术里，与取模配套。
      const uint128_t power = static_cast<uint128_t>(1)
                              << (t * base_log2);
      for (size_t i = 0; i < n2; ++i) {
        // message = B^t · s_c[i] mod q，乘法走 uint128 中间量避免回绕。
        const uint64_t message = static_cast<uint64_t>(
            (static_cast<uint128_t>(component[c][i]) * power) % q);
        // 组装 c0[i] = −(c1·s₂)[i] + e[i] + message（mod q，逐项完成上面的公式）。
        c0[i] = (q - c0[i] + noise[i]) % q;
        c0[i] = (c0[i] + message) % q;
      }
      // 行按 (c0, c1) 存入分量 c 的第 t 级；c1 被拷贝，缓冲区留给下一轮复用。
      bundle.keys.rows[c].emplace_back(std::move(c0), c1);
    }
  }
  return bundle;
}

std::vector<size_t> PirClient::get_query_indices(
    const PirParams &query_params, size_t pt_idx) const {
  // Algorithm 4 line 1 把扁平 plaintext index 映射到 QueryPack 坐标。
  // col_idx 是首维 BFV one-hot 坐标；row_idx 覆盖其余维度。论文规则是
  // binary hypercube，这里实现为 complete-but-not-perfect/ragged tree。
  // 返回向量为 {col_idx, selector bits...}；selector bits 按服务端归约
  // 顺序输出，第一个 selector 处理 deepest folded leaves。
  const size_t col_idx = pt_idx % query_params.get_fst_dim_sz();  // the first dimension
  const size_t row_idx = pt_idx / query_params.get_fst_dim_sz();  // the rest of the dimensions
  const size_t other_dim_sz = query_params.get_other_dim_sz();
  const size_t d = query_params.get_num_dims();
  const size_t h = d - 1; // the height of the further dimension complete binary tree.
  
  std::vector<size_t> query_indices = {col_idx};

  // Handle single dimension case
  if (d == 1) {
    // For single dimension, we only need the column index
    DEBUG_PRINT("Single dimension case - returning col_idx: " << col_idx);
    return query_indices;
  }
  
  const size_t r = 2 * other_dim_sz - (1 << h);   // the number of elements in the last level of the complete binary tree.
  const size_t sl = other_dim_sz - r;

  // r 是实际落在 deepest level 的 leaves 数；sl 是已经在上一层表示的 rows。
  // row_idx < sl 时没有 folded leaf pair，因此 deepest selector bit 为 0，
  // perfect_idx 保持 row_idx。否则 corrected_idx 选中 r 个 deepest leaves
  // 之一：corrected_idx % 2 是 folded-pair bit，corrected_idx / 2 先把
  // leaf pair 折叠回 parent position，再输出剩余 perfect-tree selector bits。
  size_t perfect_idx;
  if (row_idx < other_dim_sz - r) {
    query_indices.push_back(0);
    perfect_idx = row_idx;
  } else {
    size_t corrected_idx = row_idx - sl;
    query_indices.push_back(corrected_idx % 2);
    perfect_idx = sl + corrected_idx / 2;
  }
  
  // For the remaining perfect tree levels, emit bits MSB-first
  if (h > 1) {
    // There are (h - 1) bits for the perfect subtree
    for (size_t k = h - 2; k + 1 > 0; k--) {
      query_indices.push_back((perfect_idx >> k) & 1ULL);
      if (k == 0) break;
    }
  }
  
  return query_indices;
}




RlweCt PirClient::fast_generate_query(const size_t pt_idx) {
  return fast_generate_query(pir_params_, pt_idx);
}

RlweCt PirClient::fast_generate_query(const PirParams &query_params,
                                      const size_t pt_idx) {
  if (!pir_params_.scheme_compatible(query_params)) {
    throw std::invalid_argument(
        "PirClient query layout is not scheme-compatible with its session");
  }
  if (pt_idx >= query_params.get_num_pt()) {
    throw std::out_of_range("PIR plaintext index exceeds the runtime layout");
  }

  constexpr size_t N = DBConsts::PolyDegree;
  const size_t K = query_params.K();
  const auto &qs_arr = query_params.get_rns_mods();
  const std::vector<uint64_t> qs(qs_arr.begin(), qs_arr.end());
  const uint64_t t = query_params.get_plain_mod();
  const double sigma = query_params.get_noise_std_dev();

  std::vector<size_t> query_indices =
      get_query_indices(query_params, pt_idx);
  PRINT_INT_ARRAY("\t\tquery_indices", query_indices.data(), query_indices.size());
  const size_t expan_height = query_params.get_expan_height();
  const size_t capacity = size_t{1} << expan_height;  // 2^h slots after expansion

  uint64_t inverse = 0;
  utils::try_invert_uint_mod(capacity, t, inverse);
  const size_t reversed_index = utils::bit_reverse(query_indices[0], expan_height);
  DEBUG_PRINT("reversed_index: " << reversed_index << ", query_indices[0]: " << query_indices[0]);

  // QueryPack 等价于先 packing plaintext vector 再执行 BFV encrypt。这里利用
  // BFV message-add 线性：先 encrypt zero 到 coefficient form，再把 scaled
  // plaintext 直接加到 c0 的 BitRev(col_idx) coefficient。注入量是
  // Delta*(capacity^-1 mod t)；capacity^-1 抵消 ExpandBFV 每层 add/sub
  // 引入的 scaling。K=1 分支用 round(q0*inverse/t) 表示 direct scaling；
  // K=2 分支先按 composite Q=q0*q1 计算 full-q plaintext lift，再降到各
  // RNS limb。
  RlweCt query;
  encrypt_zero_rns(rlwe_sk_, N, qs, sigma, rng_, query, /*ntt_form=*/false);

  // Adding 1^{-1} as a message to the query so that after expansion, the query will have 1's in the correct positions.
  if (K == 1) {
    const uint64_t Q = qs[0];
    const uint64_t scaled = utils::round_div_u128((uint128_t)Q * inverse, t) % Q;
    query.c0[reversed_index] = (query.c0[reversed_index] + scaled) % Q;
  } else {
    const uint128_t Q = static_cast<uint128_t>(qs[0]) * qs[1];
    const uint128_t Delta = Q / t;
    const uint64_t r = static_cast<uint64_t>(Q - Delta * t);
    const uint64_t r_inverse_round =
        static_cast<uint64_t>((static_cast<uint128_t>(r) * inverse + (t >> 1)) / t);
    const uint128_t scaled_mp = Delta * inverse + r_inverse_round;
    for (size_t k = 0; k < K; ++k) {
      const uint64_t scaled_k = static_cast<uint64_t>(scaled_mp % qs[k]);
      const size_t idx = k * N + reversed_index;
      query.c0[idx] = (query.c0[idx] + scaled_k) % qs[k];
    }
  }

  add_gsw_to_query(query_params, query, query_indices);
  return query;
}


void PirClient::add_gsw_to_query(
    RlweCt &query, const std::vector<size_t> &query_indices) {
  add_gsw_to_query(pir_params_, query, query_indices);
}

void PirClient::add_gsw_to_query(
    const PirParams &query_params, RlweCt &query,
    const std::vector<size_t> &query_indices) {
  if (!pir_params_.scheme_compatible(query_params)) {
    throw std::invalid_argument(
        "PirClient query layout is not scheme-compatible with its session");
  }
  // no further dimensions
  if (query_indices.size() == 1) { return; }
  const size_t expan_height = query_params.get_expan_height();
  const size_t capacity = size_t{1} << expan_height;  // 2^h slots after expansion
  const size_t l = query_params.get_l();
  const auto rns_mods = query_params.get_rns_mods();
  const size_t K = query_params.K();
  const size_t fst_dim_sz = query_params.get_fst_dim_sz();

  // 1/capacity per limb, cancels the scaling factor introduced by expansion.
  std::vector<uint64_t> inv(K);
  for (size_t k = 0; k < K; k++) {
    uint64_t result;
    utils::try_invert_uint_mod(capacity, rns_mods[k], result);
    inv[k] = result;
  }

  // MP gadget table: gadget[k][p] = B^(l-1-p) mod q_k. MSB-first
  // (p=0 = largest power), matching plain_to_gsw.
  std::vector<std::vector<uint64_t>> gadget =
      utils::gsw_gadget(l, query_params.get_base_log2(), rns_mods);

  // QueryPack packed slots layout:
  // [0, N0) 是首维 BFV one-hot。代码索引 i=1..query_indices.size()-1 时，
  // 第 i 个高维 selector 占用 [N0 + (i-1)*L_EP, N0 + i*L_EP)，即对应
  // RGSW sample 的 top half rows。selector=1 注入 gadget powers；
  // selector=0 保持这些 slots 为 encryption of zero。每个位置先 BitRev，
  // 再乘 capacity^-1，使 ExpandBFV 恢复预期 row constants。
  auto q_head = query.data(0);
  for (size_t i = 1; i < query_indices.size(); i++) {
    if (query_indices[i] != 1) continue;

    // l slots per dim, gadget value written under every limb.
    for (size_t k = 0; k < l; k++) {
      const size_t coef_pos = fst_dim_sz + (i - 1) * l + k;
      const size_t reversed_idx = utils::bit_reverse(coef_pos, expan_height);
      for (size_t mod_id = 0; mod_id < K; mod_id++) {
        const size_t pad = mod_id * DBConsts::PolyDegree;
        inter_coeff_t mod = rns_mods[mod_id];
        uint64_t coef = (inter_coeff_t)gadget[mod_id][k] * inv[mod_id] % mod;
        q_head[reversed_idx + pad] = (q_head[reversed_idx + pad] + coef) % mod;
      }
    }
  }
}


// Shared single-mod decryption under modulus `q` using the matching sk.
// Computes phase = c0 + c1*s (mod q), recovers m = round(phase * t / q),
// and returns (plaintext, noise_budget).
static void decrypt_phase_single_mod(const RlweCt &ct,
                                     const uint64_t *sk_ntt,
                                     uint64_t q, uint64_t t,
                                     RlwePt &out_pt,
                                     int &out_budget) {
  constexpr size_t N = DBConsts::PolyDegree;

  std::vector<uint64_t> phase(N);
  std::vector<uint64_t> c0(N), c1(N);
  for (size_t i = 0; i < N; i++) {
    c0[i] = ct.c0[i] % q;
    c1[i] = ct.c1[i] % q;
  }

  // Compute a * s (mod q) in NTT.
  if (ct.ntt_form) {
    intel::hexl::EltwiseMultMod(phase.data(), c1.data(), sk_ntt, N, q, 1);
    utils::ntt_inv(phase.data(), N, q);
    utils::ntt_inv(c0.data(), N, q);
  } else {
    utils::ntt_fwd(c1.data(), N, q);
    intel::hexl::EltwiseMultMod(phase.data(), c1.data(), sk_ntt, N, q, 1);
    utils::ntt_inv(phase.data(), N, q);
  }
  // Add c0 in coefficient form (mod q).
  intel::hexl::EltwiseAddMod(phase.data(), phase.data(), c0.data(), N, q);

  out_pt.data.assign(N, 0);
  const uint64_t delta = q / t;
  const uint64_t half_q = q / 2;
  uint64_t max_noise = 0;

  for (size_t i = 0; i < N; i++) {
    uint64_t m = utils::round_div_u128((uint128_t)phase[i] * t, q) % t;
    out_pt.data[i] = m;

    // Compare against round(q*m/t), not floor(q/t)*m: when q is not a multiple
    // of t, the latter undercounts by m*(q mod t)/t and inflates the residue.
    uint64_t approx = utils::round_div_u128((uint128_t)q * m, t) % q;
    uint64_t noise_pos = (phase[i] >= approx) ? (phase[i] - approx) : (q - approx + phase[i]);
    uint64_t noise_abs = (noise_pos > half_q) ? (q - noise_pos) : noise_pos;
    if (noise_abs > max_noise) max_noise = noise_abs;
  }

  out_budget = (max_noise > 0)
    ? static_cast<int>(std::log2(static_cast<double>(q) / (2.0 * t * max_noise)))
    : static_cast<int>(std::log2(static_cast<double>(q) / (2.0 * t)));
}

RlwePt PirClient::decrypt_ct(const RlweCt &ct) {
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs_arr = pir_params_.get_rns_mods();
  const std::vector<uint64_t> qs(qs_arr.begin(), qs_arr.end());
  const uint64_t t = pir_params_.get_plain_mod();
  RlwePt result;
  decrypt_rns(ct, rlwe_sk_, N, qs, t, pir_params_.get_rns_tables(), result);
  return result;
}

// [共用底座 / Tree 打包查询入口] 加密零的新鲜密文：系数形式、全 Q，每次调用消耗新的
// (a, e) 随机性。两类使用者：(1) 噪声基线类测试；(2) tree PIR 的打包查询入口——
// make_tree_query 以它为底座，把 Δ·(W⁻¹ mod t)、(W⁻¹ mod q_k)·G[k] 等常数直接加进
// c0 的目标系数（Enc(0) + 明文常数 = 该常数的合法加密），从而免于重新实现编码器。
RlweCt PirClient::fresh_zero_ct() {
  // 取全 RNS limb 集与噪声参数，调用 encrypt_zero_rns 产出系数形式（非 NTT）密文，
  // 保持系数形式是为了让调用方能按系数下标做常数注入（BitRev 槽位写入）。
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs_arr = pir_params_.get_rns_mods();
  const std::vector<uint64_t> qs(qs_arr.begin(), qs_arr.end());
  const double sigma = pir_params_.get_noise_std_dev();
  RlweCt ct;
  encrypt_zero_rns(rlwe_sk_, N, qs, sigma, rng_, ct, /*ntt_form=*/false);
  return ct;
}

int PirClient::noise_budget(const RlweCt &ct) {
  // Debug/diagnostic single-mod estimate under the first limb. It derives a
  // phase/noise estimate from the K=1-style path; the K-aware decrypt_rns path
  // does not expose noise and this is not SEAL-backed invariant_noise_budget.
  const uint64_t q = pir_params_.get_rns_mods()[0];
  const uint64_t t = pir_params_.get_plain_mod();
  RlwePt tmp;
  int budget = 0;
  decrypt_phase_single_mod(ct, rlwe_sk_.data.data(), q, t, tmp, budget);
  return budget;
}



RlweCt PirClient::load_resp_from_stream(std::stringstream &resp_stream) {
  // 这里是 response codec inverse。server 写出的 single-limb small-q ciphertext
  // 其 layout 是先 c0 coefficients、再 c1 coefficients；每个 coefficient 精确使用
  // small_q_width bits，bit order 为 LSB-first。恢复出的 ciphertext 是
  // coefficient-form；query 和 key transport 位于这个 codec 之外。
  //
  // 在 Prototype trust boundary 上，expected payload 内部 EOF 会被拒绝，但不会
  // 验证 decoded coefficient < small_q，也不检查 expected payload 之后的额外
  // bytes（包括 padding），且没有 authentication 或 integrity protection。
  // decrypt path 后续会按 small_q 对 c0/c1 取模/规约。
  const size_t small_q = pir_params_.get_small_q();
  const size_t small_q_width =
      static_cast<size_t>(std::ceil(std::log2(small_q)));
  constexpr size_t coeff_count = DBConsts::PolyDegree;

  RlweCt result;
  result.c0.assign(coeff_count, 0);
  result.c1.assign(coeff_count, 0);

  uint8_t current_byte = 0;
  size_t bits_left = 0;
  auto next_bit = [&]() -> uint8_t {
    if (bits_left == 0) {
      int ch = resp_stream.get();
      if (ch == EOF)
        throw std::runtime_error("unexpected end of response stream");
      current_byte = static_cast<uint8_t>(ch);
      bits_left = 8;
    }
    uint8_t bit = current_byte & 1;
    current_byte >>= 1;
    --bits_left;
    return bit;
  };
  auto read_coeff = [&](uint64_t &dest) {
    dest = 0;
    // 位序与 save_resp_to_stream 相同：从下一个 LSB-first stream bit 读取
    // coefficient 的 bit j，并恢复到 position j。
    for (size_t j = 0; j < small_q_width; ++j)
      dest |= static_cast<uint64_t>(next_bit()) << j;
  };

  for (size_t i = 0; i < coeff_count; ++i) read_coeff(result.c0[i]);
  for (size_t i = 0; i < coeff_count; ++i) read_coeff(result.c1[i]);
  result.ntt_form = false;
  return result;
}


RlwePt PirClient::decrypt_mod_q(const RlweCt &ct) const {
  // 这里是 Algorithm 4 response 的 custom small-q decryption。输入是
  // load_resp_from_stream 恢复出的 single-limb coefficient-form ciphertext。
  // 其中 ternary secret key 原本在旧 full-q limb 下生成，所以 multiplication 前
  // get_sk_ntt_small_q 会把 -1 == old_q-1 改写为 small_q-1。随后计算
  // phase = c0 + c1*s (mod small_q)，plaintext = round(phase*t/small_q)。
  constexpr size_t N = DBConsts::PolyDegree;
  const uint64_t q = pir_params_.get_small_q();
  const uint64_t t = pir_params_.get_plain_mod();

  std::vector<uint64_t> phase(N);
  std::vector<uint64_t> c0(N), c1_ntt(N);
  // Reduce mod q in case mod_switch_inplace produced values = q (from rounding)
  for (size_t i = 0; i < N; i++) {
    c0[i] = ct.c0[i] % q;
    c1_ntt[i] = ct.c1[i] % q;
  }
  std::vector<uint64_t> sk_ntt_small_q = get_sk_ntt_small_q(pir_params_.get_rns_mods()[0], q);
  utils::ntt_fwd(c1_ntt.data(), N, q);
  intel::hexl::EltwiseMultMod(phase.data(), c1_ntt.data(), sk_ntt_small_q.data(), N, q, 1);
  utils::ntt_inv(phase.data(), N, q);
  intel::hexl::EltwiseAddMod(phase.data(), phase.data(), c0.data(), N, q);

  RlwePt result;
  result.data.assign(N, 0);
  const uint64_t delta = q / t;
  const uint64_t half_q = q / 2;
  uint64_t max_noise = 0;

  for (size_t i = 0; i < N; i++) {
    uint64_t m = utils::round_div_u128((uint128_t)phase[i] * t, q) % t;
    result.data[i] = m;

    uint64_t approx = utils::round_div_u128((uint128_t)q * m, t) % q;
    uint64_t noise_pos = (phase[i] >= approx) ? (phase[i] - approx) : (q - approx + phase[i]);
    uint64_t noise_abs = (noise_pos > half_q) ? (q - noise_pos) : noise_pos;
    if (noise_abs > max_noise) max_noise = noise_abs;
  }

  int budget = (max_noise > 0)
    ? static_cast<int>(std::log2(static_cast<double>(q) / (2.0 * t * max_noise)))
    : static_cast<int>(std::log2(static_cast<double>(q) / (2.0 * t)));
  BENCH_PRINT("Noise budget after decryption: " << budget
              << " (max noise: " << max_noise << ")");

  return result;
}


std::vector<uint64_t> PirClient::get_sk_ntt_small_q(uint64_t old_q, uint64_t small_q) const {
  constexpr size_t N = DBConsts::PolyDegree;

  // rlwe_sk_ is K-limb in NTT form (limb k under q_k). The first limb under
  // q_0 = old_q is what we need; ternary coefficients reduce identically across
  // limbs so the first limb's coefficient form recovers {-1, 0, 1}.
  std::vector<uint64_t> sk_coef(rlwe_sk_.data.begin(),
                                rlwe_sk_.data.begin() + N);
  utils::ntt_inv(sk_coef.data(), N, old_q);

  // Rewrite -1 mod old_q as -1 mod small_q (sk is ternary: {0, 1, -1}).
  std::vector<uint64_t> sk_ntt_small_q_(N);
  for (size_t i = 0; i < N; i++) {
    sk_ntt_small_q_[i] = (sk_coef[i] > 1) ? (small_q - 1) : sk_coef[i];
  }
  utils::ntt_fwd(sk_ntt_small_q_.data(), N, small_q);
  return sk_ntt_small_q_;
}
