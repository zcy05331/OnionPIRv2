#include "tree_query.h"

#include "utils.h"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <vector>

namespace {

// 守卫：两个写入 helper 都往系数 bit_reverse(logical, h_q) 落笔，因此展开
// 容量 2^h_q 本身必须放得进环（h_q <= log2 n），否则位反转后的下标可能越出
// 系数缓冲区。先查 h_q 是否会让移位溢出 size_t，再查 2^h_q 是否超过环维度。
void require_capacity_in_ring(size_t h_q) {
  if (h_q >= std::numeric_limits<size_t>::digits ||
      (size_t{1} << h_q) > DBConsts::PolyDegree) {
    throw std::invalid_argument(
        "query capacity 2^h_q exceeds the ring degree");
  }
}

// 守卫：打包（客户端）与解包（服务端）共用的前置条件——树参数必须派生自
// 当前这套方案（同一环维度、明文模数 t、gadget 长度、RNS 模数序列）。
// 否则两侧会对 Δ、W^{-1}、gadget 幂等尺度产生分歧，解出的常数静默错缩放。
void require_scheme_binding(const TreePirParams &tree,
                            const PirParams &scheme) {
  // 先做树参数自身的一致性校验（各派生量互相咬合，见 tree_index.h）。
  validate_tree_params(tree);
  // 再逐项比对树参数与方案的绑定字段：环维度 n、明文模数 t、两个 gadget
  // 长度（都被工厂冻结为 scheme.get_l()）以及完整的 RNS 模数序列。
  const auto &scheme_mods = scheme.get_rns_mods();
  if (tree.n != scheme.get_poly_degree() ||
      tree.t != scheme.get_plain_mod() ||
      tree.ell_beta != scheme.get_l() || tree.ell_gamma != scheme.get_l() ||
      !std::equal(tree.rns_moduli.begin(), tree.rns_moduli.end(),
                  scheme_mods.begin(), scheme_mods.end())) {
    throw std::invalid_argument(
        "tree parameters are not bound to this scheme");
  }
}

}  // namespace

// 工厂重载 1（2 参数）：g = 1 的冻结 MVP 形状，直接委托给 3 参数版。
TreePirParams make_tree_pir_params_for_scheme(size_t L, size_t a,
                                              const PirParams &scheme) {
  return make_tree_pir_params_for_scheme(L, a, /*g=*/1, scheme);
}

// 工厂重载 2（3 参数）：未显式给出会话密钥高度时，保守地假定会话按方案
// 默认展开高度注册了 Galois 密钥，委托给完整的 5 参数版做能力检查。
TreePirParams make_tree_pir_params_for_scheme(size_t L, size_t a, size_t g,
                                              const PirParams &scheme) {
  return make_tree_pir_params_for_scheme(L, a, g, scheme,
                                         scheme.get_expan_height());
}

// 工厂完整形式（5 参数）：树流水线中所有其它组件消费的 TreePirParams 都从
// 这里产出。输入是树形参 (L, a, g) 与当前方案；输出是一套已绑定该方案并
// 通过全部 §3.2 约束校验的树参数。数学上它固定分解
// N = 2^L, N0 = 2^a, b = L - r - a（r = log2 n），并派生打包容量
// w = N0 + ell*(b+r)、展开高度 h_q = ceil(log2 w)、展开因子 W = 2^{h_q}。
TreePirParams make_tree_pir_params_for_scheme(size_t L, size_t a, size_t g,
                                              const PirParams &scheme,
                                              size_t session_key_height) {
  // 把 ell_beta = ell_gamma 冻结为方案的 L_EP（scheme.get_l()）：这样每个
  // selector 行组都与现成的 gsw_gadget 表和 query_to_gsw 补全路径兼容；
  // 若 γ 另取一个 gadget 长度，就得为它单写一条转换路径。
  const std::vector<uint64_t> &mods = scheme.get_rns_mods();
  TreePirParams params = make_tree_pir_params(
      L, a, scheme.get_poly_degree(), g, scheme.get_l(), scheme.get_l(),
      scheme.get_plain_mod(),
      std::vector<uint64_t>(mods.begin(), mods.end()));
  // 运行时能力上界：会话密钥只携带到调用方实际注册高度为止的 Galois 代换。
  // 仅凭 W <= n 仍允许 h_q 一路到 log2 n，所以一个"更高但其余合法"的形状
  // 必须在工厂这里就失败，而不是等客户端已经打完包之后才在
  // set_client_session_keys 处报一条泛化错误。
  if (params.h_q > session_key_height) {
    throw std::invalid_argument(
        "tree query expansion height exceeds the session-key coverage");
  }
  return params;
}

// 派生"仅供展开使用"的参数视图：树查询的形状（首维 N0、b+r 个 selector
// 组、展开高度 h_q）无法由数据库规划器反推，只能经 with_query_shape 直接
// 写入这三个字段。得到的 PirParams 用来构造解包用的 PirServer 并做会话
// 密钥高度校验，它不承载任何数据库布局。
PirParams tree_query_expansion_params(const TreePirParams &tree,
                                      const PirParams &scheme) {
  return scheme.with_query_shape(
      {tree.N0, tree.b + tree.r, tree.h_q});
}

// α 常数写入（客户端打包的第一种尺度）：向密文的消息相关分量 c0 的系数
// BitRev(logical_coeff, h_q) 处叠加 BFV 明文提升 round(Q/t · value)。
// 调用方传入的 value_mod_t 已含 W^{-1} mod t 预缩放，因此 ExpandBFV 展开时
// 每个槽位被乘 W = 2^{h_q} 后，正好抵消为 Enc(value·Δ)——树查询里 value
// 取 1，展开后 α 槽位精确回到 Enc(1)。
void add_bfv_query_constant(RlweCt &ct, const PirParams &scheme,
                            size_t logical_coeff, size_t h_q,
                            uint64_t value_mod_t) {
  // 取出环维度 N、RNS limb 数 K、各 limb 模数 qs 与明文模数 t。
  constexpr size_t N = DBConsts::PolyDegree;
  const size_t K = scheme.K();
  const auto &qs = scheme.get_rns_mods();
  const uint64_t t = scheme.get_plain_mod();
  // 守卫 1：2^h_q 必须放得进环，否则位反转下标会越界（见匿名命名空间）。
  require_capacity_in_ring(h_q);
  // 守卫 2：只接受系数形式、完整 K 个 limb 的密文——NTT 形式下"往某个
  // 系数加常数"没有意义，limb 数不符则说明密文形状根本不对。
  if (ct.ntt_form || ct.c0.size() != K * N) {
    throw std::invalid_argument(
        "add_bfv_query_constant needs a coefficient-form full-q ciphertext");
  }
  // 守卫 3：逻辑槽位必须落在展开容量 2^h_q 内，否则展开树根本走不到它。
  if (logical_coeff >= (size_t{1} << h_q)) {
    throw std::invalid_argument("BFV query constant is outside the capacity");
  }
  // ExpandBFV 的堆序展开以位反转序回收叶子，故实际写入位置取
  // BitRev(logical_coeff, h_q)，让展开叶 j 恰好对应逻辑槽位 j。
  const size_t reversed = utils::bit_reverse(logical_coeff, h_q);

  // 与 fast_generate_query 相同的完整 Q 明文提升：把 Δ·value（Δ = Q/t 的
  // 舍入形式）加到消息相关分量。K=1 直接对单模数做 round(q0·value/t)；
  // K=2 先在合成模数 Q = q0*q1 下算出一个一致的多精度提升值，再分别约减到
  // 每个 limb——保证两个 limb 承载的是同一个 CRT 值，而不是各自独立舍入。
  if (K == 1) {
    // 单 limb：scaled = round(Q·value / t) mod Q，直接加到该系数上。
    const uint64_t Q = qs[0];
    const uint64_t scaled =
        utils::round_div_u128((uint128_t)Q * value_mod_t, t) % Q;
    ct.c0[reversed] = (ct.c0[reversed] + scaled) % Q;
  } else if (K == 2) {
    // 双 limb：把 round(Q·value/t) 拆成 Delta·value + round(rem·value/t)，
    // 其中 Q = Delta·t + rem。这样 128 位内即可精确算出多精度提升值
    // scaled_mp，避免直接算 Q·value（可能溢出 128 位）。
    const uint128_t Q = static_cast<uint128_t>(qs[0]) * qs[1];
    const uint128_t Delta = Q / t;
    const uint64_t rem = static_cast<uint64_t>(Q - Delta * t);
    const uint64_t rem_value_round = static_cast<uint64_t>(
        (static_cast<uint128_t>(rem) * value_mod_t + (t >> 1)) / t);
    const uint128_t scaled_mp = Delta * value_mod_t + rem_value_round;
    // 把同一个 scaled_mp 分别 mod q_k 后叠加到每个 limb 的对应系数上；
    // limb k 的系数存储区间是 [k*N, (k+1)*N)。
    for (size_t k = 0; k < K; ++k) {
      const uint64_t scaled_k = static_cast<uint64_t>(scaled_mp % qs[k]);
      const size_t idx = k * N + reversed;
      ct.c0[idx] = (ct.c0[idx] + scaled_k) % qs[k];
    }
  } else {
    // K >= 3 需要真正的多精度算术，当前方案配置不会出现，明确拒绝。
    throw std::invalid_argument("BFV query lift supports only K <= 2");
  }
}

// β/γ 常数写入（客户端打包的第二种尺度）：向 c0 的系数
// BitRev(logical_coeff, h_q) 处叠加一个 RLWE*（RLWE' gadget 行）风格常数。
// 与 α 路径的本质区别：**没有 Δ 因子**——gadget 行的语义是"密文相位上
// 直接携带 G[k]·bit"，而不是 BFV 明文。调用方传入的每 limb 值已含
// W^{-1} mod q_k 预缩放并乘好 gadget 幂 G[k]，展开乘回 W 后该行的相位
// 恰为 G[k]·bit，正好构成 RLWE' 的第 k 行，供 query_to_gsw 组装 RGSW。
void add_rlwe_star_constant(RlweCt &ct, const PirParams &scheme,
                            size_t logical_coeff, size_t h_q,
                            std::span<const uint64_t> value_per_limb) {
  // 取出环维度 N、limb 数 K 与各 limb 模数。
  constexpr size_t N = DBConsts::PolyDegree;
  const size_t K = scheme.K();
  const auto &qs = scheme.get_rns_mods();
  // 守卫 1：2^h_q 必须放得进环（同 add_bfv_query_constant）。
  require_capacity_in_ring(h_q);
  // 守卫 2：只接受系数形式、完整 K 个 limb 的密文。
  if (ct.ntt_form || ct.c0.size() != K * N) {
    throw std::invalid_argument(
        "add_rlwe_star_constant needs a coefficient-form full-q ciphertext");
  }
  // 守卫 3：RLWE* 常数按 RNS 语义必须每个 limb 恰好一个值，缺一个 limb
  // 就意味着调用方混淆了 mod-t 与逐 limb mod-q_k 两种域。
  if (value_per_limb.size() != K) {
    throw std::invalid_argument(
        "add_rlwe_star_constant needs one value per RNS limb");
  }
  // 守卫 4：逻辑槽位必须在展开容量之内。
  if (logical_coeff >= (size_t{1} << h_q)) {
    throw std::invalid_argument("RLWE* constant is outside the capacity");
  }
  // 同样按 ExpandBFV 的位反转序确定实际写入系数。
  const size_t reversed = utils::bit_reverse(logical_coeff, h_q);

  // 无 Δ 提升：每个 limb 的原始值直接落进消息相关分量。本 helper 独占
  // (c0, c1) = (-as + e + Delta*m, a) 的分量约定——改的是 c0；树层调用方
  // 对这一约定保持不可知，将来若换分量布局只需改这里。
  for (size_t k = 0; k < K; ++k) {
    const size_t idx = k * N + reversed;
    ct.c0[idx] = (ct.c0[idx] + value_per_limb[k] % qs[k]) % qs[k];
  }
}

// Algorithm 3 QueryGen：客户端为目标叶 leaf 打包一条树查询。
// 流水线位置：这是客户端唯一的查询构造入口，产物经网络发给服务端后由
// unpack_tree_query 展开。数学骨架（§8.5）：
//   1) 叶索引一次性分解为坐标 (α, β 位串, γ 位串)——全部 L+1 层共用；
//   2) 以零加密为底（提供 (a, e) 随机性与安全性）；
//   3) 明文侧叠加 w 个常数：α 槽位一个 BFV 提升 + 每个"1"选择位 ell 行
//      gadget 常数。所有常数都预乘 W^{-1}，以抵消 ExpandBFV 的乘 W 效应。
// 输出密文之外不泄露任何逐层信息：0 选择位与未选 α 槽位保持零加密。
RlweCt make_tree_query(PirClient &client, const PirParams &scheme,
                       const TreePirParams &tree, size_t leaf) {
  // 前置守卫：树参数必须绑定当前方案，两侧尺度才一致。
  require_scheme_binding(tree, scheme);
  // 叶索引只分解一次：γ = ⌊leaf/P⌋、α = ⌊(leaf mod P)/B⌋、
  // β = (leaf mod P) mod B（Lemma 1/3/4 保证各层坐标都是其前缀/截断）。
  const ClientCoordinates coords = client_index(leaf, tree);

  // 底座：一条新鲜的零加密。每次调用都从客户端 RNG 抽取新的 (a, e)，
  // 保证同一 leaf 的两次查询密文不同（语义安全所必需）。
  RlweCt query = client.fresh_zero_ct();

  // α one-hot：在逻辑槽位 α（实际系数 BitRev(α, h_q)）写入 BFV 值
  // W^{-1} mod t 的 Δ 提升。展开把每个槽位乘 W = 2^{h_q}，于是
  // W·W^{-1} = 1 (mod t)，展开叶 α 精确回到 Enc(1)，其余 N0-1 个 α 槽位
  // 保持 Enc(0)——这就是首维选择向量 A^(0)。
  const uint64_t t = scheme.get_plain_mod();
  uint64_t w_inv_t = 0;
  // W = 2^{h_q} 与奇素数 t 互素，正常配置下必可逆；求逆失败说明参数损坏。
  if (!utils::try_invert_uint_mod(tree.W, t, w_inv_t)) {
    throw std::invalid_argument("W is not invertible modulo t");
  }
  add_bfv_query_constant(query, scheme, coords.alpha, tree.h_q, w_inv_t);

  // β/γ 部分的公共材料：每个 RNS limb 下的 W^{-1} mod q_k（gadget 行走的
  // 是逐 limb 的 mod-q_k 域，与上面的 mod-t 域互不相通），以及方案共享的
  // MSB-first 数据 gadget 表 G（gadget[k][row] = 第 row 行在 limb k 下的
  // gadget 基幂）。
  const auto &qs = scheme.get_rns_mods();
  const size_t K = scheme.K();
  std::vector<uint64_t> w_inv_q(K);
  for (size_t k = 0; k < K; ++k) {
    // W = 2 的幂与奇素数 q_k 互素，正常配置下必可逆。
    if (!utils::try_invert_uint_mod(tree.W, qs[k], w_inv_q[k])) {
      throw std::invalid_argument("W is not invertible modulo a RNS limb");
    }
  }
  // ell 行 gadget 与 query_to_gsw 使用同一张表（同 ell、同基宽），
  // 保证服务端补全时行语义严格对得上。
  const size_t ell = scheme.get_l();
  const std::vector<std::vector<uint64_t>> gadget = utils::gsw_gadget(
      ell, scheme.get_base_log2(),
      std::vector<uint64_t>(qs.begin(), qs.end()));

  // 写入一个"1"选择位的整组 ell 行：组 group_index 占用逻辑槽位
  // [N0 + group_index*ell, N0 + (group_index+1)*ell)。第 row 行在 limb k
  // 下写入 (W^{-1} mod q_k)·G[k][row]，展开乘回 W 后相位恰为 G[k][row]，
  // 即"gadget 幂 × bit(=1)"的 RLWE 加密——RLWE' 的一行。
  std::vector<uint64_t> value_per_limb(K);
  const auto append_selector_rows = [&](size_t group_index) {
    for (size_t row = 0; row < ell; ++row) {
      const size_t logical = tree.N0 + group_index * ell + row;
      for (size_t k = 0; k < K; ++k) {
        value_per_limb[k] = static_cast<uint64_t>(
            (uint128_t)gadget[k][row] * w_inv_q[k] % qs[k]);
      }
      add_rlwe_star_constant(query, scheme, logical, tree.h_q,
                             value_per_limb);
    }
  };

  // 选择位为 0 的组什么都不写——底座本来就是零加密，展开后整组行都是
  // Enc(0)，恰是"gadget 幂 × bit(=0)"；为 1 的组写入缩放后的 gadget 行。
  // 布局顺序：β 组占 [N0, N0 + b*ell)，γ 组紧随其后（LSB-first 位序，
  // beta_bits_le[u] 即 β 的第 u 个二进制位）。
  for (size_t u = 0; u < tree.b; ++u) {
    if (coords.beta_bits_le[u] == 1) append_selector_rows(u);
  }
  for (size_t v = 0; v < tree.r; ++v) {
    if (coords.gamma_bits_le[v] == 1) append_selector_rows(tree.b + v);
  }
  return query;
}

// Algorithm "QueryUnpack"（服务端，§9）：make_tree_query 的逆过程。
// 流水线位置：服务端收到打包密文后的第一步，产物 ExpandedTreeQuery
// （N0 条 α BFV 密文 + b 个 β / r 个 γ RGSW selector）供后续首维选择、
// CMux 折叠与旋转/投影各阶段消费。两个同态阶段：
//   9.1 ExpandBFV 系数展开 → w 条 RLWE 密文；
//   9.2 query_to_gsw 补全 → 每个 ell 行组变成一个完整 RGSW。
ExpandedTreeQuery unpack_tree_query(PirServer &server,
                                    const PirParams &scheme,
                                    const TreePirParams &tree,
                                    size_t client_id, RlweCt &query) {
  // 前置守卫：与打包侧相同的方案绑定检查，两侧尺度一致才谈得上解包。
  require_scheme_binding(tree, scheme);
  // 形状守卫：server 必须构造自 tree_query_expansion_params(tree, scheme)
  // ——首维 N0、维度数 1 + b + r、展开高度 h_q 三者以及底层方案参数都要
  // 对上。任何一处不符（例如 h_q 差 1）都会让展开尺度静默错位，因此在做
  // 任何同态运算之前直接拒绝。
  const PirParams &view = server.get_params();
  if (view.get_fst_dim_sz() != tree.N0 ||
      view.get_num_dims() != 1 + tree.b + tree.r ||
      view.get_expan_height() != tree.h_q ||
      !scheme.scheme_compatible(view)) {
    throw std::invalid_argument(
        "unpack_tree_query server was not built on this tree's query shape");
  }

  // 阶段 9.1 展开：带 useful-leaf 剪枝的堆序 ExpandBFV。位反转写入 +
  // 堆序回收相互抵消，返回的 w 条密文正好是**逻辑序**——先 N0 条 α
  // one-hot，随后每个 selector 一组 ell 行。
  std::vector<RlweCt> expanded = server.expand_query(client_id, query);
  // 守卫：展开必须恰好回收 w 片有用叶，数目不符说明剪枝或形状出了问题。
  if (expanded.size() != tree.w) {
    throw std::runtime_error(
        "unpack_tree_query expansion returned an unexpected leaf count");
  }

  // 阶段 9.2 补全：共享的服务端补全通道（complete_selectors，内部即
  // query_to_gsw）自己按 ell 切出 b + r 个行组，并用客户端注册的 RGSW(s)
  // 密钥把每组 RLWE' 行补全成完整 RGSW。flat 生产路径 make_query 走的是
  // 同一份实现，行布局约定因此单源化，不可能在两条路径间漂移；树层在此
  // 只负责把结果按坐标拆回 β / γ。
  std::vector<GSWCt> selectors =
      server.complete_selectors(client_id, expanded);
  // 守卫：selector 数必须等于 b + r，否则切组与树参数不一致。
  if (selectors.size() != tree.b + tree.r) {
    throw std::runtime_error(
        "unpack_tree_query completion returned an unexpected selector count");
  }

  // 组装输出：α 取展开结果的前 N0 条（保持 BFV 形态）；selector 按打包
  // 布局切分——前 b 个是 β、后 r 个是 γ。全部走 move，避免拷贝大密文。
  ExpandedTreeQuery result;
  result.alpha.assign(std::make_move_iterator(expanded.begin()),
                      std::make_move_iterator(expanded.begin() + tree.N0));
  result.beta_selectors.assign(
      std::make_move_iterator(selectors.begin()),
      std::make_move_iterator(selectors.begin() + tree.b));
  result.gamma_selectors.assign(
      std::make_move_iterator(selectors.begin() + tree.b),
      std::make_move_iterator(selectors.end()));
  return result;
}
