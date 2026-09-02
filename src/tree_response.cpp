#include "tree_response.h"

#include "tree_project.h"
#include "tree_rotate.h"
#include "utils.h"

#include <stdexcept>
#include <string>

// ----------------------------------------------------------------------------
// path_chunk_bounds：路径槽位 -> 响应密文的公开分组算术（§21.8）。
// 位置与作用：打包与提取两端共用的"放置合同"——把 L+1 个层槽位按每密文容量
// capacity（生产中 = rho = n/g）连续切分。服务端据此决定发多少条响应密文、
// 每条装哪些层；客户端用完全相同的算术还原分组，两端因此天然一致。
// 输入：level_count = 路径节点数 L+1；capacity = 每条密文的槽位容量 rho。
// 输出：每条密文的 (first_level, size)，first_level 单调递增且首尾相接，
//       size <= capacity——保证槽位既不重叠也不回绕（层在 chunk 内的偏移
//       z < capacity <= rho，X^z 移位不会越过一个 mod-rho 周期）。
// 只依赖公开参数，不接触任何密文，故可用极小容量单元测试其正确性。
// ----------------------------------------------------------------------------
std::vector<std::pair<size_t, size_t>> path_chunk_bounds(size_t level_count,
                                                         size_t capacity) {
  // 守卫：空路径或零容量会让下方循环退化（除以零语义的分组无意义），直接拒绝。
  if (level_count == 0 || capacity == 0) {
    throw std::invalid_argument(
        "tree_response: chunk bounds need positive levels and capacity");
  }
  std::vector<std::pair<size_t, size_t>> bounds;
  // 每次前进 capacity 个槽位开一条新密文；最后一条可能不满，
  // 尺寸取 min(capacity, 剩余层数)，即 ceil(level_count/capacity) 条。
  for (size_t first = 0; first < level_count; first += capacity) {
    bounds.emplace_back(first,
                        std::min(capacity, level_count - first));
  }
  return bounds;
}

// ----------------------------------------------------------------------------
// answer_path_mvp（Algorithm 7 AnswerPathMVP）：服务端的整条路径答复主流程。
// 位置与作用：Binary Tree PIR 在线阶段的核心——查询展开（unpack_tree_query）
// 之后、客户端提取（extract_path_*_mvp）之前的全部同态计算都在这里。
// 对每层 l = 0..L 执行四步：
//   (1) SelectLevel：α 首维 matmul + β 维 CMux fold，得到加密的
//       C_l = D_l[p_l]（目标记录仍在其打包位置 u_l 上）；
//   (2) PrivateRotateLevel：乘加密的 X^{-γ_l}，把目标记录的 g 个 chunk 一次性
//       对齐到跨步格 {j * rho}（私有对齐，γ_l 对服务端保密）；
//   (3) ProjectRecord：project_keep_stride 深度 min(r, l) 的迹式投影，把跨步格
//       以外的所有系数清零（公开 stride 过滤，必须发生在私有对齐之后，见头文件
//       负结果 3）；
//   (4) 乘公开单项式 X^z 把该层移到其 chunk 内槽位 z 并累加进响应密文。
// 每条响应密文在全部同态运算结束后做 Milestone-5 同环模数切换（压响应体积）。
// 输入：db = 预处理树（每层一个 NTT 或 m32 视图 + 公开 LevelPlan）；query = 展开后
//   的 α 密文与 β/γ RGSW 选择子；server 提供 CMux 与模数切换并持有客户端会话密钥。
// 输出：TreePathResponse——ceil((L+1)/rho) 条密文 + 公开放置图 + small_q 标志。
// 安全不变量：所有分支与循环次数只依赖公开的 plan/tree 参数；私密信息只通过
// 密文（pyramid、选择子）参与运算。
// ----------------------------------------------------------------------------
TreePathResponse answer_path_mvp(const PreprocessedTree &db,
                                 ExpandedTreeQuery &query, PirServer &server,
                                 size_t client_id, const TreePirParams &tree,
                                 const PirParams &scheme) {
  // 预处理端二选一：复合模数配置下只建 m32 视图（ntt 留空），否则只建 ntt 视图。
  // 以 m32 是否非空判定本次查询走哪条首维内核。
  const bool use_m32 = !db.m32.empty();
  // 守卫：每层必须恰有一个数据库视图和一个公开 plan，否则说明预处理树与
  // tree 参数（L）不匹配，继续算只会越界或答错层。
  if ((use_m32 ? db.m32.size() : db.ntt.size()) != tree.L + 1 ||
      db.plans.size() != tree.L + 1) {
    throw std::invalid_argument(
        "tree_response: one database view and one plan per level are "
        "required");
  }
  // 取该客户端会话的 BV Galois 密钥：投影需要 η_0..η_{r-1} 替换自同构，
  // create_session_keys(log2 n) 保证覆盖 max(h_q, r)（§5.1）。
  const bvks::BvGaloisKeys &galois_keys =
      server.client_session_keys(client_id)->bv_galois_keys;

  // α 金字塔（§10）：pyramid[c][j] 加密 [floor(α / 2^c) == j]，由展开后的 one-hot
  // α 密文只用密文加法逐级粗化而成——每个查询建一次，供所有层共享（层 l 用
  // 粗化级 c 取决于该层 plan）。随后一次性抬到 NTT 域（Milestone 6），使每层的
  // 首维运算都跑在预先变换好的表示上（逐点乘 + 每候选一次逆变换）；复合模数
  // 配置再把 NTT 形式按内核布局拆成两个 32-bit CRT limb。
  TIME_START(TREE_PYRAMID_TIME);
  const AlphaPyramid pyramid =
      build_alpha_pyramid(query.alpha, tree, scheme);
  const AlphaPyramid pyramid_ntt = pyramid_to_ntt(pyramid, scheme);
  AlphaPyramidM32 pyramid_m32;
  if (use_m32) {
    pyramid_m32 = pyramid_to_m32(pyramid_ntt, scheme);
  }
  TIME_END(TREE_PYRAMID_TIME);

  // 初始化响应骨架：L+1 个路径槽位、全零放置图（下方打包时逐层填入），
  // 并按容量 rho 算出密文分组，好预留密文数组空间。
  TreePathResponse response;
  response.level_count = tree.L + 1;
  response.level_offsets.assign(response.level_count, 0);
  const auto bounds = path_chunk_bounds(response.level_count, tree.rho);
  response.chunks.reserve(bounds.size());

  // 每层的"选择 + 私有旋转"子流程（步骤 1-2），抽成 lambda 以示与打包解耦：
  // 两个打包器（本函数与 answer_path_compressed）共享同一套逐层语义。
  const auto select_and_rotate = [&](size_t level) {
    // 步骤 (1) SelectLevel（Algorithm 4）：得到加密的整条打包明文 D_l[p_l]。
    // 内部按 plan 分三种互斥情形（Single / CoarsenedAlpha / AlphaBeta）：
    // 首维用 α 金字塔做 matmul（m32 走 32x32->64 延迟规约 CRT 内核，ntt 走
    // u64 逐点乘），得到 2^d 个候选后再用 β RGSW 选择子做 MSB-first 的
    // CMux fold（fold_beta_dimension）折半到 1 个。两内核输出比特级一致。
    RlweCt selected =
        use_m32 ? select_level_m32(
                      db.m32[level], db.plans[level], pyramid_m32,
                      std::span<GSWCt>(query.beta_selectors), server, tree,
                      scheme)
                : select_level_ntt(
                      db.ntt[level], db.plans[level], pyramid_ntt,
                      std::span<GSWCt>(query.beta_selectors), server, tree,
                      scheme);
    // 步骤 (2) PrivateRotateLevel：用 γ RGSW 选择子经 CMux 组合出加密的
    // X^{-γ_l} 并乘上去——把目标记录从其打包位置 u_l 平移到位置 0，
    // g 个 chunk 因跨步布局被同一次旋转同时对齐到 {j * rho}（§3.4 收益 1）。
    TIME_START(TREE_ROTATE_TIME);
    RlweCt rotated = private_rotate_level(
        std::move(selected), db.plans[level],
        std::span<GSWCt>(query.gamma_selectors), server, scheme);
    TIME_END(TREE_ROTATE_TIME);
    return rotated;
  };

  // 顺序打包器（Algorithm 7 第 4-6 行）：逐 chunk、逐槽位处理。健全性来自
  // 投影后的密文在跨步格 {j * rho} 之外全为零：乘 X^z（z < rho）后载荷落在
  // {z + j * rho}，不同 z 占不同 mod-rho 残差 => 相加不重叠；z < rho 也保证
  // 不触发 X^n = -1 的负循环回绕（头文件负结果说明了为何不能跨层融合摊销）。
  for (const auto &[first_level, size] : bounds) {
    RlweCt packed;
    for (size_t z = 0; z < size; ++z) {
      // 本槽位对应的全局层号：chunk 起始层 + chunk 内偏移。
      const size_t level = first_level + z;
      // 步骤 (3) ProjectRecord：迹式投影只保留跨步格 {j * rho} 上的系数。
      // 深度取 plan 里的 min(r, level)：层 l < r 时旋转后非目标记录都落在
      // 非零残差 u - γ_l (mod 2^l) 上，深度 l 已足够杀光（§3.3 技巧二）；
      // 投影内部的 2^{-d} 预缩放与 d 轮 T + Subs(T, η) 逐轮翻倍累积出的
      // 2^d 精确相消；噪声经历同一投影，不被 2^{-d} mod q 放大（§3.3 技巧一）。
      RlweCt rotated = select_and_rotate(level);
      TIME_START(TREE_PROJECT_TIME);
      RlweCt projected = project_keep_stride(
          std::move(rotated), db.plans[level].projection_depth,
          galois_keys, scheme);
      TIME_END(TREE_PROJECT_TIME);
      // 记录公开放置图：顺序打包器把层放在其 chunk 内位置 z（提取端按
      // level_offsets[level] + j * rho 读回，见 §4.2）。
      response.level_offsets[level] = z;
      if (z == 0) {
        // 槽位 0 无需移位（X^0 = 1），直接作为累加器的初值。
        packed = std::move(projected);
      } else {
        // 步骤 (4)：乘公开单项式 X^z 把该层载荷移到 {z + j * rho}，
        // 然后加进累加器——由上述残差论证，加法是无碰撞的直和。
        TIME_START(TREE_PACK_TIME);
        const RlweCt shifted = mul_x_pow(projected, z, scheme);
        tree_ct_add_inplace(packed, shifted, scheme);
        TIME_END(TREE_PACK_TIME);
      }
    }
    // Milestone 5 收尾：本 chunk 的全部同态运算已完成，此刻才允许做同环模数
    // 切换（全 q 58-bit -> 22-bit small q 的居中重缩放 x -> round(x*q'/q)）。
    // 必须最后做：提前切换会损失噪声余量，且与首维 matmul / 外积 / Galois
    // 密钥的参数约定冲突（§4.1，与生产 make_query 同一纪律）。返回值指示
    // 配置是否定义了更窄的 small q（未定义则密文原样保留在全 q）。
    TIME_START(TREE_SWITCH_TIME);
    response.small_q = server.switch_response_to_small_q(packed);
    TIME_END(TREE_SWITCH_TIME);
    response.chunks.push_back(std::move(packed));
  }
  return response;
}

// ----------------------------------------------------------------------------
// answer_path_compressed（Milestone-7 路径）：与 answer_path_mvp 相同的逐层
// select/rotate/project 流水线，但打包与收尾改为环切换压缩形态：
//   * 层 z 放在偏移 2z 而非 z（§23.4 偶对齐）：全部载荷落在偶子格
//     {2z + j * rho}（rho 为偶数，j * rho 也是偶数）。d = 2 环切换基于奇偶分解
//     f(X) = f_e(X^2) + X * f_o(X^2)，只保留偶部——载荷因此被压缩映射完整保留，
//     奇系数只含噪声，丢弃无害（实测压缩后噪声反而略优）。
//   * 跳过大环 small_q 切换，把仍在全 q 的打包密文交给 compress_path_response：
//     先在全 q 下 gadget-KS 到小环密钥 s2，再居中降模到 small q（顺序纪律：
//     KS 噪声 ~2^{39} 必须先被 2^{-36} 的降模缩放压掉，若先降模则直接越界）。
// 输入较 MVP 多一个 keys：客户端注册的 d = 2 环切换密钥（KSK_e / KSK_o）。
// 输出：CompressedPathResponse——单条 R_{n2}（n2 = n/2）小环密文，
// 响应体积折半（11,264 B -> 5,632 B）。
// ----------------------------------------------------------------------------
CompressedPathResponse answer_path_compressed(
    const PreprocessedTree &db, ExpandedTreeQuery &query, PirServer &server,
    size_t client_id, const TreePirParams &tree, const PirParams &scheme,
    const TreeRingSwitchKeys &keys) {
  // 与 answer_path_mvp 相同的视图选择与形状守卫：每层一个视图一个 plan。
  const bool use_m32 = !db.m32.empty();
  if ((use_m32 ? db.m32.size() : db.ntt.size()) != tree.L + 1 ||
      db.plans.size() != tree.L + 1) {
    throw std::invalid_argument(
        "tree_response: one database view and one plan per level are "
        "required");
  }
  // 守卫：偶对齐把最大偏移推到 2L，必须 2L < rho 才能保证所有层仍落在
  // 同一条密文的不同 mod-rho 残差上（即整条路径压进单 chunk 且不混叠）。
  if (2 * tree.L >= tree.rho) {
    throw std::invalid_argument(
        "tree_response: even-aligned packing needs 2L < rho");
  }
  // 投影所需的 BV Galois 密钥（η 替换自同构），同 MVP。
  const bvks::BvGaloisKeys &galois_keys =
      server.client_session_keys(client_id)->bv_galois_keys;

  // 每查询一次的 α 金字塔构建 + NTT 抬升（+ 复合模数配置的 CRT limb 拆分），
  // 与 answer_path_mvp 完全一致，见彼处注释。
  TIME_START(TREE_PYRAMID_TIME);
  const AlphaPyramid pyramid =
      build_alpha_pyramid(query.alpha, tree, scheme);
  const AlphaPyramid pyramid_ntt = pyramid_to_ntt(pyramid, scheme);
  AlphaPyramidM32 pyramid_m32;
  if (use_m32) {
    pyramid_m32 = pyramid_to_m32(pyramid_ntt, scheme);
  }
  TIME_END(TREE_PYRAMID_TIME);

  // 与 answer_path_mvp 相同的逐层流水线，差异仅两点：偏移取 2*level（偶对齐），
  // 且始终单 chunk、全程保持全 q（为随后的环切换保留噪声余量）。
  std::vector<size_t> offsets(tree.L + 1, 0);
  RlweCt packed;
  for (size_t level = 0; level <= tree.L; ++level) {
    // 步骤 (1) SelectLevel：α 首维 matmul + β 维 CMux fold，
    // 得到加密的 D_l[p_l]（详见 answer_path_mvp 内的注释）。
    RlweCt selected =
        use_m32 ? select_level_m32(
                      db.m32[level], db.plans[level], pyramid_m32,
                      std::span<GSWCt>(query.beta_selectors), server, tree,
                      scheme)
                : select_level_ntt(
                      db.ntt[level], db.plans[level], pyramid_ntt,
                      std::span<GSWCt>(query.beta_selectors), server, tree,
                      scheme);
    // 步骤 (2) PrivateRotateLevel：乘加密的 X^{-γ_l}，
    // 一次旋转对齐目标记录的全部 g 个 chunk 到跨步格 {j * rho}。
    TIME_START(TREE_ROTATE_TIME);
    RlweCt rotated = private_rotate_level(
        std::move(selected), db.plans[level],
        std::span<GSWCt>(query.gamma_selectors), server, scheme);
    TIME_END(TREE_ROTATE_TIME);
    // 步骤 (3) ProjectRecord：深度 min(r, level) 的迹式投影，
    // 清零跨步格以外的一切系数。
    TIME_START(TREE_PROJECT_TIME);
    RlweCt projected = project_keep_stride(
        std::move(rotated), db.plans[level].projection_depth, galois_keys,
        scheme);
    TIME_END(TREE_PROJECT_TIME);
    // 步骤 (4) 偶对齐放置：记录公开偏移 2*level 并乘 X^{2*level} 移位后累加。
    // 载荷因此全部落在偶系数 {2*level + j * rho} 上；2L < rho 保证各层残差
    // 互异、加法无碰撞（level 0 即偏移 0，直接充当累加器初值）。
    offsets[level] = 2 * level;
    if (level == 0) {
      packed = std::move(projected);
    } else {
      TIME_START(TREE_PACK_TIME);
      const RlweCt shifted = mul_x_pow(projected, 2 * level, scheme);
      tree_ct_add_inplace(packed, shifted, scheme);
      TIME_END(TREE_PACK_TIME);
    }
  }

  // 收尾交给 M7 压缩：packed 仍在全 q。compress_path_response 先做偶部提取 +
  // 双 KSK gadget 密钥切换（大密钥的偶/奇小环分量 s_e、s_o 切到独立三值 s2），
  // 再居中降模到 small q；big_offsets（全为偶数）除以 2 变成小环放置图。
  TIME_START(TREE_SWITCH_TIME);
  CompressedPathResponse compressed =
      compress_path_response(packed, offsets, tree.L + 1, keys, scheme);
  TIME_END(TREE_SWITCH_TIME);
  return compressed;
}

// ----------------------------------------------------------------------------
// extract_path_chunks_mvp（Algorithm 8 ExtractPathMVP，chunks 版）：客户端提取。
// 位置与作用：流水线的最后一步——把 answer_path_mvp 的响应解密并按公开放置图
// 读出整条路径，每层返回该节点的 g 个 chunk 值（Z_t 中的明文系数）。
// 输入：response = 服务端响应；client 持有解密密钥；tree 提供 rho/g 与分组容量。
// 输出：path[level][j] = 第 level 层节点的第 j 个 chunk，根在前。
// 关键点：寻址完全由公开数据决定（bounds 分组 + response.level_offsets +
// 跨步 j * rho），提取端对打包策略零假设——换放置方案无需改这里。
// ----------------------------------------------------------------------------
std::vector<std::vector<uint64_t>> extract_path_chunks_mvp(
    const TreePathResponse &response, PirClient &client,
    const TreePirParams &tree) {
  // 用与服务端完全相同的公开算术重建"层 -> 密文"分组：两端各自计算同一个
  // 确定性函数，天然一致，无需在响应里传输分组本身。
  const auto bounds = path_chunk_bounds(response.level_count, tree.rho);
  // 守卫：响应里的密文条数必须与分组数吻合，否则说明响应与 tree 参数不匹配
  // （比如按不同的 rho 或 L 打包），继续读只会得到错位的垃圾值。
  if (response.chunks.size() != bounds.size()) {
    throw std::invalid_argument(
        "tree_response: chunk count does not match the level partition");
  }
  // 守卫：放置图必须覆盖每一层——提取端唯一的寻址依据就是它。
  if (response.level_offsets.size() != response.level_count) {
    throw std::invalid_argument(
        "tree_response: response is missing its level offset map");
  }
  std::vector<std::vector<uint64_t>> path;
  path.reserve(response.level_count);
  for (size_t c = 0; c < bounds.size(); ++c) {
    // 每条响应密文解密一次得到整张明文多项式。M5 切换执行过时必须走
    // small-q 解密（decrypt_mod_q 按切换后的 22-bit 模数与 Δ' 解码），
    // 否则用常规全 q 解密——两者的 Δ 不同，走错会全盘解码失败。
    const RlwePt pt = response.small_q
                          ? client.decrypt_mod_q(response.chunks[c])
                          : client.decrypt_ct(response.chunks[c]);
    // 按分组顺序（根到叶）逐槽位读出：层 = chunk 起始层 + 槽位 z。
    for (size_t z = 0; z < bounds[c].second; ++z) {
      // 该层的公开槽位偏移（顺序打包为 z；放置图使这里与打包策略解耦）。
      const size_t offset = response.level_offsets[bounds[c].first + z];
      // 跨步读数：第 j 个 chunk 在系数 offset + j * rho（§3.4 跨步布局，
      // 与打包不变量"载荷仅在 {offset + j * rho}"一一对应）。
      std::vector<uint64_t> chunks(tree.g);
      for (size_t j = 0; j < tree.g; ++j) {
        chunks[j] = pt.data[offset + j * tree.rho];
      }
      path.push_back(std::move(chunks));
    }
  }
  return path;
}

// ----------------------------------------------------------------------------
// extract_path_mvp（flat 版）：g = 1 时的标量便捷视图——每层恰好一个 chunk，
// 返回 vector<uint64_t> 而非每层一个单元素向量。为避免两份提取逻辑漂移，
// 它不自己解密，而是委托 chunks 版后压平。
// ----------------------------------------------------------------------------
std::vector<uint64_t> extract_path_mvp(const TreePathResponse &response,
                                       PirClient &client,
                                       const TreePirParams &tree) {
  // 守卫：g > 1 时每层有多个 chunk，压平会静默丢数据，显式要求调用方改用
  // extract_path_chunks_mvp。
  if (tree.g != 1) {
    throw std::invalid_argument(
        "tree_response: flat extraction requires g = 1; use "
        "extract_path_chunks_mvp");
  }
  // 复用 chunks 版做全部解密与寻址（单一事实来源）。
  std::vector<std::vector<uint64_t>> chunked =
      extract_path_chunks_mvp(response, client, tree);
  // g == 1 时每层向量恰含一个元素，取 front() 压平成标量路径。
  std::vector<uint64_t> path;
  path.reserve(chunked.size());
  for (const std::vector<uint64_t> &level : chunked) {
    path.push_back(level.front());
  }
  return path;
}
