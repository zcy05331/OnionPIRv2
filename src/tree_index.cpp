#include "tree_index.h"

#include <bit>
#include <limits>
#include <numeric>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

// 统一的参数校验守卫：条件不成立立即抛 std::invalid_argument，并带
// "TreePirParams:" 前缀方便上层归因。硬失败而非静默修正——对应
// "无 padding 回退"的设计纪律（蓝图 §21.1）。
void require(bool condition, const char *message) {
  if (!condition) {
    throw std::invalid_argument(std::string("TreePirParams: ") + message);
  }
}

// 精确 log₂：要求 value 恰为 2 的幂，否则抛异常。用 bit_width - 1 做整数
// 对数，避免浮点 log2 的精度陷阱；同时兼任"必须是 2 的幂"的校验器。
size_t exact_log2(size_t value, const char *name) {
  // has_single_bit 即 popcount == 1，是 2 的幂的充要条件（value = 0 也被拒）。
  if (!std::has_single_bit(value)) {
    throw std::invalid_argument(std::string("TreePirParams: ") + name +
                                " must be a power of two");
  }
  // 2^k 的 bit_width 是 k+1，故减 1 得到 k。
  return static_cast<size_t>(std::bit_width(value)) - 1;
}

// 逐步防溢出地计算打包宽度 w = N₀ + ell_beta·b + ell_gamma·r
// （蓝图 §3.2 的 checked arithmetic，技巧手册 §5.3）。若放任 size_t 回绕，
// 例如 ell = 2^60、b + r = 16 时 ell·(b+r) 会 mod 2^64 归零，w 折回 N₀ 这个
// 小得离谱的假值，之后 w ≤ n、W ≤ n 等所有门全部静默通过，而真实的
// gadget 长度仍然巨大——测试里有专门的回绕用例守着这条路径。
size_t checked_packed_width(size_t N0, size_t ell_beta, size_t b,
                            size_t ell_gamma, size_t r) {
  // 检查乘法回绕：x != 0 时 x·y 溢出当且仅当 y > max/x。
  const auto mul = [](size_t x, size_t y) {
    if (x != 0 && y > std::numeric_limits<size_t>::max() / x) {
      throw std::invalid_argument("TreePirParams: packed width overflows");
    }
    return x * y;
  };
  // 检查加法回绕：x + y 溢出当且仅当 y > max - x。
  const auto add = [](size_t x, size_t y) {
    if (y > std::numeric_limits<size_t>::max() - x) {
      throw std::invalid_argument("TreePirParams: packed width overflows");
    }
    return x + y;
  };
  // 组合顺序与公式一致：先算两段 gadget 行数，再和 N₀ 相加，步步受检。
  return add(N0, add(mul(ell_beta, b), mul(ell_gamma, r)));
}

}  // namespace

// g = 1 便捷重载：标量 MVP（每节点一个 Z_t 标量），直接转发到一般 g 版本。
TreePirParams make_tree_pir_params(size_t L, size_t a, size_t n,
                                   size_t ell_beta, size_t ell_gamma,
                                   uint64_t t,
                                   std::vector<uint64_t> rns_moduli) {
  return make_tree_pir_params(L, a, n, /*g=*/1, ell_beta, ell_gamma, t,
                              std::move(rns_moduli));
}

// 参数工厂（一般 g 版本）：整个索引层的唯一构造入口。流程是
// "先守卫原始输入 → 按定义推派生量（每步防 UB）→ 整体复核"。
// 任何一步失败都抛异常，绝不返回被静默修正过的形状。
TreePirParams make_tree_pir_params(size_t L, size_t a, size_t n, size_t g,
                                   size_t ell_beta, size_t ell_gamma,
                                   uint64_t t,
                                   std::vector<uint64_t> rns_moduli) {
  // L、a 之后都要当移位量用（2^L、2^a）；size_t 位宽内不留满位余量会触发
  // 移位 UB（a ≥ 64 曾被 UBSan 实证），故先做范围守卫（技巧手册 §5.3）。
  require(L > 0 && L < std::numeric_limits<size_t>::digits - 1,
          "tree height is out of range");
  require(a < std::numeric_limits<size_t>::digits - 1,
          "first-dimension width is out of range");
  // n = 0 会让后面的整除与 log₂ 全部失义。
  require(n > 0, "ring degree must be positive");
  // g 必须整除 n 且留下 ρ = n/g ≥ 2：每明文至少两条记录才有 γ 位可言。
  require(g > 0 && n % g == 0 && n / g >= 2,
          "g must divide n with at least two records per plaintext");
  // gadget 分解长度为 0 意味着 β/γ 选择器根本无法编码。
  require(ell_beta > 0 && ell_gamma > 0, "gadget lengths must be positive");

  // 按定义逐个填入基础量：N = 2^L、ρ = n/g、N₀ = 2^a。
  TreePirParams params;
  params.L = L;
  params.N = size_t{1} << L;
  params.n = n;
  params.g = g;
  params.rho = n / g;
  // r = log₂ ρ；exact_log2 同时校验 ρ 是 2 的幂（n 非 2 的幂在这里被拒，
  // 例如 n = 6、g = 1 时 ρ = 6 直接抛异常）。
  params.r = exact_log2(params.rho, "records per plaintext");
  params.a = a;
  params.N0 = size_t{1} << a;

  // b = L - r - a 是 size_t 无符号减法，必须先确认 L ≥ r + a，
  // 否则下溢会把 b 回绕成巨大数并连带 B = 2^b 触发移位 UB。
  require(params.L >= params.r + params.a,
          "tree height is below r + a; no beta bits remain");
  params.b = params.L - params.r - params.a;
  // P = N/ρ：叶层明文数；B = 2^b：每个 α 分组内的明文数。
  params.P = params.N / params.rho;
  params.B = size_t{1} << params.b;

  // 打包查询布局：w 用防回绕版本计算（见 checked_packed_width 注释）。
  params.ell_beta = ell_beta;
  params.ell_gamma = ell_gamma;
  params.w = checked_packed_width(params.N0, ell_beta, params.b, ell_gamma,
                                  params.r);
  // 先卡 w ≤ n 再取 bit_ceil：w > 2^63 时 bit_ceil 不可表示（UB）；
  // 反正违反此界的形状也过不了后面的 W ≤ n 门，提前拦截即可。
  require(params.w <= params.n, "packed width exceeds the ring degree");
  // W = 2^{h_q} 是不小于 w 的最小 2 幂——展开树必须是满二叉树，
  // 容量只能取 2 的幂；h_q = log₂ W 即展开高度。
  params.W = std::bit_ceil(params.w);
  params.h_q = static_cast<size_t>(std::bit_width(params.W)) - 1;

  // 方案绑定：t / q 原样记录；MVP 阶段响应环与主环相同（n₂ = n、q₂ = q），
  // 环切换压缩（M7）会在别处替换这两个字段。注意 rns_moduli 先拷贝后 move。
  params.t = t;
  params.rns_moduli = rns_moduli;
  params.response_degree = n;                       // MVP：n₂ = n
  params.response_moduli = std::move(rns_moduli);   // MVP：q₂ = q

  // 构造完成后整体复核一遍：派生逻辑与校验器若有任何不一致会在此暴露。
  validate_tree_params(params);
  return params;
}

// 蓝图 §3.2 硬校验：在任何内存分配或密钥生成之前执行。参数是普通 struct，
// 测试会故意手工篡改字段（w+1、response_moduli 漂移等），所以这里不信任
// 工厂，把每个派生量都按定义重算一遍比对。
void validate_tree_params(const TreePirParams &params) {
  // 先范围检查指数 L / a：下面要做 1 << L、1 << a 的比较，指数越界时移位
  // 本身就是 UB，对手工构造的 struct 也必须先挡住。
  require(params.L > 0 && params.L < std::numeric_limits<size_t>::digits - 1,
          "tree height is out of range");
  require(params.a < std::numeric_limits<size_t>::digits - 1,
          "first-dimension width is out of range");
  // 三个基础量必须都是 2 的幂：整棵树、环维度、首维的位分解都建立在
  // 2 幂结构上（否则各处的移位/截断恒等式全部失效）。
  require(std::has_single_bit(params.N), "N must be a power of two");
  require(std::has_single_bit(params.n), "n must be a power of two");
  require(std::has_single_bit(params.N0), "N0 must be a power of two");
  // 指数与幂必须自洽：N = 2^L、N₀ = 2^a（防止两组字段各改一半）。
  require(params.N == size_t{1} << params.L, "N must equal 2^L");
  require(params.N0 == size_t{1} << params.a, "N0 must equal 2^a");

  // 打包形状：g 是 2 的幂（保住 γ 位分解与投影深度的 2 幂结构），
  // g ≤ n/2 即 ρ = n/g ≥ 2（每明文至少两条记录），ρ、r 按定义重算。
  require(std::has_single_bit(params.g), "g must be a power of two");
  require(params.g <= params.n / 2, "g must leave at least two records");
  require(params.rho == params.n / params.g, "rho must equal n / g");
  require(params.r == exact_log2(params.rho, "rho"), "r must equal log2(rho)");
  // ρ ≤ N：每明文的记录数不能超过总叶数，否则叶层连一个满明文都填不满
  // （P = N/ρ 归零）。N₀ ≥ 2 排除退化首维（a = 0 时无 α 维可选）。
  require(params.rho <= params.N, "rho must fit below the leaf count");
  require(params.N0 >= 2, "N0 must be at least 2");
  // N₀ ≤ N/ρ = P：α 维不能比叶层明文总数还宽；且 ρ·N₀ | N 保证
  // B = P/N₀ 是整数（叶层明文恰好被 α 均分成 N₀ 组）。
  require(params.N0 <= params.N / params.rho, "N0 exceeds N / rho");
  require(params.N % (params.rho * params.N0) == 0,
          "N must be divisible by rho * N0");

  // 位数预算自洽：L 位叶索引恰好拆成 r 位 γ + a 位 α + b 位 β，
  // 由此重算 b、P、B 并与存量字段比对。
  require(params.L >= params.r + params.a, "L is below r + a");
  require(params.b == params.L - params.r - params.a, "b must be L - r - a");
  require(params.P == params.N / params.rho, "P must equal N / rho");
  require(params.B == size_t{1} << params.b, "B must equal 2^b");

  // 打包查询布局自洽：w 用同一个防回绕例程重算（w+1 之类的篡改在此落网），
  // 且 w ≤ n 必须在 bit_ceil 比较之前成立（w > 2^63 时 bit_ceil 是 UB）。
  require(params.ell_beta > 0 && params.ell_gamma > 0,
          "gadget lengths must be positive");
  require(params.w == checked_packed_width(params.N0, params.ell_beta,
                                           params.b, params.ell_gamma,
                                           params.r),
          "w must equal N0 + ell_beta*b + ell_gamma*r");
  require(params.w <= params.n, "packed width exceeds the ring degree");
  // W = bit_ceil(w)、h_q = log₂ W、W ≤ n：w 个逻辑常数要装进一条 n 维
  // 密文并用高度 h_q 的 Subs 树展开，容量 W 超过环维度就装不下了。
  require(params.W == std::bit_ceil(params.w),
          "W must be the next power of two of w");
  require(params.h_q == static_cast<size_t>(std::bit_width(params.W)) - 1,
          "h_q must equal log2(W)");
  require(params.W <= params.n, "W exceeds the ring degree");

  // 可逆性门：查询展开时每个槽位被乘上 W，客户端打包前须预乘 W⁻¹ 抵消
  // （α one-hot 走 mod-t 域，β/γ gadget 行走每 limb 的 mod-q_k 域，见
  // 技巧手册 §1.2）。W 是 2 的幂，故"W⁻¹ 存在"等价于模数为奇数。
  require(std::gcd(params.W, params.t) == 1,
          "W must be invertible modulo t");
  for (uint64_t qk : params.rns_moduli) {
    // 每个 RNS 肢都要奇：只要有一个偶肢，W⁻¹ mod q_k 就不存在，
    // gadget 行的预缩放会在该 limb 上失效。
    require((qk & 1ULL) == 1ULL, "every RNS modulus must be odd");
    require(std::gcd<uint64_t>(params.W, qk) == 1,
            "W must be invertible modulo every RNS modulus");
  }

  // MVP 冻结：响应环即主环（n₂ = n、q₂ = q）。字段漂移说明有人改了响应
  // 侧却没走正式的环切换路径，直接拒绝。
  require(params.response_degree == params.n,
          "MVP response ring must equal the main ring");
  require(params.response_moduli == params.rns_moduli,
          "MVP response moduli must equal the main moduli");
}

// Algorithm 1 ClientIndex：客户端唯一的索引分解入口。把目标叶 i 一次性
// 拆成 (α, β 位, γ 位)——之后所有 L+1 层的查询都复用这一组坐标
// （跨层坐标复用，技巧手册 §1.1），本函数之外不再产生任何私有索引量。
ClientCoordinates client_index(size_t leaf, const TreePirParams &params) {
  // 越界叶直接拒绝：后面的除法/取模对越界值会静默给出错误坐标。
  if (leaf >= params.N) {
    throw std::invalid_argument("client_index leaf is out of range");
  }
  // 第一级分解：γ = ⌊leaf/P⌋ 是打包记录坐标（目标记录在明文内的系数槽），
  // p = leaf mod P 是叶在其 γ 组内的明文序号。等价于把 L 位叶索引切成
  // 高 r 位（γ）与低 L-r 位（p）。
  const size_t gamma = leaf / params.P;
  const size_t p = leaf % params.P;
  ClientCoordinates coords;
  // 第二级分解：α = ⌊p/B⌋ 是首维 one-hot 下标（高 a 位），
  // β = p mod B 是剩余的 b 位明文选择量。
  coords.alpha = p / params.B;
  const size_t beta = p % params.B;
  // β 按小端逐位拆开：每一位后续各自加密成一个 RGSW 选择器，
  // 供各层的 CMux 折叠按 LevelPlan 的位窗口取用。
  coords.beta_bits_le.resize(params.b);
  for (size_t u = 0; u < params.b; ++u) {
    coords.beta_bits_le[u] = static_cast<uint8_t>((beta >> u) & 1U);
  }
  // γ 同理拆成 r 个位选择器：驱动 X^{-γ} 私有旋转链（RotSelect），
  // 上层前缀 γ_ℓ 只是复用其中的高位段。
  coords.gamma_bits_le.resize(params.r);
  for (size_t v = 0; v < params.r; ++v) {
    coords.gamma_bits_le[v] = static_cast<uint8_t>((gamma >> v) & 1U);
  }
  // 只有这三样坐标离开本函数；γ/β 的整数值不外传。
  return coords;
}

// 为每层 ℓ = 0..L 生成公开执行计划。所有字段只由公开参数与层号决定，
// 与具体查询无关，服务端可自由据此分支；私有信息只通过加密坐标进入。
// 计划的职责：告诉服务端本层用哪种选择情形、消费哪些 β/γ 位、投影多深。
std::vector<LevelPlan> build_level_plans(const TreePirParams &params) {
  // 树有 L+1 层（0 = 根，L = 叶），每层恰好一份计划。
  std::vector<LevelPlan> plans;
  plans.reserve(params.L + 1);
  for (size_t level = 0; level <= params.L; ++level) {
    LevelPlan plan;
    plan.level = level;
    // R_ℓ = 2^{max(ℓ-r,0)}：第 ℓ 层的 2^ℓ 个节点按每明文 ρ = 2^r 个打包后
    // 得到的明文数；深度不足 r 的浅层整层塞进一个明文（R = 1）。
    plan.R = level >= params.r ? size_t{1} << (level - params.r) : size_t{1};

    // 三种情形按构造互斥（R 与 1、N₀ 的比较是全序划分）。coarsen_count 在
    // 整个粗化区间恒为 a - log₂R；R = 1 时即 Single 情形用的满金字塔深度 a
    // （§10/§11.3）——α 金字塔第 c 层给出 ⌊α/2^c⌋ 的 one-hot，塔顶恒为
    // 加密的 1（技巧手册 §2.1）。
    if (plan.R == 1) {
      // Single：整层一个明文，无需选择，取塔顶 A^{(a)}_0 = Enc(1)。
      plan.select_case = SelectCase::Single;
      plan.coarsen_count = params.a;
    } else if (plan.R < params.N0) {
      // CoarsenedAlpha：明文数不足 N₀，α 的 a 位只需要高 log₂R = ℓ-r 位，
      // 用金字塔第 c = a-(ℓ-r) 层的粗化 one-hot 直接选中 ⌊α/2^c⌋。
      plan.select_case = SelectCase::CoarsenedAlpha;
      plan.coarsen_count = params.a - (level - params.r);
    } else {
      // AlphaBeta：明文数 ≥ N₀，需要完整 α one-hot（金字塔底层）
      // 再加下方的 β 位折叠，不做粗化。
      plan.select_case = SelectCase::AlphaBeta;
      plan.coarsen_count = 0;
    }

    // β 位窗口：仅 AlphaBeta 层有活跃 β 位。第 ℓ 层的候选下标是
    // δ_ℓ = ⌊β/2^{s_ℓ}⌋（s_ℓ = L-ℓ），即只有 β 的高位段 [s_ℓ, b) 参与选择；
    // 折叠必须按位下标降序（MSB-first）消费——候选数组按 δ 自然整数序
    // 排列时，每步 CMux(S_u, 下半, 上半) 后截半，LSB-first 会配错对
    // （技巧手册 §2.2 有突变实验证据）。其余情形没有 β 位，
    // 用 begin = b 的空区间哨兵表示。
    if (plan.select_case == SelectCase::AlphaBeta) {
      const size_t s = params.L - level;
      plan.beta_begin = s;
      plan.beta_count = level - params.r - params.a;  // d_ℓ = ℓ-r-a，可为 0
    } else {
      plan.beta_begin = params.b;
      plan.beta_count = 0;
    }

    // γ 位调度（§5.3）：ℓ ≥ r 的深层，目标槽位就是完整的 γ（r 个位全用）；
    // ℓ < r 的浅层，祖先节点的槽位是前缀 γ_ℓ = ⌊γ/2^{r-ℓ}⌋，只用 γ 的
    // 高 ℓ 位，即小端窗口 [r-ℓ, r)。旋转链据此复用同一组 γ 位选择器，
    // 只是移位量按窗口重排（技巧手册 §3.2）。
    if (level >= params.r) {
      plan.gamma_begin = 0;
      plan.gamma_count = params.r;
    } else {
      plan.gamma_begin = params.r - level;
      plan.gamma_count = level;
    }

    // 投影深度 min(r, ℓ)：旋转对齐后须投影清掉非目标记录。ℓ < r 的层深度 ℓ
    // 已够——非目标记录旋转后落在 mod 2^ℓ 非零的残差位上，深度 ℓ 的投影
    // 全部杀掉，保留格的其余位置本来无占用（技巧手册 §3.3 技巧二）。
    plan.projection_depth = level < params.r ? level : params.r;
    plans.push_back(plan);
  }
  return plans;
}

// 测试专用 oracle（蓝图 §5.6）：绕开 LevelPlan 与加密路径，直接用坐标算出
// (j_ℓ, p_ℓ, γ_ℓ)，供测试与主路径交叉验证（"独立重实现对拍"方法学）。
// 它直接暴露目标位置，因此绝不序列化、绝不进入生产服务端入口。
LevelOracle build_level_oracle_for_test(size_t leaf, size_t level,
                                        const TreePirParams &params) {
  // 两个入参守卫：叶越界或层号超过 L 都会让下面的移位失义。
  if (leaf >= params.N) {
    throw std::invalid_argument("level oracle leaf is out of range");
  }
  if (level > params.L) {
    throw std::invalid_argument("level oracle level is out of range");
  }
  LevelOracle oracle;
  // 满二叉树里，叶的第 ℓ 层祖先编号就是叶索引砍掉低 L-ℓ 位：
  // j_ℓ = ⌊leaf/2^{L-ℓ}⌋。
  oracle.node_index = leaf >> (params.L - level);
  // 重做一次一级分解（与 client_index 相同）：γ 选系数槽，p 是层内序号。
  const size_t gamma = leaf / params.P;
  const size_t p = leaf % params.P;
  if (level >= params.r) {
    // 深层（R_ℓ ≥ 1 个满明文）：打包布局 D_ℓ[p][u] = M[ℓ][p + u·R_ℓ]，
    // 即节点 j_ℓ 位于明文 p_ℓ = j_ℓ mod R_ℓ、系数槽 u = ⌊j_ℓ/R_ℓ⌋。
    // 由 leaf = γ·2^{L-r} + p 可推 p_ℓ = ⌊p/2^{L-ℓ}⌋、槽位恒为 γ，
    // 二者合成不变量 j_ℓ = γ_ℓ·R_ℓ + p_ℓ（Invariant 1）。
    oracle.packed_plaintext_index = p >> (params.L - level);
    oracle.record_position = gamma;
  } else {
    // 浅层（ℓ < r）：整层 2^ℓ 个节点装进唯一一个明文（p_ℓ = 0），
    // 节点槽位是 γ 的高 ℓ 位前缀 γ_ℓ = ⌊γ/2^{r-ℓ}⌋。
    oracle.packed_plaintext_index = 0;
    oracle.record_position = gamma >> (params.r - level);
  }
  return oracle;
}

// Invariant 2（蓝图 §16）：仅凭跨层共享的 (α, β) 重建第 ℓ 层的层内明文
// 位置 p_ℓ = ⌊p/2^{s_ℓ}⌋（p = α·B + β，s_ℓ = L-ℓ）。这个恒等式是"一条
// 查询服务全部层"的数学根基：服务端不需要每层单独的坐标，只要按层截断
// 同一组 (α, β)。定义域是 ℓ ∈ [r, L]；在 CoarsenedAlpha 层它顺带给出
// 粗化 one-hot 下标 ⌊α/2^c⌋。测试用它对拍 oracle 的 p_ℓ（全叶穷举）。
size_t level_record_position_from_coordinates(size_t alpha, size_t beta,
                                              size_t level,
                                              const TreePirParams &params) {
  // ℓ < r 的层 p_ℓ 恒为 0，公式无意义；ℓ > L 则不存在——都直接拒绝。
  if (level < params.r || level > params.L) {
    throw std::invalid_argument(
        "record position formula is defined for levels in [r, L]");
  }
  // s = s_ℓ = L - ℓ：本层要截掉的低位数。对 p = α·2^b + β 除以 2^s 取整时，
  // 要么只有 β 的低 s 位被截掉（s ≤ b），要么整个 β 连同 α 的低 s-b 位
  // 一起被截掉（s > b）——两个分支是同一个截断的两种落点。
  const size_t s = params.L - level;
  if (s <= params.b) {
    // 截断只吃 β：p_ℓ = α·2^{b-s} + ⌊β/2^s⌋（α 的位完整保留在高位）。
    return alpha * (size_t{1} << (params.b - s)) + (beta >> s);
  }
  // 截断吃光 β 并波及 α：p_ℓ = ⌊α/2^{s-b}⌋（β < 2^b < 2^s 全部落入余数）。
  return alpha >> (s - params.b);
}
