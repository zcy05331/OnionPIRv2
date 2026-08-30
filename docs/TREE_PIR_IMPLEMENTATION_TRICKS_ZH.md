# Binary Tree PIR 实现技巧手册

> 对象：`src/tree_*.{h,cpp}` 全栈（M0–M7 + g=32 扩展）。
> 每条技巧按四要素组织：**机制 / 动机 / 位置 / 证据**。
> 所有实测数字来自 x86_64 + HEXL + Rosetta 2 @ Apple M4、`CONFIG_N2048_K1_COMP`
> （n=2048、log q≈58、log t=13、log q'=22），非原生环境，只做同机相对比较。

---

## 1. 查询侧

### 1.1 一条密文服务全部 L+1 层：跨层坐标复用

**机制**：叶索引 i 只分解一次：γ = ⌊i/P⌋、α = ⌊(i mod P)/B⌋、β = (i mod P) mod B。
草稿论文 Lemma 1/3/4 保证每层的目标坐标都是这三个量的前缀/截断：
γ 在 ℓ≥r 各层恒定；AlphaBeta 层的候选下标 δ_ℓ = ⌊β/2^{L−ℓ}⌋；粗化层的 one-hot
下标 = ⌊α/2^{a−(ℓ−r)}⌋。因此打包 w = N₀ + ℓ_g·(b+r) 个逻辑常数（α one-hot +
b 个 β 位 + r 个 γ 位的 gadget 行）就够全树使用。

**动机**：baseline 每层独立发一条 14,880 B 查询（L=22 时共 575 KB）；跨层复用
把查询压到一条（14,880 B），这是 22× 通信优势的一半来源。

**位置**：`tree_index.cpp: client_index / build_level_plans /
level_record_position_from_coordinates`；`tree_query.cpp: make_tree_query`。

**证据**：`draft_deep_check` 对拍脚本 126,975 组 (leaf, level) 零偏差；
`test_tree_index` 全叶穷举 Invariant 1/2。

### 1.2 两种尺度、两个 helper：Δ·W_t⁻¹ 与 W_{q_k}⁻¹·G[k]

**机制**：打包密文的每个逻辑槽位在展开时会被乘 W = 2^{h_q}（每层 add/sub 翻倍）。
预先除掉它有两条**不同**的路径：
- α one-hot 是 BFV 明文值：注入 Δ·(W⁻¹ mod t)，展开后精确回到 Enc(1)；
- β/γ gadget 行是 RLWE\* 常数（无 Δ 因子）：每个 RNS limb 注入
  (W⁻¹ mod q_k)·G[k]，展开后精确回到 gadget 幂。

蓝图 §8.2 明令二者不得共用"通用标量加"helper——因为一个走 mod-t 域、
一个走每 limb mod-q_k 域，混用会静默产生错误缩放。

**位置**：`tree_query.cpp: add_bfv_query_constant / add_rlwe_star_constant`
（后者独占 (c0,c1)=(−as+e+Δm, a) 的分量约定，调用方不感知）。

**证据**：`test_tree_query`：打包态 BitRev(α) 槽位解密恰为 W⁻¹ mod t；
展开后 α 段精确 one-hot、one-selector 行相位级等于 G[k]（大行 |phase−G|<2^27）。

### 1.3 BitRev 写入 + useful-leaf 剪枝

**机制**：逻辑槽位 j 写在系数 BitRev(j, h_q)，配合服务端 heap 序展开树，
使展开叶 j 恰好回收逻辑槽位 j；useful_cnt = w 右侧的整棵子树在 Subs 前跳过。

**位置**：客户端两个 helper 内部；服务端 `server.cpp: fast_expand_qry`
（`left_leaf >= useful_cnt` 剪枝）。

### 1.4 `with_query_shape`：仅展开的参数视图

**机制**：树查询形状（fst=N₀、b+r 个 selector、高度 h_q）不可能由数据库
规划器 `calculate_db_shape` 反推出来。`PirParams::with_query_shape` 直接写入
这三个字段，并把 num_pt 折叠为 fst_dim_sz——该视图**不承载数据库**，只喂
`fast_expand_qry` 和会话密钥校验。误用防护：`evaluate_other_dim` 对
`other_dim_sz < 2^{h−1}` 的布局硬抛异常（否则 ragged 公式 size_t 下溢会
静默越界写）。

**位置**：`pir.cpp: with_query_shape`；`server.cpp: evaluate_other_dim` 守卫。

### 1.5 QueryUnpack 单源化

**机制**：展开行切片 + RGSW 补全收敛为 `PirServer::complete_selectors`，
flat 生产路径（make_query）与树路径（unpack_tree_query）调用同一份实现，
行布局约定不可能漂移；`test_pir` 与树 CMux 门从此守护同一段代码。

**位置**：`server.cpp: complete_selectors`；`tree_query.cpp: unpack_tree_query`。

---

## 2. 选择层（首维）

### 2.1 α 金字塔：只用加法的多分辨率 one-hot

**机制**：A^{(c+1)}_j = A^{(c)}_{2j} + A^{(c)}_{2j+1}。一次展开得到的 N₀ 维
one-hot，经 a 轮纯密文加法变出全部粗化分辨率：层 c 对 ⌊α/2^c⌋ one-hot，
塔顶 A^{(a)}_0 恒加密 1。Single/CoarsenedAlpha/AlphaBeta 三种层各取所需，
无需第二次展开或额外密钥。

**位置**：`tree_select.cpp: build_alpha_pyramid`；分层消费逻辑
`plan_row_and_cols`。

**证据**：`test_tree_select` 金字塔逐槽解密门（指示值 + 常数性）。

### 2.2 MSB-first β 折叠

**机制**：候选数组按 δ 自然整数序排列时，折叠必须从最高位 β_{b−1} 开始
（每步 CMux(S_u, 下半, 上半) 后截半）。LSB-first 会配错对。

**证据**：`test_tree_select` 明文模型证明 LSB-first 对非对称目标必错；
加密层回归用倒序 selector 重放最深层折叠并要求结果 ≠ D[p_ℓ]；
β=01 非对称叶经突变实验验证能杀死位序翻转（评审时实测过该突变）。

### 2.3 三只首维核，逐位相等

**机制**：同一个环表达式 Y[δ] = Σ_k D[k·2^d+δ]·A_k 有三个实现：

| 核 | 做法 | 相对成本 |
|---|---|---|
| scalar | 每项 NTT-乘-INTT + 系数域累加 | 参考基线 |
| **NTT-u64** | 层库预 NTT（`TreeLevelDatabaseNtt`）+ 每查询一次金字塔 NTT，NTT 域点乘累加，每候选一次 INTT | NTT 次数降 ~99% |
| **composite m32** | NTT 值按 q=q₁·q₂ 拆成两组 29-bit u32 limb，按 (δ,k) 重排成 level-major 矩阵，`level_mat_mat_32` 做延迟规约 32×32→64 matmul，CRT 合成后每候选一次 INTT | 再快 ~40%（path 808→568 ms） |

**关键不变量**：mod-q 算术精确 + INTT 线性 ⇒ INTT(Σ) = Σ(INTT)，
三条路径**密文逐位相等**——比"解密相等"强得多的回归护栏，且 CRT 合成
返回的正是 mod q 的规范代表元，不破坏逐位性。

**内存注记**：m32 视图与 NTT-u64 视图等大（8 B/系数），启用 composite 时
只建 m32、留空 ntt，避免内存翻倍。

**位置**：`tree_select.cpp: select_level / select_level_ntt / select_level_m32、
build_level_ntt_view / build_level_m32_view / pyramid_to_ntt / pyramid_to_m32`；
复用核 `matrix.cpp: level_mat_mat_32`。

**证据**：`test_tree_kernel` 三路逐位门（两形状 × 全层 × 多叶）；
g=32/2²² 实测 path 808 → 568 ms。

---

## 3. 旋转与投影

### 3.1 MulXPow：mod 2n 的符号位技巧

**机制**：负循环环里 X^{−k} = X^{2n−k}。复用 `negacyclic_shift_poly_coeffmod`：
index_raw = shift + i，低 log n 位定位置，`index_raw & n` 位定符号——
一个位运算同时处理回绕与 X^n = −1 变号。明确区分于 BFV batching 槽旋转。

**证据**：`test_tree_rotate` 对全部 4096 个指数（[0,2n)）与明文负循环 oracle
逐一比对，覆盖符号翻转。

### 3.2 RotSelect：旋转即 CMux

**机制**：RotSelect(S, C, k) = C + ExtPdt(X^{−k}C − C, S) 恰好是现成
`ext_prod_mux(C, X^{−k}C, S)`——不需要新原语。γ 的 r 个位选择器串成
X^{−γ} 的私有旋转链；上层前缀 γ_ℓ 复用同一 selector 数组的高位段，
移位量按 2^{v−gamma_begin} 重排——LevelPlan 的 gamma 窗口字段直接驱动。

**位置**：`tree_rotate.cpp: rot_select / private_rotate_level`。

### 3.3 投影的两个反直觉性质

**机制**：π_d 通过 d 轮 f ← f + τ_{η_u}(f)（η_u = n/2^u+1）实现，
**2^{−d} 预缩放放在最前**抵消每轮翻倍。

技巧一（噪声也被投影）：自同构和 Σ_i σ_i(e) = 2^d·π_d(e)——噪声项经历与
消息完全相同的投影，预缩放的 2^{−d} 与 2^d 精确相消，所以投影输出噪声
≈ |π(e)| + d 次 keyswitch 噪声，而不是被 2^{−d} mod q 炸成均匀大数。
这是"先乘逆再展开"类构造普遍成立但容易看错的一点。

技巧二（深度 min(r,ℓ) 足够）：ℓ<r 的层旋转后非目标记录位于非零残差
u−γ_ℓ (mod 2^ℓ)，深度 ℓ 已全部杀掉；保留格上其余位置本来无占用。

**位置**：`tree_project.cpp: project_keep_stride`。

**证据**：`test_tree_project`：深度 0..11 对明文 oracle 精确相等（含 2^{−d}
缩放正确性）；纯投影深度 11 后噪声预算仍有 23 bit；ℓ<r 层全深度 vs
min(r,ℓ) 等价性逐层验证。

### 3.4 跨步 g-chunk 布局：g>1 的全部秘密

**机制**：记录 u 的 g 个 12-bit chunk 放在系数 {u + j·ρ}（ρ = n/g），
而非连续放置。收益三连：
1. 旋转 X^{−γ}（γ<ρ）**一次**对齐全部 g 个 chunk；
2. 满深度投影的保留格 {0, ρ, 2ρ, …} **恰好**是目标记录的 chunk 格；
3. 打包容量顺势变为 ρ 槽/密文，X^z 移位后不同层占不同 mod-ρ 残差，不重叠。

r = log₂ρ 同时缩短旋转/投影链（g=32 时 11→6 级），部分抵消 ×g 的首维负载。

**位置**：`tree_select.cpp: pack_tree_level`（chunk 版）；
`tree_response.cpp` 容量 `tree.rho`；`tree_index.cpp` 校验泛化。

**证据**：`test_tree_g32` 跨步放置恒等式双向验证 + 端到端 32 字节逐字节恢复。

---

## 4. 响应层

### 4.1 `switch_response_to_small_q`（M5）：最后一刻的模数切换

**机制**：全部同态运算完成后，把全 q（58-bit）响应中心化重缩放到 22-bit
NTT 友好素数 q'：x → round(x·q'/q)。切换后噪声 = 原噪声×(q'/q) + 舍入项
（≈ ternary 密钥的 ||s||/2 量级）。**为什么必须最后做**：提前切换损失
噪声余量，且与首维 matmul、外积、Galois 密钥的参数约定冲突（生产
make_query 同一纪律）。树路径通过公开 wrapper 复用生产
`mod_switch_inplace`，守卫（SmallQWidth < RnsMods[0]）一致。

**一个度量口径陷阱**：全 q 下打包响应"只剩 3–4 bit 预算"曾看似濒危，
实际是大 Δ 度量的错觉——切到 q' 后 max noise 42–67 对界 256，与生产
PIR 同水位。评估噪声要看**绝对噪声 vs Δ'/2**，不是全 q 预算位数。

**位置**：`server.cpp: switch_response_to_small_q`；
`tree_response.cpp: answer_path_mvp` 每 chunk 终结处。

**证据**：`test_tree_e2e` 切换后全路径正确；线上响应 11,264 B 实测
（与单条 baseline 响应同字节数）。

### 4.2 公开 level_offsets 放置图

**机制**：响应携带每层槽位偏移（只依赖公开参数）。顺序打包填 z；M7 压缩
路径填 2z；未来任何放置方案都不再触碰提取端。提取统一读
`offset + j·ρ`。

**位置**：`tree_response.h: TreePathResponse.level_offsets`。

### 4.3 d=2 环切换（M7）：响应折半的完整配方

**机制**（四个要点缺一不可）：

1. **奇偶分解视角**：f(X) = f_e(X²) + X·f_o(X²)，Y = X² 保持负循环
   （Y^{n₂} = X^n = −1）。大密文相位的偶部 = c0_e + a_e·s_e + Y·a_o·s_o，
   即以大密钥的两个小环分量为密钥的 2-秩 MLWE 密文。
2. **独立目标密钥 + 双 KSK**：客户端采样三值 s₂，注册
   KSK_c[t] = RLWE_{n₂,q}(B^t·s_c) under s₂（c ∈ {e,o}，B=2^{29}，l₂=2）；
   服务端 gadget 分解 a_e 与 Y·a_o，digit×KSK 累加即切到 s₂ 下。
3. **顺序纪律（本条最关键）**：切换必须在**全 q**做、之后才降模。
   在 q'=2^22（Δ'=2^9）下任何 gadget-KS 噪声（≥2^{10} 量级）都直接越界；
   全 q 下 KS 项 ~2^{39} ≪ Δ/2 = 2^{44}，随后 2^{−36} 的降模缩放把它压到
   O(10)。误差分解：e_out ≈ e_carried·2^{−36} + e_KS·2^{−36} + e_round
   ≈ 100 + 10 + 30，对界 508。
4. **偶对齐打包（§23.4 向量化的对齐形态）**：打包偏移取 2z（需 2L < ρ），
   全部载荷落在偶子格上，被压缩映射完整保留；奇系数只有噪声，丢弃无害
   ——实测压缩后噪声（39–51）反而比未压缩（45–54）略好。

**免 NTT 根注册**：小环乘法用 u128 单次规约的负循环 schoolbook
（n₂·q² = 2^{126} < 2^{128}），合成模数无需注册 2n₂ 次根——正确性优先的
参考核，素数 q' 下的 NTT 化留作优化。

**收益**：响应 11,264 → 5,632 B（rate 6.5% → 13.1%）；在线总量 20,512 B，
低于单次标准 OnionPIR 查询；一次性环切换密钥 ~58 KB。

**位置**：`tree_compress.{h,cpp}`；`client.cpp: create_ring_switch_bundle`；
`tree_response.cpp: answer_path_compressed`。

**证据**：`test_tree_compress`：真实哈希与标量两形状全过，压缩/未压缩
解码逐值相等；噪声与字节数见上。

### 4.4 被证伪的三个融合方案（否定性结果，同样是 trick 知识）

试图跨层摊销旋转/投影的 keyswitch 时，三个候选调度全部不健全：

1. **细→粗 PackPair 树**（C = A + X^{2^u}B + τ(A − X^{2^u}B)）：放在奇
   2^u 格位的内容会被下一轮更粗的 τ 映射出 e+n/2 处鬼影（n/2 是 ρ 的
   倍数，正落在载荷格上）。
2. **CDKS PackLWEs 直套**：健全级联要求输入已在 stride-ρ 格上（等于每
   输入仍要全深度投影，KS 反增），且其放置格距 n/2^m = ρ 与多 chunk
   载荷别名。
3. **先并后旋（共享 γ 链）**：每层有 ρ/2^{d₀} 个与 γ 同余的非目标记录
   落在共享投影保留格上，与他层槽位碰撞——**私有对齐必须先于公开
   stride 过滤**。

结论：按层的旋转+投影开销在现有原语下不可摊销；打破它需要"加密偏移
投影"（对私密偏移的保留格算子）这类新构造——开放问题。推导记录在
`tree_response.h` 头注释。

---

## 5. 参数与噪声工程

### 5.1 会话密钥高度 = log₂ n

投影需要 η_0..η_{r−1}；g=1 时 r=11 > 编译期 TREE_HEIGHT=10 的默认覆盖。
`create_session_keys(height)` 用 `with_query_shape({1,0,height})` 的高度
视图喂 `gen_bv_galois_keys`——同一密钥族 (n≫u)+1 同时服务展开与投影。
（`client.cpp`）

### 5.2 能力界前移到参数工厂

W ≤ n 允许 h_q 到 log₂n，但会话密钥只覆盖注册高度；
`make_tree_pir_params_for_scheme(..., session_key_height)` 在工厂处拒绝
超界形状，而不是等客户端打完包后在 `set_client_session_keys` 报泛化错误。
（`tree_query.cpp`）

### 5.3 checked arithmetic 三处

`checked_packed_width`（w 的乘加逐步防回绕：ell=2^60、b+r=16 时 w 会
回绕成 N₀ 并静默通过全部校验）；`bit_ceil` 前先 w ≤ n（防 >2^63 UB）；
L/a 移位前范围检查（a≥64 UBSan 实证过）。（`tree_index.cpp`）

### 5.4 三次被数据否定的参数实验（防止后人重走）

| 实验 | 预期 | 实测/解析结论 |
|---|---|---|
| a=10/h_q=11 折叠减半 | path −190 ms | 展开 +72、金字塔翻倍吃掉收益（净 +46 ms）；首维 1024 项求和使 max noise 294 > 256 ✗ |
| n4096_K2 消槽位税 | 首维 −33% | 环×2 + 双 limb 使总耗时 +74%（1.6 s）、通信 ×4.3 ✗ |
| t=2^17 @ n2048 零浪费 | 膨胀 1.5→1.0 | Δ 缩 2^4 ⇒ 预算转负，解析排除 ✗ |

**运行点结论**：k1_comp / g=32 / a=9 是帕累托点；384/256 的槽位圆整是
小环噪声经济性的固定价格。

---

## 6. 测试方法学技巧

1. **逐位相等门**：优化核与参考核比较原始密文系数而非解密值——凡是
   "同一环表达式的不同求值顺序"（mod-q 精确）都应该用这一档强度。
   （`test_tree_kernel`）
2. **突变验证**：测试强度用真实突变实验标定——β 位序翻转、LSB-first
   折叠都有"突变必死"的显式回归，且曾实际编译运行突变确认。
3. **相位级尺度检查**：gadget 行无 Δ 因子，解密取整会毁掉尺度信息，
   必须在 phase = c0 + c1·s 层比对；辅以噪声地板门限 + 防空转断言
   （单 limb 配置下顶行必须清界，否则测试静默退化）。（`test_tree_query`）
4. **独立重实现对拍**：索引/打包数学用蓝图与草稿公式的独立 Python
   实现全叶穷举对拍（126,975 组），封死"实现自测自己"的循环论证。
5. **中间提交可编译纪律**：分层提交时用隔离 worktree 逐个构建中间
   commit；跨层文件用"剥离-提交-恢复"而非脆弱的 hunk 手术。

---

## 7. 快速索引：技巧 → 文件

| 技巧 | 主要位置 |
|---|---|
| 跨层坐标复用 | `tree_index.cpp` |
| 双尺度打包 helper | `tree_query.cpp` |
| with_query_shape 视图 | `pir.cpp` |
| complete_selectors 单源 | `server.cpp` |
| α 金字塔 | `tree_select.cpp` |
| NTT-u64 / m32 双优化核 | `tree_select.cpp` + `matrix.cpp` |
| MulXPow / RotSelect | `tree_rotate.cpp` |
| 投影（噪声共投影、min(r,ℓ)） | `tree_project.cpp` |
| 跨步 g-chunk 布局 | `tree_select.cpp: pack_tree_level` |
| switch_response_to_small_q | `server.cpp` / `tree_response.cpp` |
| level_offsets 放置图 | `tree_response.h` |
| d=2 环切换 | `tree_compress.{h,cpp}` / `client.cpp` |
| 融合否定性结果 | `tree_response.h` 头注释 |
| 会话密钥高度 / 能力界 | `client.cpp` / `tree_query.cpp` |
