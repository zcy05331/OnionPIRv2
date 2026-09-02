# Cuckoo Batch PIR 的优化空间：开销在"按桶付费"而非哈希本身，而对 Merkle 路径最优的优化是不用它

## 摘要

本仓库的 cuckoo batch PIR 基线（Angel 等人的概率批码 PBC：3 个 hash、1.5k 个桶、每项复制 3 份）在 256 MB / k=22 的 Merkle 路径工作负载上测得单批 server 时间 3,555 ms、存储 2.91 倍、通信 863 KB，分别是同一数据库上 layerwise 基线的 3.5、2.9 和 1.5 倍。本文以"它还能优化多少、往哪里优化"为题，检索并核实了 2004–2026 年间批码理论、cuckoo hashing 参数、batch PIR 系统、密文打包/压缩原语、结构感知树路径检索与下界/方法学批评五个视角共 46 篇文献，并用本仓库新增的分阶段计时与 10⁵ 量级蒙特卡洛模拟作为第一手证据。三个结论：第一，3n 存储 / 1.5k 桶不是理论最优而是工程折中——组合批码在实用规模下要求复制度趋近 k，2-hash 无 stash 在小批量下不可用，更多 hash 函数是理论上最便宜的失败率杠杆，但每一种都换不来低于 2× 的存储；第二，时间开销的大头不是哈希而是"每桶一个独立 PIR 实例"的固定成本——本基线 31% 时间花在 33 次查询展开与 RGSW 补全，扫描本身只占 46%——文献中查询侧打包、响应侧重打包与遗忘压缩能分别削掉通信的 30–97% 与响应密文的 1.5→1.05 倍，但没有任何方案能摊薄展开成本本身；第三，当批量是一条根到叶路径时，结构感知检索（TreePIR 的平衡祖先染色、本仓库的 layerwise 与 tree MVP）在存储、计算、通信三个轴上同时占优，且检索范围内没有任何反例。附带一个此前未被量化的事实：文献沿用的 2⁻⁴⁰ 失败率只在 k≳200 成立，k=22 时 1.5k/3-hash 的放置失败率实测约 2⁻¹¹。

## 1. 引言

本仓库为 Binary Tree PIR 的对比实验实现了三个基线：flat（整树逐节点 PIR）、layerwise（逐层独立 PIR）与 cuckoo batch（Angel–Chen–Laine–Setty 风格的概率批码）。前两者的开销结构已在此前的分阶段计时中解释清楚；cuckoo 基线是最晚加入的，它代表"通用批处理"这一类方法，其开销来源、可优化程度与理论下界尚未系统梳理。回答这个问题对论文有两层意义：如果基线还有便宜的优化未做，对比就不公平；如果基线已接近其方法族的极限，那么 tree MVP 相对它的优势就是结构性的。

现有综述不足以回答。ePrint 2026/1135 的 PIR 教程把 batch PIR 概括为 Angel 框架并指出 cuckoo 失败可能影响正确性或隐私，但没有覆盖 PIRANA、VIA-B、Npir、BitBatSPIR 等 2024 年后的分支，也不讨论存储与失败率的理论边界 [40]。批码的组合理论（IKOS04 及其后续）与系统论文之间几乎不互引：Angel、VBPIR、PIRANA、Respire 全部转引同一个经验估计，而不引用 cuckoo hashing 的负载阈值或 stash 理论 [1][2][3][5]。本文的角度正是把这两条线接起来，并用本仓库的实测校准。

研究问题：

- **RQ1（空间）**：单服务器 cuckoo batch PIR 的 3 倍复制是否有理论或工程上的降低余地？把存储降到 2× 或 1× 各自要付什么代价（桶数、失败率、每桶容量、额外查询）？
- **RQ2（时间与通信）**：一次批查询的 server 时间在扫描、每桶固定成本、dummy 桶之间如何分配？哪些已发表技术能削减哪一项，幅度多大，并且能否移植到 OnionPIRv2 这种 RGSW 外积流水线？
- **RQ3（结构）**：当批量是一条 Merkle 路径（每层恰好一项）时，通用 cuckoo 批处理还值得优化吗，还是应当被结构感知方案取代？

第 2 节说明检索方法与语料，第 3 节给出分类法，第 4 节解剖本仓库基线的时间/空间/通信账目作为案例，第 5–8 节分别回答空间、时间、结构与批评四个分支，第 9 节做跨分支综合，第 10 节列开放问题，第 11 节逐条回答研究问题。

## 2. 方法

**检索视角**（五路并行，各两轮以上，宽后窄）：主流 PBC 谱系（SealPIR/PBC 及其后续系统）；空间/编码理论（批码、组合批码、cuckoo hashing 负载阈值与 stash）；压缩与摊销（查询侧打包、响应侧 LWE/RLWE 重打包、遗忘密文压缩、离线/在线模型）；结构感知（Merkle 证明、CT 审计、区块链轻客户端、结构化子集检索）；批评与方法学（下界、跨客户端摊销、报告口径）。关键词按"核心机制 × 目标任务"与"引用网络"两种模式构造，并对 VBPIR、PIRANA、Respire 的 Semantic Scholar 被引列表做了引用链检查。

**核实**：每篇候选文献均通过 ePrint/arXiv/出版社或 DBLP 页面确认题名、作者与发表信息，并从摘要或本地抽取的全文核对引用的数字；无法确认存在者一律不用。46 篇入选文献中 VERIFIED 33 篇，MINOR（存在无疑、个别元数据如期刊卷号未核）11 篇，PAYWALL（仅摘要可得）2 篇。时间范围 1999–2026 年，以 2018 年 PBC 提出后为主。

**第一手证据**：（i）本仓库 2026-09-02 在 Apple M4（Rosetta x86_64 + Intel HEXL）上的 256 MB / 16 次实测，含本轮新增的 server 内部阶段计时（expand / convert / first_dim / other_dim / mod_switch，覆盖率 99.97%）；（ii）对本仓库 cuckoo 放置算法（3 hash、随机游走驱逐、10,000 步上限）的蒙特卡洛模拟，每组 2×10⁵–3×10⁵ 次独立试验；（iii）node0（Xeon Silver 4314）上 1 GB/4 GB 档的五协议结果（cuckoo 当时尚未合入主干，故该机器上没有 cuckoo 数据）。

**语料范围声明**：本仓库的 draft 论文与实现不作为文献引用；两台机器的绝对数字不可直接互比（M4 本地抖动 8–13%，node0 σ<0.2%），但同机相对比例可用。

## 3. 分类法

以"优化目标"为行、"手段所在层"为列组织文献；每个非空格子给出代表工作，空格子即为发现。

| 目标 \ 层 | 哈希/批码层 | 查询侧 | 响应侧 | 结构层（利用批量结构） |
|---|---|---|---|---|
| **存储** | IKOS04 子立方码 [7]、组合批码 [8][9][10]、PBC 3n/1.5k [1]、更多 hash [6]、stash [14][15]、负载阈值 [11][12][13] | —（空：查询侧不改变存储） | —（空） | TreePIR 零复制 [26]、逐层分区（本仓库 layerwise） |
| **server 时间** | 减少桶数（[6] 理论）；SIMD 单次扫描 [2][3] | 共享展开 [18]、SIMD 查询打包 [2][3] | 压缩后处理成本 +6–8% [4] | 单查询取整条路径（本仓库 tree MVP）；平衡染色减最大子库 [26] |
| **通信** | 少 dummy 桶（[6]） | 查询打包 [2][3][5][18][22] | 重打包 [5][19][20][21][22]、遗忘压缩 [4][23][24]、模数切换 [2][18] | 路径打包成 1 条密文（本仓库） |
| **正确性/失败率** | 桶数 > 1.5k [2]、更多 hash [6]、鲁棒 PBC [6] | — | — | 确定性（无失败）[26] |

两个空列格子是真实的缺口而非检索遗漏：没有任何工作通过查询或响应侧的手段降低 server 存储，因为复制是在数据库编码阶段付出的。一个跨格子的工作是 PIRANA [3]：它保留 3n/1.5k 的哈希层，却把所有桶的查询装进同一组 SIMD 密文，使查询大小与 k 无关；它同时落在"哈希层"与"查询侧"，说明这两层是正交的——这也是本文的组织原则：**哈希层决定存储与失败率，查询/响应层决定通信，而 server 时间由二者共同但主要由"每桶固定成本"决定。**

## 4. 案例解剖：本仓库 cuckoo 基线的账目

本基线（[cuckoo_batch.cpp](../../src/cuckoo_batch.cpp)）对根除外的 2(N−1) 个节点用 3 个公开 hash 复制进 ⌈1.5k⌉ 个桶，每桶是一个独立的 OnionPIRv2 实例（per-bucket 布局由与 layerwise 相同的评分器选取）；客户端对 k 个兄弟节点做随机游走 cuckoo 放置，未命中的桶发送不可区分的 dummy 查询。256 MB 档（2²² 叶，k=22，B=33，其中 11 个 dummy 桶）、3 次预热 + 16 次测量：

| 阶段 | 每批 (ms) | 占比 | 每桶 (ms) | 说明 |
|---|---|---|---|---|
| expand（ExpandBFV） | 632.6 | 17.8% | 19.2 | 33 次独立展开 |
| convert（RGSW 补全） | 469.1 | 13.2% | 14.2 | 每桶选择位各自补全 |
| first_dim（首维扫描） | 1,647.3 | 46.3% | 49.9 | 总扫描量 = 3n 复制后的全部明文 |
| other_dim（其余维折叠） | 791.1 | 22.3% | 24.0 | 桶小、形状差，比例偏高 |
| mod_switch | 13.9 | 0.4% | 0.4 | |
| **合计** | **3,555** | | 107.7 | 阶段之和 3,554（覆盖 99.97%） |

同一机器、同一数据库上：standard 单记录 1,013 ms，layerwise 1,028 ms，tree MVP 838 ms，flat 21,308 ms。三个账目直接可读：

- **时间**：扫描只占 46%。若把本基线的首维扫描按明文数折算，每明文 6.5 µs，比 standard 的 5.0 µs 差 30%——桶只有约 7.7k 个明文，首维核的流式效率下降；再乘上 2.91 倍的明文数，首维总时间是 standard 的 3.8 倍。其余 54% 是 33 个实例各付一次的展开、补全与其余维折叠，其中 11 个 dummy 桶贡献的固定成本约 370 ms（10%）。
- **空间**：254,296 个明文对 flat 的 87,382 个，即 **2.91×**（3 倍复制减去同桶重复命中的 3%，再加每桶向 96 节点/明文取整）；以 u64 系数计的物理驻留 3.88 GiB，对 256 MiB 原始数据是 15.5×，对 flat 的 1.33 GiB 同样是 2.91×。此外客户端需要每个桶的有序成员表才能算出桶内位置，这是 Ω(N) 的公开元数据（本实现的 cuckoo_position 用 lower_bound 查成员表），文献按惯例不计入在线通信 [1][2]，但 TreePIR 指出它在 2²⁴ 叶时达 4.7 GB [26]。
- **通信**：33 条查询密文 491,040 B + 33 条响应 371,712 B = **862,752 B**，是 tree MVP（26,144 B）的 33 倍、layerwise（575,168 B）的 1.5 倍；其中 1/3 是 dummy 桶的往返。

**失败率**：本实现在随机游走失败时抛异常，因此失败率就是正确性缺口。对本实现的放置算法做蒙特卡洛（每组 2–3×10⁵ 次）：

| k | B | hash 数 | B/k | 存储倍数 | 失败率 |
|---|---|---|---|---|---|
| 22 | 33 | 3 | 1.50 | 3× | 4.05×10⁻⁴ ≈ 2⁻¹¹·³ |
| 24 | 36 | 3 | 1.50 | 3× | 3.50×10⁻⁴ ≈ 2⁻¹¹·⁵ |
| 26 | 39 | 3 | 1.50 | 3× | 1.80×10⁻⁴ ≈ 2⁻¹²·⁴ |
| 22 | 36 | 3 | 1.64 | 3× | 8.0×10⁻⁵ ≈ 2⁻¹³·⁶ |
| 22 | 40 | 3 | 1.82 | 3× | 3.3×10⁻⁶ ≈ 2⁻¹⁸ |
| 22 | 44 | 3 | 2.00 | 3× | 0/3×10⁵（< 10⁻⁵） |
| 22 | 44 | 2 | 2.00 | 2× | 8.9×10⁻² |
| 22 | 48 | 2 | 2.18 | 2× | 5.4×10⁻² |
| 22 | 28 | 3 | 1.27 | 3× | 1.5×10⁻² |
| 22 | 25 | 4 | 1.14 | 4× | 3.8×10⁻³ |
| 22 | 28 | 4 | 1.27 | 4× | 4.5×10⁻⁵ |
| 22 | 33 | 4 | 1.50 | 4× | 0/2×10⁵ |
| 22 | 28 | 5 | 1.27 | 5× | 0/2×10⁵ |
| 256 | 384 | 3 | 1.50 | 3× | 0/2×10⁴ |

即：在本工作负载的批量大小下，沿用文献参数的失败率是 2⁻¹¹ 量级，约每 2,500 条路径失败 1 条；把桶数提到 2k 才把它压到本模拟分辨率以下；2-hash 方案在小 k 下完全不可用；增加 hash 数是以存储换失败率的最陡杠杆。这与文献的自述一致而更具体：Angel 等人只声称 k>200 时 ≈2⁻⁴⁰、更小的 k "接近 2⁻²⁰" [1]，VBPIR 承认 k=32 时仅 <2⁻²⁰ 并建议小批量时 B>1.5k [2]，Yeo 则把这一整套参数标注为"仅实验估计" [6]。

## 5. 空间：批码理论、哈希参数与 3× 复制的边界

这一分支回答 RQ1：3n/1.5k 是折中而非最优，但每一条降存储的路都有明确的对价。

**确定性批码的代价是复制度趋近 k。** Ishai 等人定义的 (n,N,k,m,t) 批码中，子立方码可达任意常数码率但桶数 m 随 k 超多项式增长，Reed–Muller 与"子集"码同样把高码率换成多项式量级的桶数 [7]。Angel 等人的对比表把这些构造具体化：ℓ=2 的子立方码在 k=256 时要 25.6n 存储与 6,561 个桶，而 Pung 的混合方案是 4.5n、9k 桶、2⁻²⁰，PBC 是 3n、1.5k、≈2⁻⁴⁰ [1]。组合批码（每桶只读一项、无失败）的极限更严：Paterson–Stinson–Wei 证明复制度为 c 的均匀组合批码最多服务 (k−1)C(m,c)/C(k−1,c) 项——按 k=256、m=384、c=3 代入约为 874 项，远小于任何 PIR 数据库——且当 n 超过 (k−1)C(m,k−1) 时最优复制度趋于 k [8]；Balachandran–Bhattacharya 进一步表明要容纳多项式量级的项数，复制度必须不小于 k−⌈log k⌉ [9]。Asi–Yaakobi 的近最优构造把冗余降到 O(√n log n)，但要求多重集解码、每项读多个桶，与"每桶一次 PIR"的模型不兼容 [10]。**因此在本基线的模型（每桶恰一次单查询 PIR、无失败）下，理论明确排除了低于 3× 的确定性方案；随机化（PBC）是唯一可行的降存储路线。**

**随机化后，存储由 hash 数决定，桶数由负载阈值决定。** w-ary cuckoo hashing 的渐近阈值 c₃=0.9179、c₄=0.9768、c₅=0.9924 [11][12] 意味着 k 个球只需 1.09k（w=3）、1.02k（w=4）个桶；2-hash 的阈值 0.5 给出 2k 桶，这也是 stash-free 单桶检索的存储下限 2×。桶容量 ℓ>1 能把 2-hash 阈值抬到 0.897（ℓ=2）与 0.959（ℓ=3）[13]，但每桶要取回 ℓ 项，相当于 ℓ 次 PIR。有限 k 的松弛才是真实开销：PBC 在 w=3 时用 1.5k 而非 1.09k 换 2⁻⁴⁰，而第 4 节的模拟说明这一松弛在 k=22 时仍不够。stash 是另一条路：Kirsch–Mitzenmacher–Wieder 给出常数 stash 使 2-hash 失败率从 Θ(1/n) 降到 O(n^{−(s+1)}) [14]，Minaud–Papamanthou 修正了带容量桶时的界为 Θ(n^{−d−s}) [15]；但在单服务器 PIR 里，stash 中的每一项都要用一次全库单查询取回——以本基线为例就是每项多付一次 926 ms 的 flat 扫描——这正是 PIR-PSI 与 Pinkas 等人只把 stash 用在 PSI 而非 PIR 的原因 [16][17]。Yeo 给出理论上最便宜的杠杆：增加 hash 函数数 w=O(1+√(log(1/ε)/log n)) 可在无 stash、O(n) 桶的前提下达到失败率 ε，比 stash 或桶容量方案二次地好，并且是对抗性（hash 公开且可复用）场景下唯一有鲁棒版本的方案 [6]；代价是存储随 w 线性增长，本模拟中 w=4、B=1.5k 在 2×10⁵ 次内零失败，但存储变为 4×。

**系统层面无人偏离 (3n, 1.5k)。** SealPIR-PBC、VBPIR、PIRANA、BPSY24、Respire 全部使用同一组参数，差别只在通信与打包（第 6 节）[1][2][3][4][5]；Respire 为把桶容量控制在 2 的幂而把 T=256 的桶数提高到 391–398 [5]。据检索结果，没有任何已发表系统实现 2-hash+stash 或容量 2 桶的 2× 存储变体，也没有工作在小 k（<64）下重新校准桶数。

| 方案族 | 存储 | 桶数 | 失败率 | 每桶读取 | 证据 |
|---|---|---|---|---|---|
| 组合批码（确定性） | →k×（实用规模） | m | 0 | 1 | [8][9] |
| 子立方码 ℓ=2 | 25.6n（k=256） | 6,561 | 0 | 多桶 | [1][7] |
| PBC w=3 | 3n | 1.5k | ≈2⁻⁴⁰（k>200）；2⁻¹¹（k=22，本文） | 1 | [1][2][6]、第 4 节 |
| w=2 无 stash | 2n | ≥2k | 小 k 下 5–9%（本文） | 1 | [11][16]、第 4 节 |
| w=2 + stash s | 2n | 2k | Θ(k^{−1−s}) | 1 + s 次全库查询 | [14][15] |
| w=4 | 4n | 1.5k | <10⁻⁵（k=22，本文） | 1 | [6][11]、第 4 节 |
| 结构感知（树路径） | n | h | 0 | 1 | [26] |

表：在"每桶一次单查询 PIR"的模型下，2× 是随机化方案的存储下限且只能以更多桶或 stash 全库查询换取；1× 只存在于结构化批量。

## 6. 时间与通信：每桶固定成本、扫描与响应的可压缩部分

这一分支回答 RQ2。文献与本仓库的阶段计时指向同一个结论：**批码只摊薄扫描，不摊薄每桶的查询处理。**

**扫描项由复制度锁定，与桶数和 dummy 无关。** 全部桶的首维扫描之和等于复制后的总明文数，本基线为 2.91 倍；dummy 桶并不额外增加扫描——若桶数减少，同样的 3n 明文只是分布到更少的桶里。因此"少 dummy"的收益只落在每桶固定成本与通信上。Angel 等人的原始数据已显示这一点：k 从 1 增到 16 时每请求 server 时间从 3.24 s 降到 0.69 s，但要到 k=256 才降到 0.08 s，因为 dummy 与固定项在小 k 时占比高 [1]。

**每桶固定成本在文献中被明确点名为批码无法摊薄的项。** Respire 直接写道：批码摊薄了线性扫描，"但不摊薄查询展开的成本，后者随批量线性增长"，并在 1 GB、T=256 时比 VBPIR 慢 2.2 倍，只在 T≤16（256 MB）或 T≤128（1 GB）时更快 [5]。本基线的数字更极端：expand+convert 占 31%，其余维折叠占 22%，二者合计超过扫描。原因是 OnionPIRv2 的每个实例除 ExpandBFV 外还要把选择位补全成 RGSW（convert），这一步在 SealPIR/Spiral 谱系里没有对应项，因此"每桶付费"在 RGSW 外积流水线上更贵。

**查询侧：打包降通信，但不降展开。** MulPIR 的 Procedure 6 把 d 个选择向量拼进 ⌈d·m/2^c⌉ 条系数编码密文、一次遗忘展开取出，这一技巧可推广到多个桶的向量 [18]；VBPIR 把 g_B 个桶的查询装进 SIMD 槽，PIRANA 让 1.5L 个桶共享同一组码字密文使查询大小与 L 无关，Respire 与 VIA 则在打包后再做单查询压缩 [2][3][5][22]。它们对通信的收益是数量级的（VBPIR 对 SealPIR-PBC 97 倍；PIRANA 在 L=256 时用 30 条查询密文替代 384 条），但对 server 时间的收益并不一致：VBPIR 的计算比 Angel-PBC 高 1.1–1.6 倍，PIRANA 用密文-密文乘换取常数查询大小、单查询慢 SimplePIR 94.8 倍 [2][3]。机理上，ExpandBFV 的开销正比于输出槽位数，把 33 个桶的向量并入一条密文只是把 33 棵小展开树合成一棵大树，Galois 密钥切换的总数基本不变；能省下的是 33 次独立的密钥切换准备与 RGSW 补全里的重复部分。本仓库的 tree MVP 提供了一个同机对照：一次性展开 23 层选择位的 unpack 为 119 ms，而 cuckoo 33 个实例的 expand+convert 为 1,102 ms——但两者选择位数不同，只能提示（而非证明）合并展开对本流水线的收益在 2–5 倍之间。

**响应侧：重打包与遗忘压缩是最成熟、最可移植的部分。** 每桶一条完整响应密文（11,264 B）只承载 32 B 有用节点，其余是 95 个无关节点与 dummy。三类技术可用：（i）LWE/RLWE 重打包——CDKS 的自同构打包把 d 条 LWE 打成 1 条 RLWE [19]，YPIR 用它把 8 GB 库的 16 MB DoublePIR 响应压到 12 KB、打包固定开销 39 ms、密钥 462 KB [20]，InsPIRe 的 InspiRING 把密钥降到 60–84 KB 并快 28% [21]，Respire 用旋转+Frobenius 投影把 d₂/d₃ 个桶响应合并成 1 条 RLWE 再环切换 [5]，VIA 的 MLWEs-to-RLWE 重打包把噪声方差从 Respire 的二次降到对数，对 1 字节记录实现 127 倍的响应缩减 [22]；（ii）遗忘密文压缩——BPSY24 用随机带状线性系统把 1.5ℓ 条响应（其中 0.5ℓ 为零加密）压到 1.05ℓ，实测响应 −30%、请求 −20–24%、server 时间 +6–8% [4]，Giorgi 等人把压缩后长度从 t(1+ε) 降到最优 t 并去掉失败概率 [23]，Gao 等人用三 hash garbled cuckoo table 再削 27% 的额外通信 [24]；（iii）模数切换——VBPIR 从 200 位切到 30 位获得 4 倍，MulPIR 获得 2.4 倍 [2][18]。对本基线而言，(i) 与本仓库 tree MVP 的 X^z 打包同源：33 条响应中的 22 个有用节点（704 B）可打进 1 条密文，通信从 372 KB 降到约 11 KB，dummy 响应随之消失；代价是 Galois 密钥与每桶几毫秒的打包，按 YPIR/InsPIRe 的数据这是总时间的 1–3%。

**dummy 桶的真实代价。** BPSY24 把它表述为"1.5ℓ 次 PIR 执行、请求与响应各比朴素多 50%" [4]；本基线中它对应 1/3 的通信与约 10% 的 server 时间（固定成本部分）。没有任何已核实方案跳过 dummy 桶的扫描——隐私要求 server 对每个桶做同样的工作——能做的只是压掉它们的响应（[4][23]）与用更多 hash 减少桶数（[6]）。

| 方案 | 哈希层 | 查询侧 | 响应侧 | 对 VBPIR/PBC 的通信 | 对 VBPIR/PBC 的计算 | 条件 |
|---|---|---|---|---|---|---|
| SealPIR-PBC [1] | 3n/1.5k | 每桶独立展开 | 每桶 1 条 | 基准（122.8 MB，k=256，288 B） | 基准 | — |
| VBPIR [2] | 同上 | SIMD 打包 | rotate-and-sum 合并 + 模切换 | 97× 更小 | 1.1–1.6× 更慢 | 记录 ≤~1 KB |
| PIRANA [3] | 同上 | 全部桶共享码字 | 按槽分桶 | 查询与 L 无关 | 数百–数千查询时 ≤14.4× 更快 | 单查询延迟差 |
| BPSY24 [4] | 同上 | 请求 1.5→1.05 | 响应 1.5→1.05 | −30% 响应 | +6–8% | 大记录 |
| Respire-B [5] | 同上（B≥3T/2） | 单查询压缩 | 重打包 + 环切换 + 向量化 | 3.4–7.1× 更小 | T≤16–128 更快，否则 2.2× 更慢 | 小批量 |
| VIA-B [22] | 无批码 | LWE→RLWE 压缩 | 对数噪声重打包 | 响应 127×（1 B 记录） | 无扫描摊销 | — |
| Npir_b [25] | 无批码 | — | NTRU 打包 | 响应 6–521× 更小 | T=8 快 1.4–5.5×，T=32 输给 PIRANA | 数十 KB 记录 |

表：在同一哈希层上，通信可以压掉 1–2 个数量级，但 server 时间的改善不超过常数且常为负；2025–2026 年的新方案干脆放弃批码。

## 7. 结构：当批量是一条树路径时

这一分支回答 RQ3。检索到的唯一严格对照实验只指向一个方向。

**TreePIR（Cao、Dau 等，IEEE S&P 2025）**对静态满二叉树做"平衡祖先染色"：h 种颜色，每条根到叶路径恰好经过每种颜色一次，各色类大小为 ⌊N/h⌋ 或 ⌈N/h⌉；每色一个子库、一次 PIR、零复制。与 PBC（w=3、1.5h 个桶、3N 存储、子库 2N/h、客户端 Ω(N) 索引）在 SealPIR、Spiral、VBPIR 后端上的对照：总存储 3 倍更低（h=24 时 1,074 对 3,227 MB），通信 1.5 倍更低（VBPIR 因查询打包而持平），server 计算 1.5–2 倍更快（h=20：SealPIR 1,250 对 2,916 ms；Spiral 663 对 1,151 ms），setup 快 8–60 倍，索引快 19–160 倍 [26]。作者特别指出，最自然的"按层分区"也是祖先染色但**不平衡**（叶层占 N/2 节点），并因此未采用；他们也否决了 h 份整树复制的方案。本仓库的 layerwise 基线正是这个未被 TreePIR 测量的按层分区，tree MVP 则是把 h 次查询进一步合并为一次的单查询方案。

**本仓库的实测与 TreePIR 独立收敛。** 同一台机器、同一 256 MB 树上，cuckoo 对 layerwise 的比值是存储 2.91×、server 时间 3.46×、通信 1.50×；TreePIR 报告的 PBC 对平衡染色比值是 3×、1.5–2×、1.5×。存储与通信两项几乎逐项吻合，时间差距本仓库更大，原因即第 6 节所述：OnionPIRv2 每实例多一道 RGSW 补全，且小桶的首维核效率下降。这是两套彼此独立的实现（不同后端、不同硬件、不同作者）在三个轴上给出同向且量级一致的结果，按证据强度可以说：**对 Merkle 路径批量，结构感知分区优于 PBC 是已被表明的，而非单一研究的提示。**

**更早的 CT 隐私工作从未使用逐层 PIR。** Lueks–Goldberg 把每个叶的整条路径存成一条 32h 字节记录，用 Strassen 式批矩阵乘在跨客户端之间摊销 [27]；Kales 等人把树分层为多级子树，底层子树的证明静态地随 SCT 下发，只对顶层用两服务器 DPF PIR 取回，2³¹ 证书时总开销低于 9 ms [28]；Meiklejohn 等人的 SoK 把这两者与 Checklist 列为 PIR 路线，并指出部署障碍在于证书必须携带其索引且需要两个同步的日志副本 [29]。Qin 等人对比特币轻客户端按时间分区数据库以缩小扫描范围，但 Merkle 数据库的记录是整块交易列表、由客户端自算根 [30]；Colombo 等人的 Authenticated PIR 则把整条包含证明附在每条记录上、随记录一并取回，是"路径随叶存储"的另一种形态 [31]。信息论一侧，Issa–Heidarzadeh 的"结构化子集检索"是最接近"带公开访问结构的 PIR"的形式化，但只处理连续子集族，未涉及树路径 [32]。**注意误归档**：Lazzaretti–Papamanthou 的 TreePIR（CRYPTO 2023）是两服务器客户端预处理 PIR，"Tree"指其 GGM PRF 树，与树结构数据无关 [33]。

**检索为空的方向**：没有工作显示通用批码在树路径上胜过结构感知检索；没有单服务器上"朴素按层分区"对"平衡染色"或对 PBC 的实测；没有对生长/稀疏树的结构感知方案（TreePIR 将其列为开放问题）；密钥透明度、DNSSEC 链、以太坊 MPT 的逐层 PIR 检索均无命中。

## 8. 批评与边界：下界、方法学与"不用批码"的趋势

这一分支为前三节的判断划定条件。

**批处理不能绕过预处理下界。** Yeo 证明带私有预处理的（批）PIR 满足 tr=Ω(nk)（k≤r≤n/400），即批处理在客户端提示之上不再带来额外节省 [34]；Corrigan-Gibbs–Henzinger–Kogan 给出 ST+QT=Ω̃(n) 并指出批 PIR 强迫查询非自适应 [35]；Hoover–Persiano–Yeo 进一步表明 s 位客户端存储下，一次 k=Θ(s) 的批查询的摊销在线通信或 server 密码学位操作至少为 Ω(n/s) [36]。这些结果把批码的收益限定在"线性扫描的常数因子"之内：Piano 指出需要 O(√n) 个并行查询才能追平其摊销时间，且仍是 O(n) 的 HE 工作 [37]；SimplePIR/DoublePIR 与 YPIR 展示的"跨客户端批处理"（单次扫描服务多个客户端、k=4 时 1.3–1.4 倍有效吞吐）与 PBC 是不同的模型，且只有首层扫描受益 [38][20]。Distributional PIR 则从另一侧松动前提：允许按流行度分布只取回 24 条中平均 19 条推文时，对现有 batch PIR 的 server 工作降低 5–77 倍、通信 2–117 倍 [39]——说明当正确性可以放松时，批码的固定成本可以整体绕开。

**失败率与隐私。** 2026 年的教程明确指出 cuckoo 失败"视实现可能影响正确性或隐私" [40]：Angel 等人列出的三种处理（更换索引、只取子集、静默失败）都要求处理方式不泄露信息 [1]；VBPIR 建议以相同概率发送 dummy 查询 [2]；Yeo 指出 hash 公开且可复用时，对抗性选择的查询集可以被构造成高概率失败，鲁棒 PBC 的代价是 O(log λ) 的码率 [6]。本基线的"失败即抛异常"在单次实验中只是正确性问题，但若作为服务部署，失败后的行为差异就是一个可观测事件。

**方法学口径。** 批 PIR 论文普遍只报告请求+响应字节，把数 MB 的密钥与公共参数算作一次性（VBPIR 9.34 MB，Respire 4.6 MB，VIA-B 14.8 MB）且常不报告（Respire 指出 VBPIR 的参考实现未报告其公共参数大小）[2][5][22]；桶索引元数据不计入通信（[1][2][26]）；基线常为作者自行重实现（PIRANA 重实现 VBPIR）[3]；LWE 一系要么跨客户端摊销、要么在对比表中干脆不列批 PIR（FrodoPIR 明言"不含批 PIR 方案"）[43][20]。因此跨论文的"摊销每查询成本"不可直接比较，本文的所有横向数字都取自同一论文内的同机对照。

**放弃批码的新趋势。** VIA-B 与 Npir_b 都不再使用 PBC：前者对每个查询单独压缩、server 时间随 T·N 线性、以对数噪声重打包换取 1 字节记录下 127 倍的响应缩减 [22]；后者为实现简单省去批码，在 T=8、32 KB 记录时比 VBPIR/PIRANA 快 1.4–5.5 倍，到 T=32 输给 PIRANA [25]。BitBatSPIR 从 PSI 重新推导批处理，以 1.02–1.48 倍的 LAN 时延换取对称隐私与约一半的在线通信 [42]；Bridging 一文在客户端预处理模型里用 MPHF 与"Rewind & Skip"实现无 cuckoo 的批处理，但要求索引独立随机且预处理代价可观 [41]。这些工作共同说明：**当记录小、批量小或结构已知时，"每桶一个 PIR 实例"的框架并不是默认最优。**

## 9. 综合讨论

三个分支汇合到一个判断：cuckoo batch PIR 的成本结构是"复制度 × 扫描 + 桶数 × 固定成本 + 桶数 × 响应"，三项分别由哈希层、实例框架与响应层决定，而文献四十余篇的努力几乎全部落在第三项。第一项有理论天花板（第 5 节），第二项被 Respire 与本仓库的阶段计时同时判定为不可被批码摊薄（第 6 节），第三项可以被压到接近最优（[4][23]）。这解释了一个表面矛盾：为什么通信改善动辄两个数量级而 server 时间从未改善超过常数，以及为什么 2025–2026 年的新方案宁可放弃批码。

第二个跨分支张力在"小批量"。第 4 节的失败率模拟、Angel 的 k>200 限定、VBPIR 的 k=32 让步与 Respire 的 T≤16–128 交叉点指向同一事实：PBC 的参数与收益都是为 k 在数百量级设计的；本工作负载的 k=22–27 恰在其舒适区之外——失败率高、dummy 占比高、每桶固定成本占比高。而 Merkle 路径的 k 由树高决定，不可能被拉大到 PBC 的舒适区。

第三个张力在"通用 vs 结构"。TreePIR 与本仓库的独立收敛（第 7 节）表明，对树路径批量，结构感知分区在所有轴上占优；但 TreePIR 的优势依赖平衡染色与静态满树，本仓库的 tree MVP 进一步把 h 次查询合并为一次并把通信压到 26 KB，二者都还没有处理生长树。通用批码保留的唯一论据是"任意批量"——这对本论文的比较是关键：cuckoo 基线的角色不是"能被优化到与 tree 持平的竞争者"，而是"通用方法在结构化任务上的代价刻度"。

方法学上的共同弱点：所有系统论文的失败率都来自同一个经验估计的转引；跨论文摊销数字口径不一；本仓库的 cuckoo 数据只在一台笔记本上测得且抖动 8–13%。

## 10. 开放问题

1. **小批量 PBC 的参数校准是空白。** 分类法中"失败率 × 哈希层"一格只有理论（[6]）与大 k 经验（[1][2]）；据检索结果，没有工作给出 k<64 时 (w, B) 与失败率的实测表。第 4 节的模拟是第一份，但仅覆盖本实现的驱逐策略；把 Yeo 的多 hash 方案与更大 B 在真实 PIR 成本（存储 w×、固定成本 B×）下做帕累托刻画是直接可做的实验。
2. **RGSW 流水线上的查询侧合并未被量化。** 第 6 节只能给出 2–5 倍的区间提示。一个决定性实验是把 33 个桶的选择位装进一条查询（本仓库 tree 查询打包已具备机制）并测量 expand+convert 的变化——这将回答"固定成本中多少是可共享的密钥切换、多少是不可共享的 RGSW 补全"。
3. **"朴素按层分区"对"平衡染色"的差距未被测量。** TreePIR 只说前者不平衡；本仓库的 layerwise 恰是前者，而叶层 N/2 的最大子库是否真的主导延迟，取决于 PIR 成本是否线性——在 OnionPIRv2 上做一次平衡染色版 layerwise 即可闭合这一格。
4. **响应打包在小记录树路径上的极限。** 本仓库 tree MVP 已把 23 层打进一条密文并用 d=2 环切换减半；VIA 的对数噪声重打包提示 1 字节量级记录还有 100 倍空间，但它放弃了扫描摊销——两者能否结合是开放的。
5. **生长树与稀疏树。** TreePIR 与本仓库都假设静态满树；Kales 等人的分层方案是目前唯一处理生长日志的实用答案，但它是两服务器的。单服务器、可增量的结构感知路径检索，据检索结果尚无工作。
6. **失败处理的隐私形式化。** 教程指出失败可能泄露 [40]，Yeo 给出鲁棒 PBC [6]，但没有工作给出单服务器批 PIR 下"失败-重试"策略的严格隐私定义与开销。

## 11. 结论

**RQ1（空间）。** 3 倍复制不是理论最优但接近工程最优：确定性批码在实用规模下要求复制度趋近 k [8][9]，随机化方案的存储下限是 2×（w=2），而 2-hash 在本工作负载的 k 下无 stash 时失败率达 5–9%，加 stash 的每一项都是一次全库单查询 [14][16]；更多 hash 是理论上最便宜的失败率杠杆 [6] 但把存储推向 4–5×。因此对本基线而言，空间上值得做的不是降复制，而是（a）把桶数从 1.5k 提到约 2k 以把失败率从 2⁻¹¹ 压到可接受水平——代价是每桶固定成本与通信增加 1/3——或（b）改用 w=4 以 4× 存储换零失败；真正的 1× 只有结构感知分区能给 [26]。

**RQ2（时间与通信）。** 本基线的 server 时间 46% 是由 2.91 倍复制锁定的扫描、31% 是 33 次查询展开与 RGSW 补全、22% 是小桶的其余维折叠；文献一致表明批码只摊薄扫描 [1][5]。可移植且证据充分的优化按收益排序：响应侧重打包与 dummy 响应压缩（通信 372 KB→约 11 KB，时间 +1–3%）[4][5][19][20][21]；查询侧合并展开（通信 491 KB→约 15 KB，时间收益待测，提示为 2–5 倍于 unpack 项）[18]；桶数校准（见 RQ1）。总通信可从 863 KB 降到约 30 KB，与 tree MVP 同量级；但 server 时间的可压缩部分只在 10–25% 之间，扫描项无法低于 layerwise 的 2.9 倍。

**RQ3（结构）。** 对 Merkle 路径，通用 cuckoo 批处理在存储、计算、通信三个轴上都被结构感知方案占优，本仓库的实测（2.91×、3.46×、1.50×）与 TreePIR 的独立对照（3×、1.5–2×、1.5×）同向且量级一致，检索范围内没有反例 [26]。因此 cuckoo 基线不值得作为"待追平的竞争者"继续优化；它应当在完成上述通信侧优化（使对比不因通信口径失真）与失败率修正（使其正确性与其他基线对等）之后，作为"通用批处理在结构化任务上的代价刻度"固定下来。

本文的贡献是把批码的组合理论、cuckoo hashing 的参数理论与 batch PIR 系统文献接到同一张账目上，并用本仓库的分阶段计时与失败率模拟校准：它暴露了文献沿用的 2⁻⁴⁰ 在小批量下不成立这一未被量化的缺口，指出 server 时间中不可被批码摊薄的固定成本在 RGSW 流水线上比在 SealPIR/Spiral 谱系里更重，并用两套独立实现的收敛把"结构感知优于通用批码"从单篇论文的结果提升为有条件的既定事实。

## 参考文献

[1] S. Angel, H. Chen, K. Laine, S. Setty, "PIR with compressed queries and amortized query processing," IEEE S&P, 2018.
[2] M. H. Mughees, L. Ren, "Vectorized batch private information retrieval," IEEE S&P, 2023.
[3] J. Liu, J. Li, D. Wu, K. Ren, "PIRANA: Faster multi-query PIR via constant-weight codes," IEEE S&P, 2024.
[4] A. Bienstock, S. Patel, J. Y. Seo, K. Yeo, "Batch PIR and labeled PSI with oblivious ciphertext compression," USENIX Security, 2024.
[5] A. Burton, S. Menon, D. J. Wu, "Respire: High-rate PIR for databases with small records," ACM CCS, 2024.
[6] K. Yeo, "Cuckoo hashing in cryptography: Optimal parameters, robustness and applications," CRYPTO, 2023.
[7] Y. Ishai, E. Kushilevitz, R. Ostrovsky, A. Sahai, "Batch codes and their applications," STOC, 2004.
[8] M. B. Paterson, D. R. Stinson, R. Wei, "Combinatorial batch codes," Advances in Mathematics of Communications, 2009.
[9] N. Balachandran, S. Bhattacharya, "On an extremal hypergraph problem related to combinatorial batch codes," arXiv:1206.1996, 2012.
[10] H. Asi, E. Yaakobi, "Nearly optimal constructions of PIR and batch codes," IEEE ISIT, 2017.
[11] M. Dietzfelbinger, A. Goerdt, M. Mitzenmacher, et al., "Tight thresholds for cuckoo hashing via XORSAT," ICALP, 2010.
[12] N. Fountoulakis, K. Panagiotou, "Sharp load thresholds for cuckoo hashing," arXiv:0910.5147, 2009.
[13] S. Walzer, "Load thresholds for cuckoo hashing with overlapping blocks," ICALP, 2018.
[14] A. Kirsch, M. Mitzenmacher, U. Wieder, "More robust hashing: Cuckoo hashing with a stash," SIAM Journal on Computing, 2009.
[15] B. Minaud, C. Papamanthou, "Generalized cuckoo hashing with a stash, revisited," arXiv:2010.01890, 2020.
[16] D. Demmler, P. Rindal, M. Rosulek, N. Trieu, "PIR-PSI: Scaling private contact discovery," PoPETs, 2018.
[17] B. Pinkas, T. Schneider, C. Weinert, U. Wieder, "Efficient circuit-based PSI via cuckoo hashing," EUROCRYPT, 2018.
[18] A. Ali, T. Lepoint, S. Patel, et al., "Communication–computation trade-offs in PIR," USENIX Security, 2021.
[19] H. Chen, W. Dai, M. Kim, Y. Song, "Efficient homomorphic conversion between (ring) LWE ciphertexts," ACNS, 2021.
[20] S. Menon, D. J. Wu, "YPIR: High-throughput single-server PIR with silent preprocessing," USENIX Security, 2024.
[21] R. A. Mahdavi, S. Patel, J. Y. Seo, K. Yeo, "InsPIRe," IEEE S&P, 2026.
[22] Y. Liu, X. Wang, Y. Zhang, "VIA: Communication-efficient single-server PIR," IEEE S&P, 2026.
[23] P. Giorgi, B. Grenet, M. Simkin, "Oblivious ciphertext compression via linear codes," EUROCRYPT, 2026.
[24] Gao, Zheng, Wang, Zhou, "GPU-accelerated batch PIR with lower communication overheads," Cybersecurity, 2026.
[25] Lin, Wang, Wang, Chen, "Npir: High-rate PIR for databases with moderate-size records," IACR ePrint 2025/2257, 2025.
[26] Q. Cao, S. H. Dau, R. Gagiano, et al., "TreePIR: Efficient private retrieval of Merkle proofs via tree colorings with fast indexing and zero storage overhead," IEEE S&P, 2025.
[27] W. Lueks, I. Goldberg, "Sublinear scaling for multi-client private information retrieval," Financial Cryptography, 2015.
[28] D. Kales, O. Omolola, S. Ramacher, "Revisiting user privacy for certificate transparency," IEEE EuroS&P, 2019.
[29] S. Meiklejohn, J. DeBlasio, D. O'Brien, et al., "SoK: SCT auditing in certificate transparency," PoPETs, 2022.
[30] K. Qin, H. Hadass, A. Gervais, J. Reardon, "Applying private information retrieval to lightweight Bitcoin clients," IEEE CVCBT, 2019.
[31] S. Colombo, K. Nikitin, H. Corrigan-Gibbs, D. J. Wu, B. Ford, "Authenticated private information retrieval," USENIX Security, 2023.
[32] Issa, Heidarzadeh, "Private structured-subset retrieval," arXiv:2605.05160, 2026.
[33] A. Lazzaretti, C. Papamanthou, "TreePIR: Sublinear-time and polylog-bandwidth private information retrieval from DDH," CRYPTO, 2023.
[34] K. Yeo, "Lower bounds for (batch) PIR with private preprocessing," EUROCRYPT, 2023.
[35] H. Corrigan-Gibbs, A. Henzinger, D. Kogan, "Single-server private information retrieval with sublinear amortized time," EUROCRYPT, 2022.
[36] A. Hoover, G. Persiano, K. Yeo, "Lower bounds for PIR with preprocessing from blackbox cryptography," FOCS, 2026.
[37] M. Zhou, A. Park, W. Zheng, E. Shi, "Piano: Extremely simple, single-server PIR with sublinear server computation," IEEE S&P, 2024.
[38] A. Henzinger, M. M. Hong, H. Corrigan-Gibbs, et al., "One server for the price of two: Simple and fast single-server private information retrieval," USENIX Security, 2023.
[39] R. Lehmkuhl, A. Henzinger, H. Corrigan-Gibbs, "Distributional private information retrieval," USENIX Security, 2025.
[40] Arunachalaramanan, Chen, Ren, "Private information retrieval: A tutorial and survey," IACR ePrint 2026/1135, 2026.
[41] Liang, Yu, Xu, et al., "Bridging keyword PIR and index PIR via MPHF and batch PIR," IACR ePrint 2025/2252, 2026.
[42] Li, Peng, Liu, et al., "BitBatSPIR: Efficient batch symmetric PIR from PSI," IEEE TDSC, 2025.
[43] A. Davidson, G. Pestana, S. Celi, "FrodoPIR: Simple, scalable, single-server private information retrieval," PoPETs, 2023.

（未在正文引用但经核实、供延伸阅读：Fotakis–Pagh–Sanders–Spirakis 的 d-ary cuckoo hashing（Theory Comput. Syst. 2005）；Azar–Broder–Karlin–Upfal 的 balanced allocations（SIAM J. Comput. 1999）；Groth–Kiayias–Lipmaa 的常数通信率多查询 CPIR（PKC 2010）。）
