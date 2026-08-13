# OnionPIRv2 Core Comments Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 OnionPIRv2 的 Algorithm 1–4 核心路径和必要底层密码代码增加中文教学注释，同时保持 executable tokens、接口、布局和行为不变。

**Architecture:** 注释按论文执行链分层：参数与对象模型 → QueryPack → ExpandBFV → QueryUnpack → 首维矩阵乘 → 高维 MUX → ModSwitch/解密。每个关键 block 解释论文对应、输入输出、domain/layout、数学等价性和工程不变量；普通控制流不做逐行翻译。

**Tech Stack:** C++20、BFV/RLWE、RGSW、RNS/CRT、Intel HEXL NTT、CMake、仓库内测试 dispatcher。

---

## 工作区约束

开始实施时，工作区已知包含用户自己的改动：

```text
M CMakeLists.txt
M src/tests/test_hexl_ntt.cpp
?? docs/ONIONPIRV2_READING_GUIDE_ZH.md
```

实施者不得覆盖、暂存或提交这些改动。每次 `git add` 都必须列出确切文件，禁止使用 `git add .` 或 `git add -A`。

源码 comments-only 审计使用固定基线 commit `cf07dd5`。该 commit 只加入本任务设计文档，核心源码仍与实施前一致；即使后续按任务分别提交注释，也始终用它比较全部源码。

所有源码修改必须满足：

```text
允许：新增/修订 //、/* ... */、Doxygen 注释，以及保持注释排版所需的空白
禁止：修改 identifier、literal、operator、preprocessor directive、type、函数签名或控制流
```

## 文件责任图

| 层次 | 文件 | 责任 |
|---|---|---|
| 参数/shape | `src/includes/database_constants.h`, `src/includes/pir.h`, `src/pir.cpp` | 论文参数、三类 gadget length、RNS/composite、query capacity、DB shape |
| RLWE/util | `src/includes/rlwe.h`, `src/rlwe.cpp`, `src/includes/utils.h`, `src/utils.cpp` | ciphertext layout、BFV scale、domain transition、automorphism、NTT、gadget、rescale |
| Algorithm 1 | `src/includes/client.h`, `src/client.cpp` | index coordinates、one-hot、gadget-row packing |
| Algorithm 2 | `src/includes/server.h`, `src/server.cpp`, `src/includes/bv_keyswitch.h`, `src/bv_keyswitch.cpp` | ExpandBFV、BV Galois key、tree pruning |
| Algorithm 3 | `src/includes/gsw.h`, `src/gsw.cpp`, `src/server.cpp` | RGSW layout/decomposition、external product、selector completion |
| Algorithm 4 首维 | `src/includes/matrix.h`, `src/matrix.cpp`, `src/server.cpp` | DB/query matrices、composite split、chunked/SIMD kernel、layout recovery |
| Algorithm 4 后半 | `src/server.cpp`, `src/client.cpp` | binary MUX、ModSwitch、wire codec、small-q decrypt、主调度 |

### Task 1: 注释参数、RNS/CRT 与数据库 shape

**Files:**
- Modify: `src/includes/database_constants.h:8-128`
- Modify: `src/includes/pir.h:9-117`
- Modify: `src/pir.cpp:11-96`

- [ ] **Step 1: 确认工作区基线并保护用户改动**

Run:

```bash
git status --short
git diff --name-only
```

Expected: 能看到 `CMakeLists.txt`、`src/tests/test_hexl_ntt.cpp` 和 `docs/`；本任务不得修改前两个文件。

- [ ] **Step 2: 在 compile-time config 上解释论文参数与三种 gadget length**

在 `namespace DBConsts` 与各 config 前加入以下语义，而不改常量：

```cpp
// [论文参数] 2025 论文评测使用 n=2048、log q≈58、log t=13、
// log q'=22、σ=2.55。run.py 默认选择 CONFIG_N2048_K1_COMP，
// 因而该 config 是阅读 Algorithm 1–4 时的主参考路径。
//
// 三个长度不能混用：
//   L_EP  : data selector 的 external-product gadget 行数；
//   L_KEY : 用 RGSW(s) 补全 selector 时的 key decomposition 行数；
//   L_KS  : ExpandBFV 中 BV key switching 的 decomposition 行数。
```

在 K=1、K=2 MP 与 composite config 附近分别说明：single-mod、真实双 limb、逻辑 composite q 的区别。

- [ ] **Step 3: 在 PirParams 上解释 runtime 参数派生与 size 口径**

在 `RnsTables`、`CompositeRnsTables` 与 `PirParams` getter group 前加入：

```cpp
// [运行期参数] DBConsts 只给 bit width 与策略；PirParams 负责生成实际
// NTT-friendly moduli、CRT tables、small_q、gadget base 和数据库 shape。
// logical DB size、physical NTT storage 和 modeled communication bytes 是
// 三种不同口径，不能用同一个 size getter 替代。
```

在 `get_BFV_size` 和 key-size helpers 上明确它们是 seed-compressed model，不是实际 query/key serializer。

- [ ] **Step 4: 注释 composite modulus 初始化**

在 `PirParams::init_composite_rns` 前加入：

```cpp
// [Composite NTT] 流水线把 q=q1*q2 当成一个 logical K=1 modulus；
// 只有首维 matrix multiplication 临时把 coefficient 投影到 q1/q2，
// 以使用 29-bit 的 32x32->64 kernel。w_crt 是在 composite q 下可用的
// 2N-th root，必须注册给 NTT wrapper；它不是普通 prime-modulus root。
```

在 DB shape 构造附近解释 `N0`、`Nrest`、`num_dims` 和 expansion capacity 的约束。

- [ ] **Step 5: 审查本任务差异**

Run:

```bash
git diff --check -- src/includes/database_constants.h src/includes/pir.h src/pir.cpp
git diff -- src/includes/database_constants.h src/includes/pir.h src/pir.cpp
```

Expected: 只有注释/空白变化；没有常量、表达式或函数体 token 变化。

- [ ] **Step 6: 提交参数注释**

```bash
git add -- src/includes/database_constants.h src/includes/pir.h src/pir.cpp
git commit -m "Explain how OnionPIRv2 parameters shape the protocol" \
  -m $'Constraint: Comments only; preserve compile-time values and runtime derivation\nConfidence: high\nScope-risk: narrow\nTested: comments-only diff and whitespace audit\nNot-tested: runtime tests deferred until all annotations are complete'
```

### Task 2: 注释 RLWE/BFV 数据模型与主链 util

**Files:**
- Modify: `src/includes/rlwe.h:12-126`
- Modify: `src/rlwe.cpp:9-359`
- Modify: `src/includes/utils.h:52-278`
- Modify: `src/utils.cpp:20-88,160-231,329-379,427-439`

- [ ] **Step 1: 注释 RLWE 类型布局**

在 `RlweCt`、`RlweSk`、`RlwePt` 前加入：

```cpp
// [核心布局] 一个 RLWE/BFV ciphertext 由 c0、c1 两个 polynomial 组成。
// 每个 polynomial 使用 limb-major 存储：
//   [q0 的 N 个 coefficients][q1 的 N 个 coefficients]...
// 不是按 coefficient 交错。ntt_form 只记录当前 domain，不会触发转换；
// 调用者必须显式执行 NTT/INTT，并保持标记与真实 buffer 一致。
```

- [ ] **Step 2: 注释 BFV encryption/decryption 的符号与 scale**

在 `encrypt_zero(_rns)`、`encrypt_bfv(_rns)`、`decrypt(_rns)` 前写明：

```cpp
// 本实现采用 c0=-(a*s+e)+Delta*m、c1=a，因此解密 phase=c0+c1*s。
// error 的符号与常见 BFV 记法可能相反，但分布对称，解密语义等价。
// Delta≈Q/t；K=2 时必须先在 composite Q 上形成一致的 scale，再把
// 同一个整数表示投影到每个 RNS limb，不能逐 limb 独立近似 Delta。
```

只在真实 domain transition 处说明输入/输出 form，不注释简单 add/sub 循环。

- [ ] **Step 3: 注释 automorphism、NTT cache、gadget 与 rescale**

分别加入以下核心说明：

```cpp
// automorphism X -> X^k 会把 ciphertext 从 secret s 变成 secret σ_k(s)；
// ExpandBFV 随后必须使用对应 BvKeySwitchKey 切回原 secret key。
```

```cpp
// NTT objects 由 function-static map 按 (N,q) 缓存。该 cache 不是
// thread_local，也没有锁；当前 benchmark 的单线程假设是其安全边界。
```

```cpp
// gsw_gadget 按 MSB-first 返回 B^(l-1-p)。QueryPack、RGSW encryption
// 与 external-product decomposition 必须使用相同 row order。
```

```cpp
// centered rescale: 先把 [0,inp_mod) 解释为以 0 为中心的代表元，再按
// out_mod/inp_mod 四舍五入。直接做 unsigned 比例缩放会破坏负噪声语义。
```

- [ ] **Step 4: 审查并提交底层注释**

Run:

```bash
git diff --check -- src/includes/rlwe.h src/rlwe.cpp src/includes/utils.h src/utils.cpp
git diff -- src/includes/rlwe.h src/rlwe.cpp src/includes/utils.h src/utils.cpp
```

Expected: 只有注释/空白变化。

Commit:

```bash
git add -- src/includes/rlwe.h src/rlwe.cpp src/includes/utils.h src/utils.cpp
git commit -m "Make RLWE domains and layouts explicit for protocol readers" \
  -m $'Constraint: Comments only; do not alter cryptographic arithmetic\nConfidence: high\nScope-risk: narrow\nTested: comments-only diff and whitespace audit\nNot-tested: runtime tests deferred until all annotations are complete'
```

### Task 3: 注释 Algorithm 1 QueryPack 与客户端坐标

**Files:**
- Modify: `src/includes/client.h:9-65`
- Modify: `src/client.cpp:18-179`

- [ ] **Step 1: 在 client API 上标明论文角色**

把 `fast_generate_query` 和 `add_gsw_to_query` 的简短注释扩展为：

```cpp
// [2025 Algorithm 1: QueryPack]
// 把首维 one-hot 位置和后续 binary selectors 的 RGSW top rows 打包进
// 一个 coefficient-form BFV ciphertext。返回值仍在 full-q 下；服务端
// 将由 ExpandBFV 恢复 N0 + L_EP*(d-1) 个 constant ciphertexts。
```

- [ ] **Step 2: 注释 index 到 ragged-tree coordinates 的映射**

在 `get_query_indices` 前解释：

```cpp
// [Algorithm 4 line 1] pt_idx 先拆为首维 col_idx 和其余维 row_idx。
// 论文把后续维度写成规则二叉 hypercube；实现允许 Nrest 不是 2 的幂，
// 因而使用 complete-but-not-perfect tree。返回值的第 0 项是 col_idx，
// 其余项按服务端归约顺序给出 selector bits；第一个 bit 专门处理最深层。
```

在 `r/sl/perfect_idx` block 旁用短注释解释最后一层 leaf 的折叠方式。

- [ ] **Step 3: 注释 one-hot 注入的等价改写**

在 `fast_generate_query` 的 encryption-zero 与 scaled injection 前加入：

```cpp
// 论文写法是“构造 packed plaintext 后 BFV encrypt”。代码先加密 0，
// 再把 Delta*(capacity^-1 mod t) 加进 c0 的 BitRev(i0) coefficient。
// BFV 对 message addition 线性，因此解密语义等价；capacity^-1 抵消
// ExpandBFV 每层 add/sub 累积出的 capacity scaling。
```

明确 K=1 直接缩放与 K=2 composite-Q 缩放的差别。

- [ ] **Step 4: 注释 RGSW gadget-row packing**

在 `add_gsw_to_query` 的 outer loops 前加入：

```cpp
// packed slots 的逻辑布局：
//   [0, N0)                         : 首维 BFV one-hot；
//   [N0+(i-1)L_EP, N0+i*L_EP)      : 第 i 个高维 selector 的 top half。
// 只有 selector bit=1 时才注入 gadget powers；bit=0 保持 encryption of 0。
// 每个位置先 BitRev，再乘 capacity^-1，确保展开后的 row 恢复目标 gadget。
```

- [ ] **Step 5: 审查并提交 Algorithm 1 注释**

Run:

```bash
git diff --check -- src/includes/client.h src/client.cpp
git diff -- src/includes/client.h src/client.cpp
```

Commit:

```bash
git add -- src/includes/client.h src/client.cpp
git commit -m "Trace Algorithm 1 from index coordinates to one packed BFV" \
  -m $'Constraint: Comments only; preserve query distribution and packing order\nConfidence: high\nScope-risk: narrow\nTested: comments-only diff and whitespace audit\nNot-tested: fast_expand and PIR tests deferred to final verification'
```

### Task 4: 注释 Algorithm 2 ExpandBFV 与 BV key switching

**Files:**
- Modify: `src/includes/server.h:63-101`
- Modify: `src/server.cpp:612-690`
- Modify: `src/includes/bv_keyswitch.h:10-103`
- Modify: `src/bv_keyswitch.cpp:20-100,222-279,289-492`

- [ ] **Step 1: 扩展 BV module contract**

在已有 BV header 总览中补充 Algorithm 2 语境：

```cpp
// [Algorithm 2 中的 Subs]
// ring automorphism 先把 (c0,c1) 变为 (σ_k(c0),σ_k(c1))，此时密文位于
// transformed secret σ_k(s) 下。BvKeySwitchKey 加密 σ_k(s)*B^i，并将
// transformed c1 的 signed gadget digits 乘入这些 rows，使结果回到 s 下。
```

明确 `BvRlweCt.a/b` 与主路径 `RlweCt.c1/c0` 的对应关系，以及 rows 的 NTT/limb-major layout。

- [ ] **Step 2: 注释 K=1/K=2 signed decomposition 与 apply path**

在 `bv_apply_galois_inplace` dispatcher 及其 K=1/K=2 implementation 前写明：

```cpp
// K=1: 每个 coefficient 在 q 下居中后分解；digits 转 NTT，与 key rows
// pointwise multiply-accumulate，再 INTT 回 coefficient form。
// K=2: 先 CRT-compose 到 Q=q0*q1 做一次统一 signed decomposition，随后把
// 同一 signed digit 分别编码到两个 limbs；不能对每个 limb 独立分解。
```

- [ ] **Step 3: 注释 fast_expand_qry 的 heap、scale 与 pruning**

在函数入口加入：

```cpp
// [2025 Algorithm 2: ExpandBFV]
// 输入：一个 coefficient-form、K-limb、full-q packed BFV。
// 输出：前 u=N0+L_EP*(d-1) 个 constant BFV ciphertexts。
// 实现用 1-based binary heap 保存 expansion tree：每个 internal node 执行
// automorphism+BV key switch，再通过 add/sub 和 negacyclic shift 生成 children。
// 客户端的 BitRev 与这里的 leaf 顺序互为配套；任一侧顺序改变都会静默
// 选择错误 slot。right-of-u subtrees 不会产生有效输出，因此直接剪枝。
```

在 `galois_k`、`left_leaf` 和 leaf slice 处补充短注释，不翻译 local lambda。

- [ ] **Step 4: 审查并提交 Algorithm 2 注释**

Run:

```bash
git diff --check -- src/includes/server.h src/server.cpp src/includes/bv_keyswitch.h src/bv_keyswitch.cpp
git diff -- src/includes/server.h src/server.cpp src/includes/bv_keyswitch.h src/bv_keyswitch.cpp
```

Commit:

```bash
git add -- src/includes/server.h src/server.cpp src/includes/bv_keyswitch.h src/bv_keyswitch.cpp
git commit -m "Expose the automorphism and key-switch invariants in ExpandBFV" \
  -m $'Constraint: Comments only; preserve expansion order and BV arithmetic\nConfidence: high\nScope-risk: narrow\nTested: comments-only diff and whitespace audit\nNot-tested: fast_expand and bv_ks tests deferred to final verification'
```

### Task 5: 注释 Algorithm 3、RGSW layout 与 external product

**Files:**
- Modify: `src/includes/gsw.h:7-88`
- Modify: `src/gsw.cpp:17-398`
- Modify: `src/server.cpp:720-737`

- [ ] **Step 1: 修订 GSWCt layout 和 API contract**

在 `GSWCt` 前加入：

```cpp
// [RGSW flat layout] GSWCt 是 2*l 行的 polynomial matrix；每行平铺为
// [c0 的 K*N values][c1 的 K*N values]，每个 polynomial 内部仍为 limb-major。
// external_product 把 BFV 的两个 components 分解为 2*l rows，再执行
// [1 x 2l] * [2l x 2]，输出一个 BFV/RLWE ciphertext。
```

修正 `query_to_gsw` 注释中的 `RGSW(-s)` 陈旧说法：当前 client 生成并上传的是 `RGSW(s)`。

- [ ] **Step 2: 注释 external product 的三阶段**

在 `external_product` 前加入：

```cpp
// [核心 primitive] ExternalProduct(RGSW(b), BFV(x)) ≈ BFV(b*x)。
// 1) 在 coefficient form 分解 BFV 的 c0/c1；
// 2) 把每个 digit row 转为 NTT form；
// 3) 与 RGSW matrix 做 pointwise polynomial matrix multiplication。
// 输出保持 NTT form，调用者决定何时 INTT。GSWEval scratch 会跨调用复用，
// 因而当前对象只适合仓库既定的单线程 evaluation path。
```

- [ ] **Step 3: 明确 K=1 signed 与 K=2 unsigned MP 差异**

在两种 decomposition 实现前分别写明：

```cpp
// K=1 data external product 使用 centered signed digits，可减小 digit 幅度。
```

```cpp
// K=2 data external product 先 CRT-compose，再提取 unsigned base-B digits；
// 这与 BV key switching 的 K=2 signed decomposition 是两条不同路径。
```

不得把 K=2 GSW 路径描述成论文 signed optimization 的完整实现。

- [ ] **Step 4: 注释 QueryUnpack 的 selector completion**

在 `query_to_gsw` 与 `make_query` reconstruction loop 前加入：

```cpp
// [2025 Algorithm 3: QueryUnpack]
// expanded vector 的前 N0 项直接构成 first-dimension BFV vector；之后每
// L_EP 项是一个 RGSW selector 的 top half。top rows 直接转 NTT；每个
// top row 再与 RGSW(s) 做 external product，生成对应 bottom row。
// completion key 的 decomposition 使用 L_KEY，但 selector 的最终 shape
// 仍由输入行数 L_EP 决定，即 2*L_EP rows。
```

- [ ] **Step 5: 审查并提交 Algorithm 3 注释**

Run:

```bash
git diff --check -- src/includes/gsw.h src/gsw.cpp src/server.cpp
git diff -- src/includes/gsw.h src/gsw.cpp src/server.cpp
```

Commit:

```bash
git add -- src/includes/gsw.h src/gsw.cpp src/server.cpp
git commit -m "Connect QueryUnpack to the RGSW external-product layout" \
  -m $'Constraint: Comments only; distinguish K1 signed and K2 unsigned GSW decomposition\nConfidence: high\nScope-risk: narrow\nTested: comments-only diff and whitespace audit\nNot-tested: ext_prod and PIR tests deferred to final verification'
```

### Task 6: 注释 Algorithm 4 首维 standard matrix multiplication

**Files:**
- Modify: `src/includes/matrix.h:12-100`
- Modify: `src/matrix.cpp:1-336`
- Modify: `src/server.cpp:50-508`

- [ ] **Step 1: 注释 DB preprocessing 与 coefficient-major storage**

在 `gen_data` 前补充：

```cpp
// [离线 DB preprocessing] 每个 plaintext polynomial 先转 NTT，再从
// plaintext-major 转置为 coefficient-major：固定 (limb, NTT coefficient)
// 时，所有 DB entries 连续。首维会线性扫描 DB；这种布局让 inner dot
// product 接近顺序内存访问。tile staging 避免同时保留整份 pre-NTT DB。
```

- [ ] **Step 2: 注释 matrix shape 与 query transpose**

在 `prep_query`、matrix structs 和 `evaluate_first_dim` 前统一说明：

```cpp
// 对每个 NTT level，首维计算可写为：
//   A[Nrest x N0] * B[N0 x 2] -> C[Nrest x 2]
// A 是 plaintext DB，B 是 BFV selection vector 的 c0/c1，C 是 encrypted
// candidates。level-major storage 把不同 NTT coefficients 看成互相独立的
// 小矩阵乘；prep_query 负责把 ciphertext-major query 转成该 kernel 布局。
```

- [ ] **Step 3: 注释 delayed reduction、SIMD 与 composite split**

在 `mat_mat`、dispatch 与 `level_mat_mat_32` 前加入：

```cpp
// delayed reduction 只在 accumulator 不会 overflow 的 chunk 内累加，
// 然后对 q 取模；chunk size 由 coefficient bit width 保守推导。
```

```cpp
// composite first-dim 把 logical q=q1*q2 的 NTT values 投影为两组 uint32，
// 分别执行 32x32->64 kernels，再在 inter_to_cts_composite 中 CRT-compose。
// split/compose 只存在于首维，后续 ciphertext 仍是 logical K=1 mod q。
```

明确 scalar fallback 与 AVX-512 kernel 的数学输出相同。

- [ ] **Step 4: 注释 intermediate layout recovery**

在 `inter_to_cts(_composite)` 前说明 `C[level][candidate][poly]` 到 `RlweCt[candidate].c{0,1}[level]` 的 transpose，以及 INTT 后返回 coefficient form。

- [ ] **Step 5: 审查并提交首维注释**

Run:

```bash
git diff --check -- src/includes/matrix.h src/matrix.cpp src/server.cpp
git diff -- src/includes/matrix.h src/matrix.cpp src/server.cpp
```

Commit:

```bash
git add -- src/includes/matrix.h src/matrix.cpp src/server.cpp
git commit -m "Explain why the first PIR dimension is a matrix kernel" \
  -m $'Constraint: Comments only; preserve scalar, SIMD, and composite execution paths\nConfidence: high\nScope-risk: narrow\nTested: comments-only diff and whitespace audit\nNot-tested: fst_dim and PIR tests deferred to final verification'
```

### Task 7: 注释 Algorithm 4 高维 MUX、ModSwitch、codec 与解密

**Files:**
- Modify: `src/includes/server.h:19-121`
- Modify: `src/server.cpp:510-609,712-878`
- Modify: `src/includes/client.h:44-65`
- Modify: `src/client.cpp:269-371`

- [ ] **Step 1: 注释 candidate-tree reduction**

在 `evaluate_other_dim` 前加入：

```cpp
// [Algorithm 4 lines 7-14] 首维产生 Nrest 个 encrypted candidates；每个
// RGSW bit 消去一层。规则层把前后两半配对；ragged first level 只处理
// 实际存在 sibling 的最深 leaves，未配对 candidate 原位保留。
```

- [ ] **Step 2: 注释 MUX 数学语义与 aliasing**

在 `ext_prod_mux` 前加入：

```cpp
// select(b, x_orig, y_orig) = x_orig + b*(y_orig-x_orig)。
// b=0 返回原始 x，b=1 返回原始 y。实现会原地把参数 y 改写为 y-x，
// 再复用为 external-product output；注释中的 y_orig 指调用前的值。
// external product 输出 NTT form，本函数 INTT 后才与 coefficient-form x 相加。
```

- [ ] **Step 3: 把 make_query 注释成 Algorithm 4 executable skeleton**

在五个阶段前标明：Algorithm 2 expansion、Algorithm 3 completion、lines 4–6 first dim、lines 7–14 remaining dims、line 15 ModSwitch。说明 key setup 和 response serialization 位于函数边界之外。

- [ ] **Step 4: 注释 ModSwitch 和 response codec**

在 `PirServer::mod_switch_inplace` 与 `PirServer::save_resp_to_stream` 前加入：

```cpp
// [Algorithm 4 line 15] 所有 homomorphic operations 完成后才从 full q
// centered-rescale 到 small_q。提前切换会缩小 noise headroom，并使后续
// external product 的参数不匹配。K=2 路径先 rounded-drop q1，再从 q0
// rescale；输出统一为 single-limb small-q ciphertext。
```

```cpp
// response 是仓库中真实执行的 wire codec：c0 后 c1，每个 coefficient
// 固定 small_q_width bits，LSB-first。它不提供 canonical-value validation、
// trailing-byte check、认证或完整性保护，因此只是 research prototype 格式。
```

- [ ] **Step 5: 注释 small-q load/decrypt**

在 `PirClient::load_resp_from_stream` 与 `PirClient::decrypt_mod_q` 前加入：

```cpp
// [Algorithm 4 line 16] 先按服务端相同位序还原 single-limb ciphertext，
// 再把 ternary secret 从旧 q 的 {-1 == q-1} 重编码到 small_q，计算
// phase=c0+c1*s，最后 round(phase*t/small_q) 恢复 plaintext。
```

明确 test 中 direct DB lookup 是 oracle，不属于 PIR protocol。

- [ ] **Step 6: 审查并提交 Algorithm 4 后半注释**

Run:

```bash
git diff --check -- src/includes/server.h src/server.cpp src/includes/client.h src/client.cpp
git diff -- src/includes/server.h src/server.cpp src/includes/client.h src/client.cpp
```

Commit:

```bash
git add -- src/includes/server.h src/server.cpp src/includes/client.h src/client.cpp
git commit -m "Follow Algorithm 4 through MUX, modulus switch, and decryption" \
  -m $'Constraint: Comments only; preserve aliasing, codec, and small-q behavior\nConfidence: high\nScope-risk: narrow\nTested: comments-only diff and whitespace audit\nNot-tested: mod_switch and PIR tests deferred to final verification'
```

### Task 8: 全局语义审校、comments-only 证明与运行验证

**Files:**
- Review: all files modified in Tasks 1–7
- Do not modify: `CMakeLists.txt`, `src/tests/test_hexl_ntt.cpp`

- [ ] **Step 1: 搜索语义禁区和陈旧说法**

Run:

```bash
rg -n 'RGSW\(-s\)|thread.local|所有.*signed|真实.*seed|Algorithm [1234]' \
  src/includes src/*.cpp
```

Expected:

- QueryUnpack completion key 被描述为 `RGSW(s)`；
- `thread.local` 若命中，只允许出现在“该 cache 不是 `thread_local`”这类否定性纠错中；禁止把共享的 function-static map 肯定地描述成 thread-local cache；
- K=2 GSW MP path 不被描述为 signed decomposition；
- query/key size formulas 不被描述为真实 serialization；
- Algorithm 标号与 2025 论文对应。

- [ ] **Step 2: 逐文件证明 executable token 未改变**

Run:

```bash
git diff --check cf07dd5 -- \
  src/includes/database_constants.h src/includes/pir.h src/pir.cpp \
  src/includes/rlwe.h src/rlwe.cpp src/includes/utils.h src/utils.cpp \
  src/includes/client.h src/client.cpp src/includes/server.h src/server.cpp \
  src/includes/gsw.h src/gsw.cpp \
  src/includes/bv_keyswitch.h src/bv_keyswitch.cpp \
  src/includes/matrix.h src/matrix.cpp
git diff --word-diff=porcelain cf07dd5 -- \
  src/includes/database_constants.h src/includes/pir.h src/pir.cpp \
  src/includes/rlwe.h src/rlwe.cpp src/includes/utils.h src/utils.cpp \
  src/includes/client.h src/client.cpp src/includes/server.h src/server.cpp \
  src/includes/gsw.h src/gsw.cpp \
  src/includes/bv_keyswitch.h src/bv_keyswitch.cpp \
  src/includes/matrix.h src/matrix.cpp
```

Expected: 手工审查确认所有新增/删除内容都位于 comments 或 comment-only whitespace；若发现 executable token 变化，把该 token 恢复为 `cf07dd5` 中的值后重审。

- [ ] **Step 3: 构建默认论文对齐配置**

Run:

```bash
python3 run.py -c k1_comp --build-only -j 4
```

Expected: CMake configure 与 `Onion-PIR` build 成功。若失败，先判断是否来自已存在的 CMake/HEXL 环境，而不是通过修改 build files 绕过。

- [ ] **Step 4: 运行 hard-oracle primitive tests**

Run:

```bash
./build/Onion-PIR --test barrett --experiments 1 --warmup 0
./build/Onion-PIR --test fst_dim --experiments 1 --warmup 0
./build/Onion-PIR --test ext_prod --experiments 1 --warmup 0
./build/Onion-PIR --test mod_switch --experiments 1 --warmup 0
```

Expected:

- `barrett` 退出 0，无 mismatch exception；
- `fst_dim` 输出 `Correctness check: PASS`；
- `ext_prod` 退出 0，BFV×RGSW(1/0) oracle 不抛异常；
- `mod_switch` 退出 0，decrypt/compression checks 不抛异常。

- [ ] **Step 5: 运行 query expansion 与端到端 tests**

Run:

```bash
./build/Onion-PIR --test fast_expand --experiments 1 --warmup 0
./build/Onion-PIR --test pir --experiments 1 --warmup 0
```

Expected:

- `fast_expand` 退出 0；它主要是打印型弱 oracle，必须阅读输出而不能只看 exit code；
- `pir` 输出 `Success!` 和 `Success rate: 1/1`。

- [ ] **Step 6: 最终工作区审计**

Run:

```bash
git status --short
git log --oneline -10
```

Expected: 用户原有 `CMakeLists.txt`、`src/tests/test_hexl_ntt.cpp` 与阅读指南保持原样；核心源码只含已提交的注释变化；没有 build artifacts 被提交。

- [ ] **Step 7: 记录验证结论**

最终交付应列出：

```text
1. 已注释的 Algorithm 1–4 文件与关键函数
2. 已注释的必要底层参数/RLWE/util 范围
3. comments-only 差异审计结果
4. 构建配置与各测试结果
5. 未运行或弱 oracle 的验证缺口
6. 保留且未触碰的用户已有改动
```
