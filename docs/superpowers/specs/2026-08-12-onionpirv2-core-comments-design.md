# OnionPIRv2 核心源码中文注释设计

## 目标

在不改变程序行为、接口、数据布局和性能路径的前提下，为 OnionPIRv2 的核心源码增加中文教学注释，并保留 BFV、RGSW、RLWE、NTT、RNS、QueryPack、ExpandBFV、external product、ModSwitch 等英文术语。注释应让读者能够按照 2025 OnionPIRv2 论文的 Algorithm 1 → 2 → 3 → 4 路径阅读实现，同时理解论文伪代码未表达的 domain、layout 和工程优化。

## 读者与成功标准

目标读者已经读过 OnionPIRv2 论文，但不熟悉该仓库。完成后，读者只沿源码注释即可回答：

1. 线性索引如何变成首维位置和高维 selector bits；
2. 一个 BFV ciphertext 如何同时承载 one-hot 与 RGSW gadget rows；
3. ExpandBFV 为什么需要 automorphism、BV key switching、BitRev 和 tree pruning；
4. QueryUnpack 如何从 `L_EP` 个 top rows 补全 `2*L_EP` 行 RGSW selector；
5. 首维为何能写成 standard matrix multiplication，以及 DB/query/intermediate 的布局；
6. `x + b(y-x)` 如何逐层收缩 encrypted candidates；
7. ciphertext 在 coefficient/NTT、full-q/small-q、K-limb/single-limb 之间如何变化；
8. 哪些行为来自论文算法，哪些属于实现新增的性能或内存优化。

## 注释原则

### 1. 注释解释“为什么”和“不变量”

不逐行翻译 C++。普通循环、容器初始化、日志和显然的赋值不增加注释。注释集中解释：

- 与论文 Algorithm/line 的对应关系；
- 输入输出的数学对象；
- coefficient/NTT form、modulus 与 RNS limb layout；
- 等价改写的理由；
- 会导致 silent wrong result 的顺序、stride、scaling 与 ownership 不变量；
- 论文没有规定、但实现为性能或内存加入的机制。

### 2. 使用统一块结构

关键函数入口使用以下字段的适当子集，不强制每个短 helper 填满所有字段：

```cpp
// [论文对应] 2025 Algorithm 2: ExpandBFV
// [输入/输出] packed BFV -> u 个 constant BFV ciphertexts
// [数域/布局] coefficient form, K-limb, full q
// [算法语义] automorphism + BV key switching + add/sub + shift
// [工程实现] 1-based heap，并剪掉不产生有效 leaf 的子树
// [关键不变量] leaf 顺序必须与客户端 BitRev packing 一致
```

函数内部只在 domain transition、layout transpose、数学等价变换或特殊边界处增加短注释。

### 3. 中文为主，保留标准英文术语

- 使用“密文”“明文”“首维”等中文叙述；
- 保留 ciphertext、coefficient form、NTT form、limb、selector、gadget row、external product 等项目中高频术语；
- 公式和标识符保持与论文/源码一致，例如 `N0`、`Nrest`、`L_EP`、`x+b(y-x)`；
- 不翻译函数名、类型名和配置名。

## 修改范围

### A. 论文算法主线

| 文件 | 注释重点 |
|---|---|
| `src/includes/client.h`, `src/client.cpp` | `get_query_indices`、`fast_generate_query`、`add_gsw_to_query`、response load、`decrypt_mod_q`；Algorithm 4 line 1、Algorithm 1、Algorithm 4 line 16 |
| `src/includes/server.h`, `src/server.cpp` | DB preprocessing、`fast_expand_qry`、QueryUnpack orchestration、`evaluate_first_dim`、`evaluate_other_dim`、`ext_prod_mux`、ModSwitch、response codec、`make_query`；Algorithm 2–4 |
| `src/includes/gsw.h`, `src/gsw.cpp` | `GSWCt` layout、K=1/K=2 decomposition、`external_product`、`query_to_gsw`、`plain_to_gsw` |
| `src/includes/bv_keyswitch.h`, `src/bv_keyswitch.cpp` | BV evaluation-key layout、signed decomposition、key generation、K=1/K=2 apply paths、automorphism 后为何必须 key-switch |
| `src/includes/matrix.h`, `src/matrix.cpp` | matrix shapes、level-major storage、chunked reduction、scalar/SIMD/composite dispatch、32×32→64 kernel 的范围与不变量 |

### B. 必要的底层密码与参数代码

| 文件 | 注释重点 |
|---|---|
| `src/includes/database_constants.h` | 2025 默认参数对应关系；`L_EP`、`L_KEY`、`L_KS` 的不同职责；K=1、K=2 MP、composite first-dim 的边界 |
| `src/includes/pir.h`, `src/pir.cpp` | runtime primes/CRT tables、DB shape、query capacity、logical/physical size，以及 composite modulus 初始化 |
| `src/includes/rlwe.h`, `src/rlwe.cpp` | `RlweCt/RlweSk` limb-major layout、BFV scale、encrypt/decrypt sign convention、coefficient/NTT transition、K=1/K=2 语义 |
| `src/includes/utils.h`, `src/utils.cpp` | 仅覆盖主链调用的 BitRev、automorphism、NTT wrapper/cache、gadget construction、centered rescale、DB shape 与 composite-root registration |

不修改 logging、测试、build scripts、通用打印工具或与主链无关的算术 helper。

## 论文算法到注释位置的路径

```text
Algorithm 4 line 1
  client.cpp::get_query_indices

Algorithm 1 QueryPack
  client.cpp::fast_generate_query
  client.cpp::add_gsw_to_query

Algorithm 2 ExpandBFV
  server.cpp::fast_expand_qry
  utils.cpp::automorphism_coeff
  bv_keyswitch.cpp::bv_apply_galois_inplace

Algorithm 3 QueryUnpack
  server.cpp::make_query (selector reconstruction)
  gsw.cpp::query_to_gsw

Algorithm 4 lines 4-6
  server.cpp::prep_query / evaluate_first_dim / inter_to_cts
  matrix.cpp::level_mat_mat / level_mat_mat_32

Algorithm 4 lines 7-14
  server.cpp::evaluate_other_dim / ext_prod_mux
  gsw.cpp::external_product

Algorithm 4 lines 15-16
  server.cpp::mod_switch_inplace / save_resp_to_stream
  client.cpp::load_resp_from_stream / decrypt_mod_q
```

2021 论文只用于标明 `DecompPlain/DecompEncrypt/DecompMul` 等被 2025 设计替代的祖先步骤；不加入 stateful primitive 注释。

## 关键语义边界

1. `L_EP` 决定 data selector 的行数；`L_KEY` 决定用 RGSW(s) 补全 selector 时的 decomposition；`L_KS` 决定 BV key switching decomposition。
2. K=1 GSW external product 使用 centered signed digits；K=2 MP GSW 路径使用 unsigned digit extraction。注释不能把二者统称为 signed decomposition。
3. `RlweCt.ntt_form` 是状态标记，不会自动转换数据；每处 domain transition 都必须由实际 NTT/INTT 调用支持。
4. RNS ciphertext 采用 limb-major `q0 block || q1 block`，不是 coefficient-interleaved layout。
5. `ext_prod_mux` 会原地把参数 `y` 复用为 `y-x` 与 external-product scratch；注释中的数学 `y` 必须明确指原始值。
6. query/key seed compression 只有 size formula，不能在注释中称为真实 serializer。
7. response codec 是实际执行路径，但不是认证或面向恶意输入的网络协议。

## 非目标

- 不改变任何函数签名、控制流、常量、内存布局或测试；
- 不修复现有 bug、重构代码或统一格式；
- 不新增 dependency；
- 不为每行代码生成解释；
- 不声称仓库自动证明论文安全位数或复现论文 benchmark；
- 不加入 2021 stateful OnionPIR、PSIR/PBSR 或 copy-network 内容。

## 验证设计

由于目标是 comments-only change，验证分四层：

1. `git diff --check`：无空白或 patch 格式问题；
2. 差异审计：所有 source diff 只包含注释与空白，不包含 executable token 变更；
3. 构建：使用当前默认 `k1_comp` 配置完成 CMake/build；
4. 核心测试：优先运行 `fast_expand`、`ext_prod`、`fst_dim`、`mod_switch` 与 `pir`，并区分 hard assertion 测试和只打印 success/failure 的弱 oracle。

验证过程不覆盖或重写用户已有的 `CMakeLists.txt` 与 `src/tests/test_hexl_ntt.cpp` 修改。若当前环境的既有构建问题阻止测试，将记录具体命令、错误和 comments-only 差异证据。
