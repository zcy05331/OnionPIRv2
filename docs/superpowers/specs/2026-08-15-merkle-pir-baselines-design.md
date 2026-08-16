# OnionPIRv2 Merkle PIR Baselines 设计

## 目标

在不实现 Respire rotation/projection/response repacking 的前提下，为当前
OnionPIRv2 增加两条可验证、可重复、统计口径一致的 Merkle authentication
path naive baselines，并与标准 OnionPIRv2 在同一台机器、同一个构建和同一组
密码参数下比较：

1. `merkle_flat`：将整棵树的所有非根节点装入一个 flat database；对 path 的
   每个 sibling 都在完整数据库上执行一次普通 OnionPIR；
2. `merkle_layerwise`：每个 tree level 使用独立且按该层节点数规划的 database；
   path 每层执行一次普通 OnionPIR；
3. `standard_onionpir`：在与 flat baseline 完全相同的 padded PIR shape 上执行
   一次普通 OnionPIR，作为本机标准实现参照。

最终产物必须包含硬失败的正确性测试、统一 benchmark runner、结构化结果、
通信量和吞吐量，以及明确的 x86_64/Rosetta 非原生环境标签。

## 已冻结决策

| 项目 | 决策 |
|---|---|
| Merkle node | 固定 32 bytes |
| 性能树规模 | 主跑 `leaf_count = 2^24`，`tree_height = 24`，对齐 OnionPIRv2 论文 1 GB 评测行 |
| 可选扩展规模 | `leaf_count = 2^27`，`tree_height = 27`，对齐论文 8 GB 评测行；仅在内存门控通过时运行 |
| Path 内容 | 查询 level `H..1` 的 `H` 个 sibling；root 不存储、不查询 |
| PIR 配置 | `CONFIG_N2048_K1_COMP` / `k1_comp`，对齐 OnionPIRv2 论文 4.1 节参数 |
| 性能轮次 | 3 次 warmup + 5 次 measured trials |
| 运行后端 | Apple M4 上的 `x86_64 + Intel HEXL + Rosetta 2` |
| ARM64 | 不在本分支适配；所有结果标记为非 ARM64 原生性能 |
| 服务端并行度 | 单线程，与 OnionPIRv2 论文评测定义一致 |
| 密钥 | 每个 benchmark case 只生成一个 client secret 和一套 helper keys；各层共享 |
| 在线通信 | 全部 query bytes + 全部 response bytes |
| 首次会话通信 | 一套共享 helper keys + 在线通信 |
| 通信真实性 | query/helper keys 使用仓库现有 seed-compressed 模型；response 使用实际 codec 字节数 |
| Hash | 不增加 hash dependency；使用确定性 synthetic 32-byte node |
| 计时主口径 | server online compute；另报本地 query/codec/decrypt 分项与本地 pipeline 时间 |
| 资源门控 | 当前 16 GiB Apple M4 环境必须完成 1 GB 主跑；8 GB 行预计因预处理存储约 42.7 GiB 而默认跳过并报告 skip reason |

### 论文参数对齐

`k1_comp` 不是随便选的“能跑配置”，而是这条分支的论文锚点。对齐目标是
Yue Chen 和 Ling Ren 的 *OnionPIRv2: Efficient Single-Server PIR*
`2025-1142.pdf` 修订版，具体依据第 4.1--4.3 节（PDF 第 12--13 页）：

- `n = 2048`
- `log q ≈ 58`
- `log t = 13`
- `log q' = 22`
- `L_KEY = 10`
- `L_EP = 6`
- `L_KS = 8`
- `σ = 2.55`
- 论文估计安全性为 117 bits

实现里 `PlainMod = 13` 表示生成一个 13-bit 目标 plaintext modulus；编码时每个
coefficient 只承载 `PlainMod - 1 = 12` 个 payload bits，因此一个 2048-coefficient
plaintext 的有效 payload 仍是 3072 bytes，也就是论文里评测的 3 KB entry 尺寸。

2021 版 OnionPIR（`2021-1081.pdf`）的 `n=4096` / 124-bit ciphertext
modulus / 60-bit plaintext modulus 属于不同协议版本，只保留作历史
背景，不进入这条实现分支，也不与 v2 数据混用。

论文第 4.3 节报告两行数据库规模：1 GB 和 8 GB。当前机器是 16 GiB Apple M4；
在 `k1_comp` 下，预处理数据库存储约为 logical payload 的 `2048*8/3072 = 5.33x`。
因此 1 GB 主跑可作为默认必跑项，8 GB 行只作为 resource-gated optional run，
若未运行必须在 JSON 和报告中标记为 `skipped_resource_limit`；不得
使用 swap 强行跑、不得外推或伪造 8 GB 实测数据。

论文参考实现在 Ubuntu 22.04 的 Intel Xeon Platinum 8358 2.60 GHz 上，
使用 GCC 13.3、Intel HEXL/AVX-512 和单线程；报告的 1 GB/8 GB server
throughput 分别为 1031/1372 MB/s。本分支使用 Apple M4 上的
x86_64/HEXL/Rosetta 2，所以只对齐协议参数、工作负载定义和统计公式；
本机数值不得宣称为对论文硬件性能的复现。

论文的 request/response/helper-key 量级分别约为 15 KB / 11 KB /
1.5 MB。在仓库当前 seed-compressed model 下，本设计将它们固化为
14,880 / 11,264 / 1,488,000 bytes 的精确 sanity checks，详见“通信统计
contract”。

## 非目标

- 不实现 Respire blind rotation、coefficient projection、ring switching 或跨层
  response repacking；
- 不实现论文级真实网络协议、query/key seed-compressed serializer、认证传输或
  恶意输入防护；
- 不实现 native ARM64/NEON/标量 HEXL replacement；
- 不加入 SHA-256、OpenSSL 或其他新 dependency；
- 不把上层小 level 作为 public prefix 直接返回；naive baseline 仍对每个非根
  level 执行一次 PIR；
- 不把 benchmark preprocessing、数据库生成或 helper-key generation 混入
  server online throughput；这些成本单独记录或明确排除；
- 不重写 OnionPIRv2 密码学内核。

## 参数与容量

在 `k1_comp` 下：

```text
poly_degree                   = 2048
plaintext coefficient bits   = PlainModBits - 1 = 12
plaintext payload bytes      = 2048 * 12 / 8 = 3072
node bytes                    = 32
nodes per plaintext          = 3072 / 32 = 96
max query expansion height   = 10
```

`2^24` 叶子的完整二叉树有 `2^25 - 1` 个节点。root 不进入 PIR database，
因此：

```text
non_root_node_count = 2^25 - 2 = 33,554,430
raw_merkle_bytes    = 33,554,430 * 32 = 1,073,741,760
                     = 1 GiB - 64 bytes
target_plaintexts   = ceil(33,554,430 / 96) = 349,526
```

使用当前 `k1_comp` shape policy 和 expansion height 10 时，flat/standard 的
实际 shape 如下：

```text
expansion_height               = 10
fst_dim_sz                     = 512
num_other_dims                 = 10
num_dims                       = 11
other_dim_sz                   = 683
rounded_num_pt                 = 512 * 683 = 349,696
paper_plaintext_database_bytes = 349,526 * 3072
                               = 1,073,743,872 = 1 GiB + 2,048 bytes
logical_padded_database_bytes  = 349,696 * 3072
                               = 1,074,266,112 = 1024.5 MiB
physical_preprocessed_storage_bytes = 349,696 * 2048 * 8
                               = 5,729,419,264 = 5.3359375 GiB
```

`paper_plaintext_database_bytes` 只包含容纳数据所需的 349,526 个
plaintext；`logical_padded_database_bytes` 还包含 shape rounding；
`raw_merkle_bytes` 只包含真实 32-byte nodes。标准 OnionPIRv2 必须直接
复用这一 exact shape，而不是使用另一个“约 1 GB”的近似值。

可选 8 GB 行使用 `2^27` leaves：

```text
non_root_node_count = 2^28 - 2 = 268,435,454
raw_merkle_bytes    = 8 GiB - 64 bytes
target_plaintexts   = ceil(268,435,454 / 96) = 2,796,203
paper plaintext     = 2,796,203 * 3072 = 8 GiB + 1,024 bytes
actual_shape        = 2,796,544 plaintexts = 8193 MiB logical padded payload
physical storage    = 2,796,544 * 2048 * 8
                    = 45,818,576,896 bytes = 42.671875 GiB
```

其 reference shape 为 `expansion_height=10`、`fst_dim_sz=512`、
`num_other_dims=13`、`num_dims=14`。这条可选行的预处理
coefficient storage 约为 42.7 GiB，
不得在 16 GiB 机器上作为默认必跑 benchmark。

## Merkle 索引与布局

### 树坐标

root 为 level 0，leaf 为 level `H`。level `l` 包含 `2^l` 个节点，其
level-local index 范围为 `[0, 2^l)`。

对 leaf index `i`，level `l` 的 authentication sibling local index 为：

```text
sibling_local(i, l) = (i >> (H - l)) XOR 1,  l in [1, H]
```

必须覆盖 leaf `0`、`2^H - 1` 和至少一个中间/确定性伪随机 leaf 的边界测试。

### Flat layout

flat database 使用 root-excluded BFS/level-order。level `l`、local index `j`
对应的 0-based flat node ordinal 为：

```text
flat_ordinal(l, j) = (2^l - 2) + j
```

如果使用 1-based binary-heap 描述，则 node heap index 为 `2^l + j`，并有
`flat_ordinal = heap_index - 2`。第一个存储节点是 heap index 2，不是 root。

### Layerwise layout

level `l` 的独立 database 只存该 level，node ordinal 等于 local index：

```text
layer_ordinal(l, j) = j
```

### Plaintext 地址

无论 flat 或 layerwise，node ordinal `r` 映射为：

```text
plaintext_index = r / 96
node_offset      = r % 96
```

PIR 查询只隐藏 `plaintext_index`。客户端解密整个 3072-byte logical plaintext，
然后公开地按 `node_offset` 取出 32-byte node。最后一个实际 plaintext 和 PIR
shape 额外 padding plaintexts 全部补零。

## Node codec

codec 将 96 个连续 32-byte nodes 拼成 3072-byte byte stream，再把它解释为
一个 LSB-first bit stream。第 `c` 个 plaintext coefficient 读取连续 12 bits：

```text
coefficient[c] = bits[12*c .. 12*c+11] as little-endian unsigned integer
```

值域为 `[0, 4095]`，严格小于运行时生成的 13-bit plaintext modulus。decoder
执行完全相反的操作。必须提供以下断言：

- `plaintext_payload_bytes % node_bytes == 0`；
- 所有编码 coefficient `< plain_modulus`；
- codec round trip byte-for-byte 相等；
- 跨 node、byte 和 12-bit coefficient 边界的 offset 正确；
- shape padding 解码为全零。

synthetic node 由 `(level, local_index)` 唯一、确定性地产生 32 bytes。生成器
可使用固定常量的 SplitMix64 类整数混合填充 4 个 64-bit words，但不能使用
`std::hash`、`random_device` 或依赖平台实现的 byte order。它不是密码学 hash，
只作为布局和 PIR 返回值 oracle。

## Runtime shape 设计

### 分离密码参数和数据库布局

当前 `PirParams()` 同时生成密码参数并从编译期 `DB_SIZE_MB/TREE_HEIGHT` 推导
database shape。baseline 需要保持默认构造行为，同时增加显式 runtime layout：

```cpp
struct PirLayoutConfig {
  size_t target_num_pt;
  size_t expansion_height;
  bool fst_dim_pow2;
};

PirParams();
PirParams with_layout(const PirLayoutConfig &layout) const;
```

`with_layout` 只能改变：

- `target_num_pt` 对应的 `fst_dim_sz_`；
- `num_dims_`；
- rounded/padded `num_pt_`；
- runtime `expansion_height_`；
- runtime `fst_dim_pow2_`。

它必须保持以下 scheme fields 完全相同：poly degree、plaintext modulus、full-q
RNS/composite moduli、small-q、`L_EP/L_KEY/L_KS`、gadget bases、noise sigma、NTT
roots/tables。默认 `PirParams()` 仍等价于当前 compile-time standard 配置。

`utils::calculate_db_shape` 必须接收显式 `fst_dim_pow2`，不得继续在 helper 内部
偷偷读取全局 `DBConsts::FST_DIM_POW2`。

实现时必须显式拆除三个当前的 compile-time 阻塞点：

1. `PirParams::PirParams()` 目前从 `DBConsts::DB_SIZE_MB` 计算
   `target_num_pt`；新 layout path 必须使用调用者给定的精确值；
2. `PirParams::get_expan_height()` 目前直接返回
   `DBConsts::TREE_HEIGHT`；必须改为返回 instance field，默认构造再用
   compile-time value 初始化该 field；
3. `utils::calculate_db_shape()` 目前直接读取
   `DBConsts::FST_DIM_POW2`；新 API 必须显式传 policy，旧调用点使用
   保持现行行为的 wrapper。

仅修改 benchmark 常量而未消除这三个阻塞点，不算 runtime-shape
实现完成。

### Layerwise shape planner

flat 和 standard 固定使用 `target_num_pt = 349,526`、`expansion_height = 10` 的
同一个 reference layout。每个 layerwise database 使用以下确定性 planner：

1. 目标 plaintext 数为 `ceil(2^l / 96)`；
2. 枚举 `h = 0..10`，调用显式 policy 的 `calculate_db_shape(target, L_EP, h)`；
3. 丢弃无法容纳目标的候选；
4. 丢弃 `num_other_dims` 大于 reference flat layout 的候选，避免为了减少
   expansion 而增加比标准参数更多的 MUX depth/noise；
5. 对候选计算：

   ```text
   rounded_num_pt = fst_dim_sz * ceil(target_num_pt / fst_dim_sz)
   useful_expand  = fst_dim_sz + L_EP * num_other_dims
   ```

6. 按以下 tuple 的字典序选最小值：

   ```text
   (rounded_num_pt, useful_expand, num_other_dims, expansion_height)
   ```

至少存在 reference height 10 候选；否则抛出错误。该 policy 优先忠实保存每层
真实大小，同时限制 MUX depth，不宣称是 OnionPIR 的全局性能最优调参器。所有
选择结果和 padding 必须输出到 benchmark metadata。

height 0 是合法的单 plaintext 退化 PIR：仍生成一条 encrypted BFV query、
执行 server path 并返回一条 encrypted response，只是不使用 Galois expansion。
不得替换为明文直接读取。

对 `H=24` 主工作负载，planner 必须产生以下可固化为单元测试的
sanity anchors：

```text
levels 1..6:  target_num_pt=1, expansion_height=0, fst_dim_sz=1
level 7:      target_num_pt=2, expansion_height=1, fst_dim_sz=2
level 12:     target_num_pt=43, expansion_height=5, fst_dim_sz=16,
              num_dims=3, rounded_num_pt=48
level 24:     target_num_pt=174,763, expansion_height=9, fst_dim_sz=256,
              num_dims=11, rounded_num_pt=174,848

sum paper_plaintext_database_bytes = 1,073,783,808
sum logical_padded_database_bytes  = 1,074,843,648
sum physical_preprocessed_storage_bytes = 5,732,499,456
```

这些 layerwise totals 是对各层 database 各计一次；在一个完整 path trial
中每层恰好执行一次 PIR，因此也分别等于该 case 的三个对应
scan totals（raw application total 另为 1,073,741,760 bytes）。

## 共享 client session 和 helper keys

### Session contract

一个 benchmark case 创建一个 client session。session 拥有：

- 唯一 client id；
- 一份 RLWE secret key；
- 一个按 reference/max expansion height 10 生成的 `BvGaloisKeys`；
- 一个 `GSWCt` completion/helper key；
- client RNG。

查询 API 必须允许同一 secret 在 scheme-compatible 的不同 `PirParams` layout
上生成 query，例如：

```cpp
RlweCt fast_generate_query(const PirParams &query_params, size_t pt_idx);
```

旧的单参数 API 保留并委托给 client 的默认 params。调用前必须检查 scheme
compatibility；layout fields 可以不同，scheme fields 不同则 hard fail。

### Key reuse contract

BV Galois key集合只为 max height 10 生成一次。height `h < 10` 的 server
expansion 使用同一集合中前 `h` 个对应 automorphism keys。GSW helper key 与
database shape 无关，同样只生成一次。

服务端不得为 `H` 层按值复制整套 keys。增加只读共享 key bundle：

```cpp
struct PirSessionKeys {
  bvks::BvGaloisKeys bv_galois_keys;
  GSWCt gsw_key;
};

using SharedPirSessionKeys = std::shared_ptr<const PirSessionKeys>;
```

每个 `PirServer` 保存相同 bundle 的 shared pointer，并只读访问。现有 setter
可以保留为兼容 wrapper，但 baseline runner 必须使用共享接口。通信统计始终只
计算 bundle 一次，不因 C++ 对象 ownership 或 server 数量改变。

## Database source 和 preprocessing

当前 `PirServer::gen_data()` 只生成随机 plaintext。增加 deterministic plaintext
source/loader，使服务器能按 plaintext index 逐条生成输入并执行现有 NTT、
composite split 和 coefficient-major realignment：

```cpp
using PlaintextSource = std::function<void(size_t logical_index, RlwePt &out)>;
void load_data(size_t logical_num_pt, const PlaintextSource &source);
```

`logical_index < logical_num_pt` 时 source 生成 packed Merkle plaintext；其余
rounded shape plaintexts 由 loader 补零。source 采用回调而不是先构造完整
`vector<RlwePt>`，避免同时保留约 688 MiB raw coefficient buffer 和预处理 DB。
现有 `gen_data()` 行为保留，可复用 loader 的底层 preprocessing helper。

database preprocessing 在 benchmark trial 计时之外完成，并分别报告 setup
时间。correctness tests 以 synthetic node generator 作为 oracle，不依赖 server
保留整个原始数据库副本。

## 三种执行模式

### `standard_onionpir`

- 使用 flat reference layout 的 349,696 padded plaintext shape；
- 数据内容可为确定性 plaintext source；
- 每个 trial 查询一个 plaintext；
- 一条 query、一条 response；
- useful response payload 定义为一个 3072-byte plaintext；
- 该模式同时是现有 OnionPIR 核心的 correctness gate。

### `merkle_flat`

- 一个 server/database 存储所有非 root nodes；
- database 只 preprocess 一次；
- 每个 trial 选择一个 leaf，并按 level `H..1` 生成 `H` 个 sibling 查询；
- `H` 条 query 依次访问相同 server；
- 返回的 `H` 个 plaintext 分别按对应 node offset 解出 32-byte node；
- useful response payload 为 `H * 32` bytes；1 GB 主跑为 `24 * 32 = 768` bytes；
- scanned padded bytes 为 `H * reference_layout_bytes`。

### `merkle_layerwise`

- `H` 个 per-level layout/server/database；
- 所有 server 共享同一个 `SharedPirSessionKeys`；
- 每个 trial 在每一层查询 local sibling plaintext index；
- upper level 即使只有一个 logical plaintext 也执行退化 encrypted PIR；
- useful response payload 同样为 `H * 32` bytes；
- scanned padded bytes 为 `H` 个 per-level rounded layout bytes 之和；
- level servers 可以同时驻留，但 benchmark cases 必须顺序构造/销毁，避免
  standard、flat 和 layerwise 大数据库同时占用内存。

## 正确性测试

所有 mismatch 必须 `throw`、assert 或返回非零进程状态；只打印 `Failure!` 不算
测试通过。性能结果只有在同一当前构建的全部 correctness gates 通过后才可生成。

### 纯布局/codec tests

1. `merkle_node_codec_round_trip`；
2. `merkle_node_codec_crosses_12_bit_boundaries`；
3. `merkle_sibling_indices_edges`：leaf 0、last、middle；
4. `merkle_flat_layout_matches_formula`；
5. `merkle_layerwise_layout_matches_formula`；
6. `merkle_padding_decodes_zero`；
7. `runtime_shape_planner_is_deterministic_and_bounded`。

小型 fixture 使用 `H = 8`，足以覆盖多个 plaintext、level boundary 和最后一个
partial plaintext，且不需要运行 HE。

### Cryptographic tests

1. 当前 HEAD 重新构建后的 `standard_onionpir` smoke 必须 hard-pass；
2. 同一个 client secret/helper bundle 在至少三种不同 expansion heights/shapes
   上生成 query，并由对应 servers 正确解密；
3. `merkle_flat` 返回完整 sibling path，与 direct synthetic oracle byte-for-byte
   相等；
4. `merkle_layerwise` 返回同一完整 sibling path；
5. flat 和 layerwise 对 leaf 0、last 和 deterministic middle leaf 返回相同 path；
6. communication accumulator 对 `H` 层只计算一次 helper bundle。

多维 HE smoke 使用 `H = 16`：flat target 超过 1024 plaintexts，确保测试不仅
覆盖 single first-dimension 路径，还覆盖 QueryUnpack/other-dimension MUX。

仓库旧 build artifact 曾在一次 129 MiB probe 中解密失败；该 artifact 早于当前
HEAD，不能作为回归结论，也不能用于最终数据。必须从当前 commit 创建全新
x86_64 Benchmark build，并先通过上述 standard smoke。

## Benchmark timing contract

所有三种模式使用相同 timer boundaries。setup 与每个 trial 的 online pipeline
分开：

```text
setup:
  params/layout planning
  client secret + helper key generation
  server construction
  database generation/packing/NTT/realignment

online trial:
  client_query_time
  server_compute_time
  response_serialize_time
  response_load_decrypt_extract_time
```

Merkle 两种模式的一个 trial 是完整 `H`-level path，不是单个 level call。各分项
在 `H` 次 PIR 上求和。`server_compute_time` 是主要 latency/throughput 分母，以
保持与现有 OnionPIRv2 `SERVER_TOT_TIME` 和论文“完整 server
computation”口径一致：它覆盖 server 从 query 展开、first-dimension
scan、后续 dimensions 折叠到 modulus switch/response 生成的全部在线计算，
不只计 first-dimension kernel。另报：

```text
local_online_pipeline_time = query + server + serialize + load/decrypt/extract
```

该值不含真实 network latency，因此不得标记为网络端到端 latency。正确性比较
在计时区间外执行。warmup trials 执行完整相同流程但不进入平均值。
论文未给出可直接复用的 warmup/measured 轮次协议，因此 3+5 是本地
重复性方法，不得宣称为复制了论文的 trial protocol。服务端必须单线程运行。

## 通信统计 contract

当前仓库只有 response 的实际 wire codec。结果字段必须明确区分 model 和 actual：

```text
modeled_query_bytes_per_pir = reference_crypto.get_BFV_size(use_seed=true)
modeled_helper_key_bytes    = max_height_bv_galois_key_size(use_seed=true)
                            + gsw_key_size(use_seed=true)
actual_response_bytes       = sum(save_resp_to_stream return values)
```

不计算 client secret、本地 RNG state、C++ metadata 或不存在的 public/relin key。
论文对齐配置下的精确字节推导为：

```text
seed-compressed BFV query = 32 + 2048 * 58 / 8 = 14,880
small-q RLWE response     = 2 * 2048 * 22 / 8 = 11,264
BV Galois keys            = 10 * 8 * 14,880 = 1,190,400
GSW completion key        = 2 * 10 * 14,880 = 297,600
shared helper-key bundle  = 1,190,400 + 297,600 = 1,488,000
```

在 1 GB 主跑、`H = 24`、`k1_comp` 下，通信 sanity check 必须满足：

```text
modeled_query_bytes_per_pir = 14,880
actual_response_bytes_per_pir = 11,264
modeled_helper_key_bytes = 1,488,000

standard_onionpir:
  online_total_bytes_mixed = 14,880 + 11,264 = 26,144
  first_session_total_bytes_mixed = 1,514,144

merkle_flat / merkle_layerwise:
  online_query_bytes_modeled = 24 * 14,880 = 357,120
  online_response_bytes_actual = 24 * 11,264 = 270,336
  online_total_bytes_mixed = 627,456
  first_session_total_bytes_mixed = 2,115,456
```

这些数字的 KB 展示可四舍五入，但 JSON 中保留 byte 精确值。
每行结果必须包含：

```text
pir_call_count
online_query_bytes_modeled
online_response_bytes_actual
online_total_bytes_mixed
helper_key_bytes_modeled
first_session_total_bytes_mixed
```

公式为：

```text
online_query_bytes_modeled   = pir_call_count * modeled_query_bytes_per_pir
online_response_bytes_actual = 每条实际 response codec bytes 之和
online_total_bytes_mixed     = online_query_bytes_modeled
                             + online_response_bytes_actual
first_session_total_bytes    = modeled_helper_key_bytes
                             + online_total_bytes_mixed
```

standard 的 `pir_call_count = 1`；flat 和 layerwise 均为 `H`。因此 naive flat 与
layerwise 的通信量应相同；若不同，benchmark 必须失败并解释实际 codec 差异。
字段名和报告说明必须使用 `modeled`/`actual`/`mixed`，不能把 mixed 数字称为
完整实测 wire bytes。

## 吞吐量统计 contract

论文将 server throughput 定义为“plaintext database size in bytes /
server computation time”。本 benchmark 的 Merkle case 以完整 H 层 path 为一次
case，因此分母是 H 次 PIR 的 server computation 总和，分子是该 case 存储的
plaintext database footprint，只计一次：

```text
paper_plaintext_database_bytes:
  standard         = flat_target_num_pt * plaintext_payload_bytes
  merkle_flat      = flat_target_num_pt * plaintext_payload_bytes
  merkle_layerwise = sum(ceil(2^l / 96) * plaintext_payload_bytes,
                         l=1..H)
```

为了另外诊断重复扫描和 shape padding，每个 case 同时报三个 scan-byte 口径：

```text
paper_plaintext_scan_bytes:
  standard         = flat_target_num_pt * plaintext_payload_bytes
  merkle_flat      = H * flat_target_num_pt * plaintext_payload_bytes
  merkle_layerwise = sum(ceil(2^l / 96) * plaintext_payload_bytes,
                         l=1..H)

logical_padded_scan_bytes:
  standard         = reference_num_pt * plaintext_payload_bytes
  merkle_flat      = H * reference_num_pt * plaintext_payload_bytes
  merkle_layerwise = sum(level_params.get_num_pt() * plaintext_payload_bytes,
                         l=1..H)

raw_application_scan_bytes:
  standard         = flat_target_num_pt * plaintext_payload_bytes
  merkle_flat      = H * raw_merkle_bytes
  merkle_layerwise = sum(2^l * node_bytes, l=1..H)
```

`paper_plaintext_scan_bytes` 排除为 PIR shape rounding 额外增加的 plaintexts，但保留
最后一个 logical plaintext 内的 node-packing padding；它是重复扫描诊断分子，
不是论文 throughput 的主分子。`logical_padded_scan_bytes` 是实际 PIR shape
扫描的 logical bytes，
只用于诊断 padding 影响。`raw_application_scan_bytes` 是真实 Merkle nodes
在各次 PIR 中被重复扫描的应用层字节数。三者都不是 NTT/composite
physical RAM bytes。

主要吞吐量、paper scan 诊断和 padding scan 诊断分别为：

```text
paper_server_throughput_MBps =
    paper_plaintext_database_bytes / server_compute_seconds / 2^20

paper_scan_throughput_MBps =
    paper_plaintext_scan_bytes / server_compute_seconds / 2^20

padded_scan_throughput_MBps =
    logical_padded_scan_bytes / server_compute_seconds / 2^20
```

论文表头使用 `MB/s`；本仓库现有 `DB_SIZE_MB` 和实验工作负载使用
`2^20` 字节，因此 JSON 中保留 `_MBps` 字段名并明确采用
`1 MB = 2^20 bytes`。不得用 preprocessed physical storage 作为吞吐量分子。

另报应用有效载荷：

```text
useful_response_bytes = 3072           for standard
                      = H * 32 = 768   for 1 GB Merkle baselines
                      = H * 32         for other configured Merkle workloads

useful_response_throughput_Bps = useful_response_bytes / server_compute_seconds
```

同时输出 `raw_dataset_bytes`、`paper_plaintext_database_bytes`、
`logical_padded_database_bytes` 和 `physical_preprocessed_storage_bytes`，避免把
node packing、shape padding 或 coefficient storage 混为协议吞吐。

## Benchmark 参数与 leaf 序列

正式性能运行：

```text
config          = k1_comp / CONFIG_N2048_K1_COMP
leaf_count      = 2^24
tree_height     = 24
node_bytes      = 32
warmups         = 3
measured_trials = 5
```

可选资源门控运行：

```text
leaf_count      = 2^27
tree_height     = 27
paper_row       = 8 GB
run_policy      = only when estimated physical_preprocessed_storage_bytes fits available memory budget
```

trial leaf index 由固定 seed 的平台无关 SplitMix64 生成，并取模 `leaf_count`；
输出 seed 和每个 measured leaf index，以便完全复现。至少一次 correctness run
额外显式覆盖 first/last/middle leaf。

## 构建与环境复现

不能复用当前可能 stale 的 `build/`。新增 macOS x86 benchmark 入口使用独立目录，
例如 `build-x86_64-benchmark/`，并同时：

- 使用 native CMake configure/build，并把 `CMAKE_CXX_COMPILER` 固定为
  `/usr/bin/arch;-x86_64;/usr/bin/clang++`；运行 binary 时使用
  `/usr/bin/arch -x86_64`。Homebrew CMake 本身只有 arm64 slice，不能直接放在
  `arch -x86_64` 下执行；
- 设置 `CMAKE_OSX_ARCHITECTURES=x86_64`；
- 设置 `CMAKE_BUILD_TYPE=Benchmark`；
- 设置 `ACTIVE_CONFIG=CONFIG_N2048_K1_COMP`；
- 设置 `USE_HEXL=ON` 并使用仓库配置的 HEXL 1.2.6 路径；
- 在运行前用 `file` 验证 binary 是 `Mach-O 64-bit executable x86_64`；
- 记录 `uname`、macOS version、CPU、compiler、CMake、git commit/branch、build
  type、config、HEXL path/version、process architecture 和 Rosetta 标签。

所有结果标题必须包含：

```text
x86_64 + Intel HEXL under Rosetta 2 on Apple M4; non-native result
```

不得把结果描述为 Apple M4 native ARM64 性能。

## 输出格式

benchmark 同时打印 human-readable table 并写一个不依赖第三方库的 JSON artifact。
JSON 至少包含：

```text
schema_version = onionpir-merkle-baselines-v2
environment { commit, branch, build_type, config, architecture,
              hexl_enabled, hexl_version, rosetta, non_native_label }
paper_alignment { paper, revision, sections, poly_degree, log_q, log_t,
                  log_q_prime, L_KEY, L_EP, L_KS, sigma,
                  estimated_security_bits, reference_hardware,
                  local_result_is_hardware_replication }
workload { leaf_count, tree_height, node_bytes, nodes_per_plaintext,
           paper_row, warmups, measured_trials, trial_leaf_indices,
           optional_workloads[] { leaf_count, tree_height, paper_row,
                                  status, skip_reason } }
cases[] {
  name
  correctness_passed
  pir_call_count
  raw_dataset_bytes
  paper_plaintext_database_bytes
  logical_padded_database_bytes
  paper_plaintext_scan_bytes
  logical_padded_scan_bytes
  raw_application_scan_bytes
  physical_preprocessed_storage_bytes
  setup_ms
  client_query_ms
  server_compute_ms
  response_serialize_ms
  response_load_decrypt_extract_ms
  local_online_pipeline_ms
  online_query_bytes_modeled
  online_response_bytes_actual
  online_total_bytes_mixed
  helper_key_bytes_modeled
  first_session_total_bytes_mixed
  paper_server_throughput_MBps
  paper_scan_throughput_MBps
  padded_scan_throughput_MBps
  useful_response_bytes
  useful_response_throughput_Bps
}
```

若 correctness gate 失败，进程必须非零退出，JSON 不得包含看似有效的 throughput
值；可以写带错误状态的诊断 artifact，但不能将其放入最终结果表。

## 兼容性与修改边界

预计修改集中在：

- `src/includes/pir.h`, `src/pir.cpp`, `src/includes/utils.h`, `src/utils.cpp`：
  runtime layout 和显式 shape policy；
- `src/includes/client.h`, `src/client.cpp`：同一 secret 的 shape-aware query；
- `src/includes/server.h`, `src/server.cpp`：共享只读 keys 和 deterministic loader；
- 新增 `src/includes/merkle_baseline.h`, `src/merkle_baseline.cpp`：codec、layout、
  source、runner、stats；
- 新增 `src/tests/test_merkle_baseline.cpp`，并更新 `tests.h/run_test.cpp`；
- 增加独立的 benchmark runner/script 和文档化输出；
- 强化标准 PIR test，使 mismatch 真正失败。

现有默认 `PirParams()`、`PirClient::fast_generate_query(pt_idx)`、随机
`PirServer::gen_data()` 和标准 test route 必须保持兼容。密码内核的 NTT、GSW、
BV key switching、matrix multiplication、mod switching 算法不因 baseline 改写。

## 风险与缓解

1. **现有标准 PIR 可能仍有正确性问题**：从当前 HEAD 全新构建，standard hard
   smoke 是所有 baseline/benchmark 的前置门禁；失败时进入系统化诊断，不发布
   性能数值。
2. **不同 shape 共用 secret/key 的隐含假设**：用三种 expansion heights 的
   cryptographic test 直接证明；所有 scheme fields 运行时检查相等。
3. **layerwise shape 为减少 padding 产生过深 MUX**：planner 禁止超过 reference
   flat layout 的 other-dimension depth。
4. **helper keys 在多个 server 中被复制**：shared immutable bundle，测试引用
   identity/use count，并在通信 accumulator 中只计一次。
5. **查询/密钥没有真实 serializer**：字段明确标记 modeled，禁止称为实测 wire
   bytes；response 保持实际 codec 统计。
6. **Rosetta 构建漂移为 ARM64**：独立 build dir、双重 arch 设置、`file` hard
   check 和结果 metadata。
7. **内存压力**：1 GB row 的 flat preprocessed coefficient storage 已是
   5.3359375 GiB；database source 流式生成；三种 cases 顺序构造/销毁；
   不同时保留 standard、flat 和 layerwise 数据库。8 GB row 在预估
   42.671875 GiB 物理存储不符合内存门限时必须 skip。

## 验收标准

只有同时满足以下条件才算完成：

1. 当前工作位于新的 `codex/merkle-pir-baselines` 分支；
2. codec、索引、layout、shape planner tests 全部 hard-pass；
3. 从当前 HEAD 创建的 x86_64 Benchmark build 中，标准 OnionPIR smoke hard-pass；
4. flat 和 layerwise 对 edge/middle leaves 返回完整 24-node path，并与 oracle
   byte-for-byte 一致；
5. 同一 secret/helper bundle 成功服务至少三种 runtime shapes；
6. helper-key communication 对每个 Merkle path 只计算一次；
7. 1 GB 主跑的 3 warmup + 5 measured trials 在同一 x86_64/HEXL/Rosetta build 中完成；
8. 输出三行 `standard_onionpir`、`merkle_flat`、`merkle_layerwise` 的通信、
   latency、paper-aligned server throughput、padded-scan diagnostic throughput 和
   useful throughput；
9. 结构化 artifact 包含完整 workload/build/environment metadata；
10. 所有最终数字来自通过 correctness gates 的当前 commit；
11. `git diff --check`、相关单元/集成测试和完整 benchmark command 均成功；
12. 8 GB 可选行若未运行，最终报告和 JSON 明确给出资源门控 skip reason；
13. 最终报告明确说明 x86_64/Rosetta 非原生限制、modeled/actual 通信边界和剩余
    风险，且不将本机结果表述为 Xeon/AVX-512 论文性能的复现。
