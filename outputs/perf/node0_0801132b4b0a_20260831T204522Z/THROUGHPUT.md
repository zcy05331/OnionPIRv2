# node0 全协议吞吐量汇总(1GB / 4GB 档)

- 机器:CloudLab Wisconsin sm110p,Intel Xeon Silver 4314 @2.40GHz,125 GiB,
  原生 AVX-512 + Intel HEXL 1.2.6,Ubuntu 24.04,g++ 13.3,单线程基准。
- 代码:commit `0801132`(main),CONFIG_N2048_K1_COMP。
- 运行:2026-08-31 20:45–21:41 UTC,全套约 56 分钟;全部正确性门通过。
- 档位:1GB = 2^24 叶(树 2^25−1 节点 × 32 B),4GB = 2^26 叶;
  merkle 三案例 1GB 档 64 次、4GB 档固定 4 次(--run-optional-4gb),
  tree 系两档均 64 次(3 warmup)。种子 5723628103747520850。

## 吞吐量定义

- **server MiB/s** = 原始数据集字节(全部树节点 × 32 B)/ 单查询 server 计算
  时间,与 merkle.json 的 `paper_server_throughput_MBps` 同口径(MiB/s)。
- **useful B/s** = 单查询有用载荷 / server 时间(standard 为 1 条 3072 B 明文;
  路径协议为整条路径,(L+1)×32 B)。
- tree_g1 是 12-bit 标量诊断基准,原始数据集按 1.5 B/节点折算,不与 32 B
  节点协议直接对比。

## 结果

| 协议 | 1GB: server ms | 1GB: MiB/s | 4GB: server ms | 4GB: MiB/s |
|---|---|---|---|---|
| standard OnionPIR(单记录) | 824.5 | 1242.0 | 2908.2 | 1408.4 |
| flat(整树路径) | 19564.1 | 52.3 | 75441.4 | 54.3 |
| layerwise(路径) | 1755.7 | 583.3 | 5826.5 | 703.0 |
| **tree MVP g=32(路径)** | **1247.5** | **820.9** | **4392.5** | **932.5** |
| tree MVP g=32,仅 path 段 | 1138.9 | 899.1 | 4280.6 | 956.9 |
| tree g=1(12bit 诊断) | 204.2 | 235.1 | 393.8 | 487.6 |

有用载荷吞吐(B/s):1GB 档 tree 641.3 / layerwise 437.4 / flat 39.3;
4GB 档 tree 196.7 / layerwise 142.8 / flat 11.0。

## 要点

- 路径协议对比:tree MVP 的 server 吞吐是 layerwise 的 **1.41×**(1GB)/
  **1.33×**(4GB),是 flat 的 15.7× / 17.2×;每查询通信 26,144 B
  (查询 14,880 + 响应 11,264,M5 small-q)对 layerwise 的数百 KB。
- tree 的 unpack 段(expand+convert)恒定 ~110 ms 不随 DB 放大;path 段随
  DB 线性,故 DB 越大摊薄越多、总吞吐上升(820.9 → 932.5 MiB/s)。
- 噪声:L=24 与 L=26 全部解密 max noise 111–205 < 界 256,L=22 验证包络
  外推成立;逐字节正确性通过。
- tree g32 setup:1GB 档 76.2 s(52.4 万明文),4GB 档 309.4 s(209.7 万)。
- 峰值内存:cgroup v2 `memory.peak` = 69,296,607,232 B ≈ **64.5 GiB**
  (全程高水位,归因于 tree g32 L=26 阶段;见 cgroup_memory_peak_bytes.txt)。
  逐模式峰值 RSS 本轮未单独记录。
- standard 行是单记录检索的参考上界(每查询只取 1 条记录,非路径语义),
  不与路径协议同任务;flat 的原始扫描吞吐其实高达 ~1256–1412 MiB/s,
  慢在每条路径要做 25–27 次全库等价工作。

## 文件清单

merkle.json / merkle.txt(三案例 × 两档,含逐次样本与统计)、
tree_g32_{1gb,4gb}.txt、tree_g1_{1gb,4gb}.txt、compress.txt(M7 门)、
cpu_info.txt、00_cpu.txt(lscpu)、00_meta.txt(构建与旋钮)、
cgroup_memory_peak_bytes.txt。
