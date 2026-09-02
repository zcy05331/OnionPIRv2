# 本机 256MB 档全协议结果(含首次完整阶段拆分)

- 机器:Apple M4 MacBook Air(16 GiB,无风扇),x86_64 + Intel HEXL 1.2.6
  经 Rosetta 2(AVX2,无 AVX-512),macOS 15.7。单线程。
- 代码:commit `6980d18`(main),CONFIG_N2048_K1_COMP;cuckoo 基线已在 main。
- 档位:256MB = 2^22 叶(树 2^23−1 节点 × 32 B),L=22;每种 3 warmup + 16 次,
  种子 5723628103747520850。运行 2026-09-02 04:27 UTC,全套约 25 分钟。
- 抖动提示:standard σ=13%、flat σ=8%,无风扇机器在 flat 的持续负载下降频;
  相对排序与阶段占比可信,绝对值以 node0 结果为准。

## 吞吐量(server MiB/s = 原始数据集 268,435,424 B ÷ 单查询 server 时间)

| 协议 | server ms | MiB/s | 通信/查询 | 备注 |
|---|---|---|---|---|
| standard OnionPIR | 1013.3 | 252.6 | 26,144 B | 单记录 |
| flat | 21308.2 | 12.0 | 575,168 B | 23 次全库 |
| layerwise(直返前) | 1028.3 | 249.0 | 575,168 B | |
| **tree MVP g=32** | **838.1** | **305.5** | 26,144 B | unpack 118.6 + path 719.5;仅 path 356 |
| cuckoo batch | 3555.2 | 72.0 | 862,752 B | 33 桶,3 hash,1.5x |
| tree g=1(诊断) | 201.8 | — | 26,144 B | 12-bit 节点,不与 32 B 协议直接对比 |

## 阶段拆分(server 时间,ms;各段之和与总时间差 <0.3%)

| 协议 | 解包 expand+convert | 扫描 first_dim / scan | 折叠 other_dim / fold | 旋转+投影 | 合并+收尾 |
|---|---|---|---|---|---|
| standard | 39.5 | 437.4 | 533.0 | — | 0.4 |
| flat | 884.6 | 9057.7 | 11313.3 | — | 8.7 |
| layerwise | 310.0 | 370.3 | 337.4 | — | 10.0 |
| cuckoo(33 桶求和) | 1101.8 | 1647.3 | 791.1 | — | 13.9 |
| tree g=32 | 118.6(unpack) | 565.2 | 46.5 + 金字塔 59.7 | 24.6 + 21.3 | 0.28 + 0.39 |
| tree g=1 | 81.5(unpack) | 16.5 | 6.9 + 金字塔 10.3 | 47.6 + 38.0 | 0.11 + 0.51 |

要点:tree 的响应合并(pack+switch)不到 1 ms;layerwise/cuckoo 约 30% 时间花在逐层/逐桶
的展开与转换;tree 扫描核每明文 4.3 µs 对 standard 首维 5.0 µs;g=1 的时间 43% 在
r=11 的旋转/投影链上,扫描仅 8%。

## layerwise 浅层直返的 A/B(commit 040e25b,layerwise-only,2^22,3+16 次,交替 3 轮)

| | server 均值(3 轮) | 48 次中位数 | 阶段 expand/convert/first_dim/other_dim/mod_switch | 在线通信 |
|---|---|---|---|---|
| 旧:22 次 PIR | 877.6 / 864.1 / 863.7 | 849.9 | 131 / 119 / 329 / 280 / 8.2 | 575,168 B |
| 新:16 次 PIR + 6 层直返 | 1151.1* / 832.6 / 879.6 | 860.6 | 127 / 117 / 304 / 279 / 5.9 | **422,336 B(−26.6%)** |

\* 新 r1 受干扰(σ=481 ms,其余 σ 26–100)。server 时间差异在 ±4% 噪声内:规划器已给
单明文层高度 0 的展开,浅层本就近乎免费,直返只省 6 次 mod_switch;收益在通信
(−152,832 B/路径)与客户端(query 1.8→1.3 ms,extract 5.1→3.9 ms)。
逐轮 JSON 见 layerwise_direct_return_ab/。

## 文件清单

merkle.json / merkle.txt、tree_g32_256mb.txt、tree_g1_256mb.txt、cuckoo_256mb.txt、
compress.txt、cpu_info.txt、00_cpu.txt、00_meta.txt、layerwise_direct_return_ab/。
