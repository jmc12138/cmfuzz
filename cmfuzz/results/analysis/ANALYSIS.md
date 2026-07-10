# CMFuzz 全量运行 + 代码审查 + 盲区分析

日期：2026-07-09。HEAD=cf07e47。在 VM 上装好 clang14/ninja 后完整 `build_all.sh`，再跑
`run_campaign`（libFuzzer 功能+内存安全靶）、PQC 差分、`run_ct`（dudect 恒定时间）、跨库子进程差分。
受限项：Go / BoringSSL(Go 依赖) 的部分后端、wolfCrypt(autotools)、Swift/Zig —— 本机无对应工具链。

## 0. TL;DR
- **功能/差分：0 分歧、0 误报、0 崩溃。** 7 个独立后端 + 多库 libFuzzer 差分 + PQC(liboqs↔PQClean) 全一致。
- **恒定时间 oracle 有真实信号**：正对照 `naive_memcmp` 正确报 LEAK(t=705)、`crypto_memcmp`/AES-NI 报 OK；
  **ML-DSA-65 与 Falcon-512 签名被判 LEAK**（拒绝采样/高斯采样导致的已知变时行为）。
- 未发现密码库功能 bug；CT 维度的两条 LEAK 是「已知设计特性」而非新漏洞，但值得作为 oracle 生效的证据。

## 1. 构建产物（本轮真实构建）
- liboqs KEM 靶：ML-KEM-512/768/1024、Kyber768、BIKE-L1、FrodoKEM-640-AES
- liboqs SIG 靶：ML-DSA-44/65/87、Falcon-512/1024、SLH-DSA-SHA2-128F
- 传统/组合/时序靶：classic_openssl、trad_metamorphic、comp_hpke_{x25519,mlkem}、comp_trad、
  comp_authkem_{classic,pqc}、comp_kdfchain、seq_{aead,ecdsa,evp,pqc_kem}
- 多库差分：diff_multilib（OpenSSL / libsodium / MbedTLS / Crypto++）
- 跨库/跨语言子进程差分后端：boringssl、botan、rust、pycryptodome、libgcrypt、nettle、bouncycastle
- PQC 差分：pqc_diff（liboqs ↔ PQClean）
- FHE：fhe_seal_bfv、fhe_diff(OpenFHE↔SEAL)、fhe_ckks；TFHE：cmf_tfhe；ZK：cmf_zk
- 跳过：wolfCrypt(autotools 构建失败)、Go 跨语言差分(无 Go)

## 2. 跨库子进程差分（O1）
7 个独立后端对 OpenSSL 参照逐字节比对：

| seeds | 向量数 | 后端 | 结果 |
|---|---|---|---|
| 42/777/31337/20260709 | 55000 | rust/py/gcrypt/nettle/bc | all agree |
| 42 | 15000 | +boringssl +botan（共 7 个） | all agree |

**合计 7 万+ 向量，0 分歧、0 误报。** 每个 op 至少 2 个独立后端覆盖，无「仅 OpenSSL」零差分算子。

## 3. libFuzzer 功能 + 内存安全 + 多库差分（每靶 ~25s）
26 个靶全部 **0 crash / 0 CMF_VIOLATION**。关键数据（runs / cov）：

| 靶 | runs | cov | verdict |
|---|---|---|---|
| kem_ML-KEM-512/768/1024 | 13万–29万 | 20–21 | ok |
| kem_Kyber768 / BIKE-L1 / Frodo-640 | – | 20 | ok |
| sig_ML-DSA-44/65/87 | 3万–6万 | 25 | ok |
| sig_Falcon-512/1024 / SLH-DSA-128F | 0.7k–2k | 24 | ok |
| classic_openssl | 4.19M | 20 | ok |
| trad_metamorphic | 2.67M | 27 | ok |
| comp_hpke_x25519/mlkem, comp_trad, comp_authkem_*, comp_kdfchain | – | 10–34 | ok |
| seq_aead/ecdsa/evp/pqc_kem | 13万–4.19M | 5–31 | ok |
| **diff_multilib (OpenSSL/libsodium/MbedTLS/Crypto++)** | 764720 | **1278** | ok（无跨库分歧）|
| fhe_seal_bfv | 512 | 196 | ok |

## 4. PQC 差分 liboqs ↔ PQClean
- ML-KEM-768 KEM 互操作 20000 iters、双向一致
- ML-DSA-65 签/验互操作 20000 iters、双向一致

## 5. 恒定时间（dudect）时序 oracle —— 本轮唯一「非全绿」
| alg | op | max_t | verdict | 解读 |
|---|---|---|---|---|
| ML-KEM-512/768/1024, Kyber768 | decaps | 1.75–3.45 | **OK** | 解封装恒定时间，符合预期 |
| **ML-DSA-65** | sign | 7.90 | **LEAK** | Dilithium 拒绝采样→循环次数随机，已知变时（非密钥泄露型） |
| **Falcon-512** | sign | 11.01 | **LEAK** | Falcon 高斯采样/浮点，业界公认难恒定时间 |
| traditional AES-256 | enc | 3.72 | OK | AES-NI 恒定时间（真阴性）|
| traditional crypto_memcmp | cmp | 0.33 | OK | 恒定时间比较（真阴性）|
| **traditional naive_memcmp** | cmp | 705.67 | **LEAK** | **正对照**：朴素早退比较，真阳性，证明 oracle 有效 |

**要点**：CT oracle 经正/负对照验证「确实能测出时序泄露」。ML-DSA/Falcon 的 LEAK 是**已知设计特性**
（签名本就变时），阈值 t≈4.5 的 dudect 会稳定命中——这不是新发现的库漏洞，但提示：CT 结果需要
「按算法预期」解读，直接告警会对签名算法产生大量「预期内」噪声（见 §7-E）。

## 6. 代码审查：实现问题与误报/漏报风险（结论不变，全量运行进一步印证）
1. **[漏报] NA 静默跳过**（`diff_subproc_runner.c`）：后端回 `NA` 即跳过、不校验。建议 per-op 后端白名单。
2. **[误报隐患] 参照 `ERR` vs 后端有效输出**：最可能在 op12 X25519 低阶点（OpenSSL 报错、dalek 返回全零）。
3. **[结构] 星型拓扑、OpenSSL 单一参照**：OpenSSL 与某后端共享 bug 时不可见；建议 all-pairs/多数表决。
4. **[覆盖弱] 验签 op13/14 多样性极低**：签名全由 OpenSSL 生成 + 仅 1-bit 翻转；应做交叉签/验矩阵 + 畸形编码。
5. **[健壮性] popen + 单引号拼接**：路径含单引号即破。
6. **[信息量] 验签仅比 accept/reject 一个比特**，不比失败原因。

## 7. 盲区与优化建议（按性价比）
- **A. 输入分布是最大盲区**：纯 splitmix64 均匀随机，触达不到库间真正分歧的边界。尤其代码**主动
  `&=0x7F` 屏蔽 X25519 bit255、回避低阶点**——把最有价值差分点关掉了。建议反过来专门注入
  低阶点/非规范坐标（X25519）、非规范 S/cofactor（Ed25519）、high-S 可锻性与 r/s=0/DER 非规范（ECDSA）、
  salt 边界/非规范 padding（RSA-PSS）、tag 截断/nonce 复用/超长 AAD（AEAD）、L=0/max（HKDF/PBKDF2），
  并把「是否拒绝」本身做成 oracle。
- **B. 验签改交叉签/验矩阵**（N×N）+ 已知可锻/畸形编码，把 op13/14 从「几乎测不到」变主力发现源。
- **C. 前向差分外补解密/往返跨库比对**（当前 AEAD 篡改拒绝只在独立 metamorphic 靶）。
- **D. ZK/TFHE 是单库自洽而非跨库差分**（arkworks / tfhe-rs 各自证验）；第二 ZK 库(gnark/libsnark)受工具链限制，
  可用已知无效证明/被篡改 CRS 作额外 oracle 补强。
- **E. CT oracle 需按算法分级**：对 ML-DSA/Falcon 这类「设计上变时」的签名，dudect 会稳定报 LEAK。建议
  引入「预期变时」白名单或改用 leakage 分类（区分密钥依赖 vs 消息/随机依赖），否则签名类会淹没真实信号。
  另可对更多传统算法（RSA 解密、ECDSA、CBC padding）加 CT 靶。
- **F. 参数多样性**：ECDSA/RSA 全程复用单把 key、固定 salt/MGF1，应轮换。
- **G. 分诊**：命中分歧仅打前 64 hex 且首个即 break，建议 dump 完整 (op,input,各后端输出) 到 findings/。
- **H. 覆盖率偏低的靶**（seq_pqc_kem cov=5、comp_authkem_pqc cov=10）提示种子语料/字典缺失，可加初始语料与
  `-dict` 提升有效变异。

## 结论
全量跑下来实现**健壮、无功能 bug、无误报、无崩溃**；差分主要验证了成熟库在常规随机输入上的一致性。
CT oracle 经对照验证有效，并按预期在 ML-DSA/Falcon 签名上触发（已知变时，非新漏洞）。
最值钱的改进仍是 **A（对抗性边界语料 + 打开被屏蔽的 X25519 低阶点 oracle）** 与 **B（验签交叉矩阵）**，
其次是 **E（CT 结果按算法分级以降噪）**。
