# CMFuzz 代码盲区清单（基于当前 HEAD 代码审查）

日期 2026-07-09。按「差距/性价比」排序。每条尽量给出代码依据。

## A. 原语覆盖盲区 —— 差分只测了 15 个 op（compute_common.h）
测了：SHA-256/512、HMAC-SHA256、ChaCha20-Poly1305、AES-256-GCM、SHA3-256/512、
SHAKE128/256、HKDF-SHA256、PBKDF2-SHA256、Ed25519、X25519、ECDSA-P256 验签、RSA-PSS 验签。
**完全没覆盖**：
- 对称：AES-CBC/CTR/XTS/CCM/SIV、AES-128/192（只有 256）、ChaCha20 裸流、CMAC/GMAC/KMAC、
  Poly1305 独立、3DES 等 legacy。
- 哈希：**SHA-1 / MD5（legacy，正是弃用/行为差异高发区）**、SHA-224、SHA-512/224/256、
  SHA3-224/384、BLAKE2/BLAKE3、SM3、cSHAKE/KMAC。
- KDF：scrypt、Argon2、HKDF-Expand-only、SSKDF/X9.63、TLS1.3 KDF、非 SHA256 的 PBKDF2。
- 公钥：**RSA-OAEP / PKCS1v15 加密、RSA PKCS1v15 签名、ECDSA P-384/P-521/secp256k1、
  ECDH、Ed448/X448、DSA/DH**。
- 参数单一（写死→测不到参数相关分歧）：AEAD 只 12B nonce/16B tag；HMAC 只 SHA256；
  PBKDF2 固定 4096 iters/32B；RSA 固定 2048/e=65537/salt=32；ECDSA 固定 P-256。

## B. 输入分布盲区（最大盲区）
- `diff_subproc_runner.c` 用纯 splitmix64 均匀随机，`msglen=rnd()%512`、`aadlen=rnd()%64`。
  永远打不到边界：超长(>512)、块边界(15/16/17/31/32/33/63/64/65)、全零/全 FF key、弱密钥。
- **X25519 主动 `blob[need-1] &= 0x7F` 屏蔽 bit255 并回避低阶点** —— 把最有价值的库间差异
  （非规范坐标/低阶点是否拒绝、是否返回全零）直接关掉了。
- 无字典 / 无种子语料 / 非覆盖引导：子进程差分是纯随机，不吃 libFuzzer 的 corpus/`-dict`。

## C. Oracle 设计盲区
- **星型单参照**：只做 OpenSSL↔后端，OpenSSL 与某后端共享 bug 时不可见；无 all-pairs / 多数表决。
- **只正向**：AEAD 只比 encrypt 输出，不跨库比 decrypt / 篡改拒绝（篡改拒绝只在独立 metamorphic 靶）。
- **验签太弱**（op13/14）：签名全由 OpenSSL 生成 + 仅 1-bit tamper，只比 accept/reject 一个比特。
  测不到 high-S 可锻性、DER/SEC1 非规范编码、r/s=0、PSS salt 边界、非规范 padding —— 验签器真正易错处。
- **NA 静默跳过**：后端回 `NA` 直接跳过不校验，能掩盖「本应实现却错误回 NA」的 bug。
- **ERR vs 有效输出误报点**：参照失败存 "ERR"，后端成功则报分歧（最可能命中 X25519 低阶点）。

## D. PQC 盲区（定量差距最大）
- `specs/kem` 有 ~40 个、`specs/sig` 有 ~200 个规格文件（Classic-McEliece/HQC/NTRU/MAYO/OV/
  CROSS/SNOVA/mqom2/全部 SLH-DSA 变体…），但**只构建了 6 个 KEM + 6 个 SIG 的 libFuzzer 靶**。
  绝大多数算法从未被跑过。
- 跨库 PQC 差分 `pqc_diff` **只覆盖 ML-KEM-768 + ML-DSA-65**（liboqs↔PQClean）；其余 PQC 全是
  单库 liboqs 自洽 round-trip，无第二实现比对。
- **无 KAT / NIST 已知答案向量比对** —— 这是最能抓编码/字节序 bug 的手段，却没做。
- 无跨库编码互操作（A 库封装的密文/公钥喂给 B 库解封装），只在同库内 round-trip。

## E. 多库差分（diff_multilib）盲区
- 只比 4 类：SHA-256/512、HMAC-SHA256、ChaCha20-Poly1305、AES-256-GCM（4 库 OpenSSL/
  libsodium/MbedTLS/Crypto++）。**没有 SHA3 / 公钥 / KDF 的多库比对**。

## F. ZK / TFHE / FHE 盲区
- ZK：单电路（a*b=c）、单库 arkworks 自证自验；无第二 ZK 库、无畸形证明/被篡改 CRS 语料、无其它电路。
- TFHE：单库 tfhe-rs 自洽（Dec(Enc(a)⊕Enc(b))==a⊕b），无跨库 FHE 整数比对。
- CKKS：单库 SEAL 误差界自检，无跨库。
- FHE 跨库仅 `fhe_diff`（OpenFHE↔SEAL BFV，且 t=65537 单参数）。

## G. 恒定时间（dudect）盲区
- 只测 ML-KEM/Kyber decaps + ML-DSA/Falcon sign + 3 个传统对照。
  **没测**：RSA 解密（Bleichenbacher/时序）、ECDSA 标量乘、AES-CBC padding（Lucky13 类）、
  HMAC verify、KEM encaps、base64/PEM 解析。
- dudect 对签名类「设计变时」算法（ML-DSA/Falcon）会稳定报 LEAK → 需按算法分级/白名单，否则淹没真信号。

## H. 工程 / 运行盲区
- `run_campaign.sh` 会把非 libFuzzer 的 compute_*/diff_subproc/cmf_*/fhe_diff 也当靶跑，浪费预算+噪声，需过滤。
- 子进程差分用 `popen("'%s' < '%s'")` 单引号拼路径，路径含单引号即破。
- 覆盖率偏低的靶（seq_pqc_kem cov=5、comp_authkem_pqc cov=10）说明缺初始语料/字典。
- Go / wolfCrypt / Swift / Zig 后端因本机工具链缺失**从未在本机跑过**，实际「独立血统数」被高估。

## 优先级建议（性价比）
1. **B + C**：加对抗性边界语料，**打开被屏蔽的 X25519 低阶点并做成 oracle**；验签改交叉签/验矩阵 + 畸形编码。
2. **D**：接 KAT/NIST 向量比对，扩 pqc_diff 覆盖更多 KEM/SIG，跨库编码互操作。
3. **A**：补 legacy 哈希(SHA-1/MD5)、RSA 加密、更多曲线/参数 —— 低成本高命中。
4. **G/E/H**：CT 按算法分级、多库差分扩到 SHA3/公钥、run_campaign 过滤靶列表。
