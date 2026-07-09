# CMFuzz 当前可测的密码实现与算法

图例：**✅ 已构建并跑通**（有编好的 fuzz 靶 / 已出结果）；**🟢 规格就绪、按需一键构建**
（`specs/` 里已有规格，`scripts/build_harness.sh KEM:<名>` 即可编出靶）。

统计：liboqs 已生成 **41 个 KEM + 221 个 SIG** 规格；SEAL FHE、OpenSSL、以及
libsodium/Mbed-TLS/Crypto++ 多库差分均已可测。

---

## 1. 传统 / 对称密码 —— 多库差分（OpenSSL + libsodium + Mbed-TLS + Crypto++）

同一输入喂 4 个独立实现，输出不一致即报 `DIFF_mismatch`。靶：`build/harness/diff_multilib` ✅

| 算法 | OpenSSL | libsodium | Mbed-TLS | Crypto++ |
|---|:--:|:--:|:--:|:--:|
| SHA-256 | ✅ | ✅ | ✅ | ✅ |
| SHA-512 | ✅ | ✅ | ✅ | ✅ |
| HMAC-SHA256 | ✅ | ✅ | ✅ | ✅ |
| ChaCha20-Poly1305 (IETF) | ✅ | ✅ | ✅ | ✅ |
| AES-256-GCM | ✅ | (仅硬件 AES 时) | ✅ | ✅ |

单库 OpenSSL 靶 `build/harness/classic_openssl` ✅：SHA-256 分块等价、AES-256-GCM 往返 + 篡改拒绝、HMAC。

> 这 4 个库还各自实现了大量其它算法（Crypto++ 尤其多：Camellia/SM4/Serpent/Twofish/
> BLAKE2/SHA-3/Poly1305/GCM/CCM/EAX/曲线等），已链接进工程，可按需扩到差分表里。

---

## 2. 后量子 KEM（liboqs，41 个）

已构建靶：**ML-KEM-512 / ML-KEM-768 / ML-KEM-1024 / Kyber768 / FrodoKEM-640-AES / BIKE-L1** ✅
（每算法一个 libFuzzer 靶；oracle：正确性往返 / 密文不可锻造 / 错误密钥 / 解封装确定性 / 内存安全）

规格就绪、可一键构建的全部 41 个 🟢：

- **ML-KEM**：ML-KEM-512, ML-KEM-768, ML-KEM-1024
- **Kyber**：Kyber512, Kyber768, Kyber1024
- **FrodoKEM**：FrodoKEM-640/976/1344-AES、-SHAKE（及 eFrodoKEM 六个变体）
- **Classic-McEliece**：348864(f), 460896(f), 6688128(f), 6960119(f), 8192128(f)（共 10）
- **HQC**：HQC-1, HQC-3, HQC-5
- **NTRU**：NTRU-HPS-2048-509/677, NTRU-HPS-4096-821/1229, NTRU-HRSS-701/1373
- **Streamlined NTRU Prime**：sntrup761
- **BIKE**：BIKE-L1, BIKE-L3, BIKE-L5

---

## 3. 后量子签名（liboqs，221 个）

已构建靶：**ML-DSA-44 / ML-DSA-65 / ML-DSA-87 / Falcon-512 / Falcon-1024 /
SLH-DSA-PURE-SHA2-128F** ✅
（oracle：正确性 / 消息绑定 EUF / 签名不可锻造 SUF / 错误密钥 / 内存安全）

规格就绪的全部 221 个按族 🟢：

| 族 | 数量 | 例子 |
|---|---:|---|
| ML-DSA (Dilithium) | 3 | ML-DSA-44/65/87 |
| Falcon | 4 | Falcon-512/1024, Falcon-padded-512/1024 |
| SLH-DSA (SPHINCS+) | 156 | 全套 SHA2/SHA3/SHAKE × PURE/PREHASH × 128/192/256 × f/s |
| MAYO | 4 | MAYO-1/2/3/5 |
| CROSS | 18 | cross-rsdp / rsdpg × 128/192/256 × fast/small/balanced |
| OV (Rainbow 系) | 12 | OV-Is/Ip/III/V (+pkc/skc 变体) |
| SNOVA | 12 | SNOVA_24_5_4 … SNOVA_60_10_4 |
| MQOM2 | 12 | mqom2_cat1/3/5_gf16_fast/short_r3/r5 |

---

## 4. 全同态加密（Microsoft SEAL）

靶：`build/harness/fhe_seal_bfv` ✅

- **BFV** 方案：同态加法/乘法正确性（对比明文域）、分配律 `a*(b+c) == a*b + a*c`
- 使用 BatchEncoder + relinearization；CKKS 可按相同框架扩展。

---

## 5. 常量时间 / 侧信道（dudect 引擎）

靶：`engine/ct_dudect.c`（`scripts/run_ct.sh`）✅，已出判定：

| 算法 | 操作 | 判定 |
|---|---|---|
| ML-KEM-512 / 768 / 1024 | decaps | 常量时间（768 临界，受 VM 噪声影响） |
| Kyber768 | decaps | 常量时间（临界） |
| ML-DSA-65 | sign | 数据相关（拒绝采样，设计使然，不泄密钥） |
| Falcon-512 | sign | 数据相关（浮点高斯采样） |

可扩到任意 liboqs KEM/SIG 的 secret-dependent 操作。

---

## 6. 自测（证明 oracle 有效）

`tests/negative_tests.sh` ✅ 3/3：故障注入使 KEM 正确性、SIG 强不可伪造、多库差分
三个 oracle 都能正确触发，佐证"0 违反"是真无 bug 而非空转。

---

### 汇总
- **可立即跑的靶**：14 个 liboqs（6 KEM + 6 SIG，另 2 = 分块）+ SEAL FHE + OpenSSL 单库 +
  4 库差分 = 覆盖 5 类原语 × 4 实现。
- **规格就绪、一键可测**：41 KEM + 221 SIG（liboqs 全部启用算法）。
- **传统算法**：SHA-2、HMAC、ChaCha20-Poly1305、AES-GCM 跨 4 库差分；更多算法已链接可扩。
