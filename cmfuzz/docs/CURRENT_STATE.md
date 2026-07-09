# CMFuzz 当前状态（CURRENT_STATE）

> 维护说明：这是**活文档**，只记录"此刻真正做好、跑通"的实现与算法（小而稳的测试集）。
> 每次新增/验证一个实现或算法，就更新这里；未来目标不写这里（见 `docs/ROADMAP_MATRIX.md`）。
> 最近更新：2026-07-09。

## 0. 一句话现状
在一个**小而扎实**的测试集上，三支柱（规格+oracle / 功能+常量时间双检测 / PQC·FHE·多库差分）
端到端跑通：**6 个实现库 × 5 类原语 + PQC(262 规格) + FHE**，0 误报，且有故障注入自测证明 oracle 有效。

---

## 1. 已接入的实现（库 + 版本）

| 库 | 版本 | 语言 | 构建产物 | 用途 |
|---|---|---|---|---|
| OpenSSL | 3.0.2 | C | 系统 libcrypto | 传统算法（差分 + 单库靶） |
| libsodium | 1.0.23 | C | `libs/libsodium/build/lib/libsodium.a` | 传统算法差分 |
| Mbed-TLS | 3.6.2 | C | `libs/mbedtls/build/library/libmbedcrypto.a` | 传统算法差分 |
| Crypto++ | 8.9.0 | C++ | `libs/cryptopp/libcryptopp.a` | 传统算法差分 |
| liboqs | 0.16.0-rc1 | C | `libs/liboqs/build/lib/liboqs.a` | PQC KEM/签名 |
| Microsoft SEAL | 4.3.3 | C++ | `libs/SEAL/build/lib/libseal-4.3.a` | FHE(BFV) |

---

## 2. 已跑通的算法（当前测试集）

传统算法现在被**四重 oracle**覆盖：差分 + metamorphic + 常量时间 + 内存安全。

**(a) 差分**（同一输入喂多实现，逐一比对）——靶：`build/harness/diff_multilib`（~3.1M runs/90s，cov 1268，**0 差异**）

| 算法 | OpenSSL | libsodium | Mbed-TLS | Crypto++ |
|---|:-:|:-:|:-:|:-:|
| SHA-256 | ✅ | ✅ | ✅ | ✅ |
| SHA-512 | ✅ | ✅ | ✅ | ✅ |
| HMAC-SHA256 | ✅ | ✅ | ✅ | ✅ |
| ChaCha20-Poly1305 (IETF) | ✅ | ✅ | ✅ | ✅ |
| AES-256-GCM | ✅ | (仅硬件AES) | ✅ | ✅ |

**(b) metamorphic**（单实现即可，用密码学定义本该成立的关系）——靶：`build/harness/trad_metamorphic`（~4.2M runs, cov 26, **0 违反**）

| 算法 | metamorphic 关系 |
|---|---|
| SHA-256 | 确定性 `H(m)==H(m)`；分块一致 `H(m)==update(m[:k]);update(m[k:])` |
| HMAC-SHA256 | 确定性；密钥敏感（翻转 key 一位 → tag 必变） |
| AES-256-GCM | 往返 `Dec(Enc(m))==m`；篡改拒绝（改 1 位 ct/tag → 解密失败）；错误密钥失败 |
| ChaCha20-Poly1305 | 往返；篡改拒绝；错误密钥失败 |

**(c) 常量时间**（dudect，见 §3）；**(d) 内存安全**（ASan/UBSan，全靶）。

单库 OpenSSL 靶 `build/harness/classic_openssl` ✅：SHA-256 分块等价、AES-256-GCM 往返+篡改拒绝、HMAC。

### 2.2 后量子 KEM —— liboqs（已编靶 6 个）
靶：`build/harness/kem_<名>`；oracle：正确性往返 / 密文不可锻造 / 错误密钥 / 解封装确定性 / 内存安全

| 算法 | 实现来源 | 状态 |
|---|---|---|
| ML-KEM-512 / 768 / 1024 | mlkem-native | ✅ |
| Kyber768 | pqcrystals(R3) | ✅ |
| FrodoKEM-640-AES | FrodoKEM 团队 | ✅ |
| BIKE-L1 | BIKE 团队 | ✅ |

### 2.3 后量子签名 —— liboqs（已编靶 6 个）
靶：`build/harness/sig_<名>`；oracle：正确性 / 消息绑定 EUF / 签名不可锻造 SUF / 错误密钥 / 内存安全

| 算法 | 实现来源 | 状态 |
|---|---|---|
| ML-DSA-44 / 65 / 87 | mldsa-native | ✅ |
| Falcon-512 / 1024 | PQClean | ✅ |
| SLH-DSA-PURE-SHA2-128F | SPHINCS+/SLH-DSA 参考 | ✅ |

> 另：liboqs 全部 **41 KEM + 221 SIG** 已生成规格 JSON（`specs/`），可一键编靶，但"当前测试集"
> 只锁定上面已实测的 12 个，保证每个都验证过再逐步纳入。

### 2.4 全同态加密 —— SEAL
靶：`build/harness/fhe_seal_bfv` ✅：BFV 同态加/乘正确性、分配律 `a*(b+c)==a*b+a*c`。

### 2.5 L2 组合层 —— HPKE（KEM + KDF + AEAD）【新】
把测试从单原语(L1)抬到**组合层(L2)**：按 HPKE 方式把 KEM→HKDF-SHA256→AES-256-GCM 串起来，
手工组合（OpenSSL 3.0.2 无 OSSL_HPKE_* API），两种 KEM 后端：

| 靶 | KEM 后端 | campaign | 结果 |
|---|---|---|---|
| `build/harness/comp_hpke_x25519` | X25519 (OpenSSL) | ~0.28M runs/60s | 0 违反 |
| `build/harness/comp_hpke_mlkem` | ML-KEM-768 (liboqs) | ~3.3M runs/60s | 0 违反 |

组合不变量 oracle（O5）：
- **O5-roundtrip**：接收端 `open(seal(m))==m`（decaps→key schedule→AEAD 全链路）。
- **O5-context-binding**：open 时改 info/aad → 必须失败（HPKE 上下文绑定）。
- **O5-upstream-tamper**：篡改封装密钥 `enc` → 接收端派生出不同共享密钥 → open 必须失败。
  这正是"单原语(L1)可能判为良性 feature 的可锻造性，在组合层暴露为端到端失败"的体现。

---

## 3. 已跑通的检测能力（oracle）

| 类型 | 内容 | 状态 |
|---|---|---|
| 功能 metamorphic | KEM 正确性、SIG EUF/SUF、AEAD 往返/篡改拒绝、错误密钥 | ✅ |
| **L2 组合(O5)** | HPKE 往返 / 上下文绑定 / 上游篡改放大（X25519 + ML-KEM-768） | ✅ |
| 差分 | 同算法跨 4 库输出一致性 | ✅ |
| 内存安全 | ASan + UBSan（全靶插桩） | ✅ |
| 常量时间 | dudect（Welch t，|t|>4.5）：**PQC**—ML-KEM decaps、Kyber768 decaps、ML-DSA-65 sign、Falcon-512 sign；**传统**—AES-256 块加密、CRYPTO_memcmp、naive_memcmp | ✅ |

传统常量时间结果（`engine/ct_dudect_trad.c`，pin 到单核）：

| op | 说明 | max_t | 判定 |
|---|---|---:|---|
| aes256_enc | AES-NI 块加密（数据无关） | 2.47 | OK |
| crypto_memcmp | OpenSSL 常量时间比较 | 1.32 | OK |
| naive_memcmp | 逐字节提前返回的比较（故意变时） | 709 | **LEAK** |

`crypto_memcmp`(OK) vs `naive_memcmp`(LEAK) 是同一"比较 tag"任务的两种写法，引擎准确区分——
证明常量时间 oracle 对传统算法同样有效。

---

## 4. 自测（证明"0 违反"不是空转）
`tests/negative_tests.sh` ✅ **5/5**：故障注入使以下 oracle 全部正确触发——
KEM 正确性(MR1)、SIG 强不可伪造(MR3)、传统 AEAD 篡改拒绝(tamper_reject)、
**L2 HPKE 组合上游篡改(O5-upstream-tamper)**、多库差分(DIFF_mismatch)。

---

## 5. 复现命令
```
scripts/build_all.sh            # 建库 + 生成规格 + 编所有靶（含差分）
tests/negative_tests.sh         # 3/3 oracle 自测
build/harness/diff_multilib -max_len=1024 <corpus>   # 多库差分campaign
scripts/run_campaign.sh         # 全靶功能campaign
scripts/run_ct.sh               # 常量时间检测
```

---

## 6. 变更记录
- 2026-07-09（傍晚）：**PLAN 阶段1.1** —— 新增 **L2 组合层 HPKE harness**
  (`harness/comp_hpke_harness.c`，X25519 + ML-KEM-768 两后端)，组合不变量 oracle O5
  （往返 / 上下文绑定 / 上游篡改放大）。两靶 campaign 0 违反；负向自测升到 **5/5**。
  发现库结构 `findings/` 建立（本阶段 0 新发现）。
- 2026-07-09（下午）：给传统算法补齐 **metamorphic**（`trad_metamorphic`：SHA-256 分块一致/
  确定性、HMAC 确定性/密钥敏感、AEAD 往返/篡改拒绝/错误密钥）和 **常量时间**
  （`ct_dudect_trad`：AES-NI、CRYPTO_memcmp、naive_memcmp）两类 oracle；负向自测升到 4/4。
  至此传统算法被差分+metamorphic+常量时间+内存安全四重覆盖。
- 2026-07-09：接入 libsodium/Mbed-TLS/Crypto++，新增多库差分靶（SHA-256/512、HMAC、
  ChaCha20-Poly1305、AES-256-GCM），差分自测通过；建立本活文档。
- 之前：liboqs PQC(12 靶) + SEAL BFV + OpenSSL 单库 + dudect + KEM/SIG 负向自测。
