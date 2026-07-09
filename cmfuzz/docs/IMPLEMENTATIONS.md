# CMFuzz 被测「实现」清单（算法 → 具体实现）

每个算法测的是哪一份具体代码：库 + 版本 + 上游来源 + 代码变体。

## 库版本（本 VM 实际构建的）

| 库 | 版本 / commit | 语言 | 构建配置 |
|---|---|---|---|
| **liboqs** | 0.16.0-rc1 (`b5df181`) | C | `OQS_DIST_BUILD=1`，编译 portable + x86_64 变体，运行时按 CPU 特性选择；AVX2 专用路径未开启 |
| **Microsoft SEAL** | v4.3.3 (`02a5c34`) | C++ | Release 静态库 |
| **OpenSSL** | 3.0.2（系统库 libcrypto） | C/asm | 默认 provider（EVP） |
| **libsodium** | 1.0.23 | C | 静态库，ASan+coverage 插桩 |
| **Mbed-TLS** | 3.6.2（LTS） | C | 静态库，ASan+coverage 插桩 |
| **Crypto++** | 8.9.0 | C++/asm | 静态库，ASan+coverage 插桩 |

---

## 1. 传统 / 对称算法 —— 每个算法 4 份独立实现（差分）

| 算法 | OpenSSL 3.0.2 | libsodium 1.0.23 | Mbed-TLS 3.6.2 | Crypto++ 8.9.0 |
|---|---|---|---|---|
| SHA-256 | `EVP_sha256`（默认 provider） | `crypto_hash_sha256`（ref） | `mbedtls_sha256` | `CryptoPP::SHA256` |
| SHA-512 | `EVP_sha512` | `crypto_hash_sha512` | `mbedtls_sha512` | `CryptoPP::SHA512` |
| HMAC-SHA256 | `HMAC`+`EVP_sha256` | `crypto_auth_hmacsha256` | `mbedtls_md_hmac` | `HMAC<SHA256>` |
| ChaCha20-Poly1305 | `EVP_chacha20_poly1305` | `crypto_aead_chacha20poly1305_ietf` | `mbedtls_chachapoly` | `ChaCha20Poly1305` |
| AES-256-GCM | `EVP_aes_256_gcm`（含 AES-NI） | `crypto_aead_aes256gcm`（仅硬件 AES 时） | `mbedtls_gcm` | `GCM<AES>` |

即"同一算法 × 4 实现"逐一比对；OpenSSL 版另有单库 harness（分块等价 / 往返 / 篡改拒绝）。

---

## 2. 后量子 KEM —— 实现全部来自 liboqs 集成的上游参考/优化代码

| 算法族 | 上游实现来源 | 代码变体（本 VM 运行时可选） |
|---|---|---|
| **ML-KEM** (512/768/1024) | **mlkem-native**（FIPS 203） | `..._ref`（可移植 C）/ `..._x86_64` |
| **Kyber** (512/768/1024) | pqcrystals-kyber（Round 3） | clean / 优化 |
| **FrodoKEM** / eFrodoKEM | FrodoKEM 团队参考实现 | ref |
| **Classic-McEliece** | Classic McEliece 团队（含 f 变体） | ref / vec |
| **HQC** (1/3/5) | HQC 团队参考实现 | ref |
| **NTRU** (HPS/HRSS) | PQClean | clean |
| **sntrup761** | Streamlined NTRU Prime 团队 | ref |
| **BIKE** (L1/L3/L5) | BIKE 团队 | 优化（GF2X） |

已编靶：ML-KEM-512/768/1024、Kyber768、FrodoKEM-640-AES、BIKE-L1。其余 41 个规格就绪。

---

## 3. 后量子签名 —— 同样来自 liboqs 集成的上游代码

| 算法族 | 上游实现来源 | 代码变体 |
|---|---|---|
| **ML-DSA** (44/65/87) | **mldsa-native**（FIPS 204） | `..._ref` / `..._x86_64` |
| **Falcon** (512/1024, padded) | **PQClean**（Falcon 团队） | `..._clean`（AVX2 未开启） |
| **SLH-DSA** (156 参数) | SLH-DSA / SPHINCS+ 参考实现 | ref |
| **MAYO** (1/2/3/5) | MAYO 团队 | ref / opt |
| **CROSS** (rsdp/rsdpg) | CROSS 团队 | ref |
| **OV / UOV** (Is/Ip/III/V) | UOV 团队 | ref |
| **SNOVA** | SNOVA 团队 | ref |
| **MQOM2** | MQOM 团队 | ref |

已编靶：ML-DSA-44/65/87、Falcon-512/1024、SLH-DSA-PURE-SHA2-128F。其余 221 个规格就绪。

> 说明：liboqs 是"集成层"，本身不重写算法，而是 vendored 各 NIST 提交团队 / PQClean /
> mlkem-native / mldsa-native 的实现。因此 PQC 这一档测的是**这些上游参考/优化实现**，
> 版本随 liboqs 0.16.0-rc1 锁定。

---

## 4. 全同态加密

| 方案 | 实现 |
|---|---|
| **BFV** | Microsoft SEAL 4.3.3（BatchEncoder + Evaluator + relinearization） |

（CKKS 同库可扩。）

---

## 5. 常量时间（同一份实现，测时序而非功能）

针对 liboqs 上述实现的 secret-dependent 操作做 dudect 测量：
- ML-KEM-512/768/1024 `decaps`（mlkem-native）
- Kyber768 `decaps`
- ML-DSA-65 `sign`（mldsa-native）
- Falcon-512 `sign`（pqclean clean）

---

### 一句话总结
- **传统算法**：OpenSSL / libsodium / Mbed-TLS / Crypto++ 各自的实现，4 份互相差分。
- **PQC**：liboqs 0.16.0-rc1 集成的上游实现（mlkem-native、mldsa-native、PQClean-Falcon、
  SPHINCS+/SLH-DSA、以及 Kyber/Frodo/McEliece/HQC/NTRU/BIKE/MAYO/CROSS/OV/SNOVA/MQOM2 各团队代码）。
- **FHE**：Microsoft SEAL 4.3.3 BFV。
