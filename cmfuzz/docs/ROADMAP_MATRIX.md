# CMFuzz 目标实现路线图矩阵（现状 + 未来）

本文把调研到的**所有**密码库（不限语言）整理成"未来要接入的被测实现与算法"矩阵。
分三部分：① 库级路线图（含语言/star/构建/优先级/状态）② 算法 × 实现覆盖矩阵
③ 分阶段落地计划。

图例：**✅ 已接入并跑通** · **🟡 进行中** · **⬜ 计划接入（本路线图目标）**
优先级：**P0 立刻** · **P1 近期** · **P2 中期** · **P3 探索**

---

## 一、库级路线图

### A. C / C++ 大库（差分主力，OSS-Fuzz/Cryptofuzz 同款目标）

| # | 库 | 语言 | Star | 构建 | 接入方式 | 优先级 | 状态 |
|---|---|---|---:|---|---|---|---|
| 1 | OpenSSL | C/asm | 30k | 系统/源码 | EVP 直接链接 | P0 | ✅ |
| 2 | libsodium | C | 13.7k | autotools | 静态库链接 | P0 | ✅ |
| 3 | Mbed-TLS | C | 6.7k | cmake | 静态库链接 | P0 | ✅ |
| 4 | Crypto++ | C++ | 5.5k | make | 静态库链接 | P0 | ✅ |
| 5 | **BoringSSL** | C/C++ | 6.9k | cmake | 独立靶（符号与 OpenSSL 冲突，需单独二进制） | P1 | ⬜ |
| 6 | **LibreSSL** | C | — | autotools | 独立靶 | P1 | ⬜ |
| 7 | **aws-lc** | C | 0.8k | cmake | 独立靶（Wycheproof 已测） | P1 | ⬜ |
| 8 | **wolfSSL / wolfCrypt** | C | 2.9k | autotools | 静态库链接 | P1 | ⬜ |
| 9 | **Botan** | C++ | 3.3k | configure.py | 静态库链接（含 PQC/侧信道） | P1 | ⬜ |
| 10 | **libgcrypt** | C | — | autotools | 静态库链接 | P2 | ⬜ |
| 11 | **NSS** (freebl) | C | — | gyp/make | 独立靶 | P2 | ⬜ |
| 12 | **GnuTLS / nettle** | C | — | autotools | 静态库链接 | P2 | ⬜ |
| 13 | **OpenTitan cryptolib** | C | — | bazel | 独立靶 | P3 | ⬜ |

### B. Rust（跨语言差分 + 内存安全对照）

| # | 库 | Star | 接入方式 | 优先级 | 状态 |
|---|---|---:|---|---|---|
| 14 | **RustCrypto**（sha2/hmac/aes-gcm/chacha20poly1305/…） | 各 0.8–2.2k | cbindgen/FFI 或子进程桥 | P1 | ⬜ |
| 15 | **ring** | 4.1k | FFI（已是 C ABI 友好） | P1 | ⬜ |
| 16 | **dalek**（curve25519/ed25519/x25519） | — | FFI，做 X25519/Ed25519 差分 | P2 | ⬜ |
| 17 | **bc-rust**（BouncyCastle Rust） | — | FFI | P3 | ⬜ |

### C. Go / Java / Python / Swift / Zig（生态差分）

| # | 库 | 语言 | 接入方式 | 优先级 | 状态 |
|---|---|---|---|---|---|
| 18 | **Go `crypto/*`** | Go | 子进程：go 小程序读 stdin 测试向量、回 stdout | P1 | ⬜ |
| 19 | **BouncyCastle (bc-java)** | Java | 子进程 JVM 桥 | P2 | ⬜ |
| 20 | **PyCryptodome** | Python | 子进程 python 桥 | P2 | ⬜ |
| 21 | **pyca/cryptography** | Python(+OpenSSL) | 子进程桥 | P2 | ⬜ |
| 22 | **Tink**（C++/Java/Go） | 多 | 高层 API 误用测试 | P2 | ⬜ |
| 23 | **swift-crypto** | Swift | 子进程桥 | P3 | ⬜ |
| 24 | **Zig std.crypto** | Zig | 子进程桥 | P3 | ⬜ |

### D. 后量子 PQC

| # | 库 | 接入方式 | 优先级 | 状态 |
|---|---|---|---|---|
| 25 | **liboqs**（41 KEM + 221 SIG） | 每算法 libFuzzer 靶 | P0 | ✅（规格全就绪，6+6 已编靶） |
| 26 | **PQClean** | 每算法靶，与 liboqs 做 PQC **跨库差分** | P1 | ⬜ |
| 27 | **pqcrystals**（kyber/dilithium 官方参考） | 靶 + 差分 | P2 | ⬜ |
| 28 | **旧版 liboqs**（复现 CIFT/CVE 已知 bug） | 版本回退跑现有靶 | P1 | ⬜ |

### E. 全同态 FHE / 零知识 ZK

| # | 库 | 语言 | 接入方式 | 优先级 | 状态 |
|---|---|---|---|---|---|
| 29 | **Microsoft SEAL**（BFV/CKKS） | C++ | property 靶 | P0 | ✅（BFV，CKKS 待扩） |
| 30 | **OpenFHE**（BGV/BFV/CKKS/TFHE） | C++ | property 靶 + 跨库差分 SEAL | P1 | ⬜ |
| 31 | **HElib** | C++ | property 靶 | P2 | ⬜ |
| 32 | **TFHE-rs**（Zama） | Rust | FFI property 靶 | P2 | ⬜ |
| 33 | **ZK：libsnark / arkworks / gnark** | C++/Rust/Go | 电路一致性/证明验证 oracle | P3 | ⬜ |

---

## 二、算法 × 实现覆盖矩阵（未来目标）

单元格含义：✅ 已可测 · ⬜ 目标接入 · —— 该库无此算法

### 对称 / AEAD / 哈希 / MAC / KDF

| 算法 | OpenSSL | libsodium | mbedTLS | Crypto++ | BoringSSL | wolfCrypt | Botan | RustCrypto | Go | BouncyCastle |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| SHA-256/512 | ✅ | ✅ | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| SHA-3 / SHAKE | ⬜ | —— | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| BLAKE2/3 | ⬜ | ✅ | —— | ⬜ | —— | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| HMAC | ✅ | ✅ | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| KMAC/cSHAKE | ⬜ | —— | —— | ⬜ | —— | ⬜ | ⬜ | ⬜ | —— | ⬜ |
| AES-GCM | ✅ | ✅ | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| AES-GCM-SIV | ⬜ | —— | —— | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| AES-CCM/EAX/OCB | ⬜ | —— | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| ChaCha20-Poly1305 | ✅ | ✅ | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| (X)Salsa20 | —— | ✅ | —— | ⬜ | —— | —— | ⬜ | ⬜ | ⬜ | ⬜ |
| AEGIS / Ascon | ⬜ | ✅ | —— | ⬜ | ⬜ | —— | ⬜ | ⬜ | —— | ⬜ |
| Camellia/ARIA/SEED/SM4 | ⬜ | —— | ⬜ | ⬜ | —— | ⬜ | ⬜ | ⬜ | —— | ⬜ |
| HKDF/PBKDF2/scrypt/Argon2 | ⬜ | ✅ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |

### 公钥 / 曲线 / 签名（经典）

| 算法 | OpenSSL | mbedTLS | Crypto++ | BoringSSL | wolfCrypt | Botan | RustCrypto/dalek | Go | BouncyCastle |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| RSA (PKCS1/PSS/OAEP) | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| ECDSA (P-256/384/521) | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| Ed25519 | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜(dalek) | ⬜ | ⬜ |
| X25519/X448 | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜(dalek) | ⬜ | ⬜ |
| ECDH (P-curves) | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| DSA/DH | ⬜ | ⬜ | ⬜ | —— | ⬜ | ⬜ | —— | ⬜ | ⬜ |
| SM2 / BLS12-381 | ⬜ | —— | —— | —— | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |

### 后量子 PQC（KEM / 签名）

| 算法 | liboqs | PQClean | pqcrystals | Botan | wolfCrypt | 备注 |
|---|:-:|:-:|:-:|:-:|:-:|---|
| ML-KEM / Kyber | ✅ | ⬜ | ⬜ | ⬜ | ⬜ | 跨库差分目标 |
| ML-DSA / Dilithium | ✅ | ⬜ | ⬜ | ⬜ | —— | 跨库差分目标 |
| Falcon | ✅ | ⬜ | —— | ⬜ | —— | |
| SLH-DSA / SPHINCS+ | ✅ | ⬜ | —— | ⬜ | —— | |
| Frodo/McEliece/HQC/BIKE/NTRU | ✅ | ⬜ | —— | ⬜ | —— | |
| MAYO/CROSS/OV/SNOVA/MQOM2 | ✅ | —— | —— | —— | —— | liboqs 独有 |

### FHE / ZK

| 能力 | SEAL | OpenFHE | HElib | TFHE-rs | 备注 |
|---|:-:|:-:|:-:|:-:|---|
| BFV/BGV 同态正确性/分配律 | ✅ | ⬜ | ⬜ | —— | SEAL↔OpenFHE 跨库差分 |
| CKKS 近似算术（误差界 oracle） | ⬜ | ⬜ | ⬜ | —— | |
| TFHE 布尔/整数门 | —— | ⬜ | —— | ⬜ | |
| ZK 证明验证 / 电路一致性 | —— | —— | —— | —— | arkworks/gnark/libsnark（P3） |

---

## 三、分阶段落地计划

- **阶段 1（P0，已完成）**：OpenSSL + libsodium + mbedTLS + Crypto++ 对称/哈希/AEAD 多库差分；
  liboqs PQC（262 规格）；SEAL BFV；dudect 常量时间；负向自测。
- **阶段 2（P1，近期）**：
  1. 差分再加 **BoringSSL / aws-lc / wolfCrypt / Botan**（4→8 库），并把差分算法扩到
     SHA-3、AES-CCM/EAX/OCB、AES-GCM-SIV、RSA/ECDSA/Ed25519/X25519。
  2. 接 **PQClean**，与 liboqs 做 **PQC 跨库差分**；回退**旧版 liboqs**复现 CIFT/CVE 真实 bug。
  3. 跨语言：**Go crypto** 子进程桥 + **RustCrypto/ring** FFI，做跨语言差分。
  4. FHE：接 **OpenFHE**，与 SEAL 做 BFV 跨库差分；SEAL 扩 **CKKS**（带误差界 oracle）。
- **阶段 3（P2）**：libgcrypt/NSS/nettle、BouncyCastle(Java)/PyCryptodome/pyca 子进程桥、
  dalek 曲线差分、TFHE-rs/HElib。
- **阶段 4（P3，探索）**：Tink 高层 API 误用、swift-crypto/Zig、ZK（arkworks/gnark/libsnark）。

### 工程支撑（为大规模接入准备）
- 统一"测试向量编码"（算法 id + 输入槽），让 C 链接库、Rust FFI、子进程桥共用同一输入。
- 差分结果自动**根因定位**：多数一致、少数偏离 → 指认可疑实现。
- 每库独立 sanitizer 靶（内存 bug）+ 统一差分/metamorphic/常量时间三 oracle。
