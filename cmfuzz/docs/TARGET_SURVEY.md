# 被测密码库与算法调研 + CMFuzz 目标矩阵

目的：调研其它 fuzzing / 测试论文与工程都拿哪些密码库当被测目标，再在 GitHub 上按 star
找主流密码库（不限语言），据此构建尽可能大的"被测库 × 被测算法"目标集。

## 1. 各论文 / 工程都测了哪些库

| 工作 | 方法 | 被测库 | 覆盖算法面 |
|---|---|---|---|
| **Cryptofuzz** (guidovranken, OSS-Fuzz) | 多库差分 + 库内一致性 + sanitizer | OpenSSL, BoringSSL, LibreSSL, wolfCrypt, **Crypto++**, cppcrypto, libgcrypt, **libsodium**, mbed TLS(计划), Botan, NSS, Bitcoin/Monero, Veracrypt, Whirlpool 参考实现 | 对称/AEAD/哈希/HMAC/KDF/大数/ECC，跨库差分 |
| **CLFuzz** (THU-WingTecher, TOSEM'23) | 语义感知生成 + 三阶段逻辑交叉检查 | OpenSSL, **SymCrypt**, 等主流实现，评测 54 个算法 | 对称密码、消息摘要、CMAC 等；找到 12 个新 bug (OpenSSL CMAC / SymCrypt MD) |
| **CIFT** (TCHES 2026) | 密码学定义驱动的 metamorphic 测试 | **liboqs** 多历史版本、SUPERCOP | KEM (IND-CCA)、DSS (EUF/SUF)，PQC 为主 |
| **Project Wycheproof** (Google/C2SP) | 已知攻击测试向量 | OpenSSL, BoringSSL, aws-lc, LibreSSL, NSS, pyca/cryptography, Botan, Go crypto, swift-crypto, **RustCrypto**, Graviola, Tink, PyCryptodome, OpenTitan, Zig, liboqs, bc-rust | AEAD/RSA/DSA/ECDSA/EdDSA/ECDH/X25519/X448/HKDF/HMAC/KMAC/PBKDF2/SM4/BLS12-381/**ML-KEM/ML-DSA** |
| **HACL\*** / **EverCrypt** | 形式化验证实现，可作黄金 oracle | 自身（F\* 生成 C），常与 OpenSSL 差分 | 验证过的对称/哈希/曲线子集 |
| **OSS-Fuzz** | 持续 fuzzing 基础设施 | cryptofuzz(复合)、ecc-diff-fuzzer、bignum-fuzzer、wolfSSL、libsodium、openssl、boringssl、botan… | 全谱，长期运行 |
| **dudect / ct-fuzz / SideFuzz / ctgrind** | 常量时间/侧信道 | 任意 C 实现（针对 secret-dependent 分支/访存） | 时序泄漏检测（与功能正交） |

**结论**：主流工作被测面高度集中在 ①TLS 系大库（OpenSSL/BoringSSL/LibreSSL/wolfSSL/mbedTLS/NSS/aws-lc/Botan）②独立算法库（libsodium/Crypto++/libgcrypt）③新兴 PQC/FHE（liboqs/SEAL）。差分测试(Cryptofuzz/Wycheproof)是找逻辑 bug 的主力；CLFuzz/CIFT 补上"语义/密码学定义 oracle"；常量时间是正交的第二维。CMFuzz 的定位正是把这三条合一并扩到 PQC/FHE。

## 2. GitHub 高 star 密码库（不限语言）

| 库 | 语言 | Star | 构建 | 备注 / 差分价值 |
|---|---|---:|---|---|
| **OpenSSL** | C/asm | ~30.4k | 系统已装 | 事实标准，差分基准；已接入 |
| **libsodium** | C | ~13.7k | autotools | NaCl 系，API 干净，易 fuzz；**本轮接入** |
| **Mbed-TLS** | C | ~6.7k | cmake | 嵌入式，PSA API；**本轮接入** |
| **Crypto++** | C++ | ~5.5k | make | 算法面极广（几十种密码/哈希/MAC）；**本轮接入** |
| **ring** | Rust/asm/C | ~4.1k | cargo | BoringSSL 子集，Rust 生态基石 |
| **Botan** | C++ | ~3.3k | configure.py | 算法广、含侧信道检测、PQC |
| **wolfSSL** | C | ~2.9k | autotools | 嵌入式，含 PQC TLS |
| **RustCrypto** (hashes/AEADs/…) | Rust | 各 0.8–2.2k | cargo | 纯 Rust，多 crate，跨语言差分 |
| **aws-lc** | C | ~0.8k | cmake | BoringSSL/OpenSSL 派生，AWS 维护 |
| **Go crypto** (`crypto/*`) | Go | 随 Go | go build | 标准库，跨语言差分极佳 |
| **PyCryptodome** | C/Python | — | pip | Python 生态 |
| **Tink** | C++/Java/Go | — | bazel | Google 高层封装 |
| **BouncyCastle** (bc-java) | Java | — | gradle | Java 事实标准 |
| **liboqs** | C | — | cmake | PQC（KEM/SIG）；已接入 |
| **Microsoft SEAL** | C++ | — | cmake | FHE（BFV/CKKS）；已接入 |

## 3. CMFuzz 目标矩阵（现状 + 本轮扩展）

图例：✅ 已接入并跑通；🟡 本轮接入中；⬜ 规划

| 域 | 库 | 语言 | 接入方式 | 状态 |
|---|---|---|---|---|
| PQC-KEM | liboqs | C | 每算法一个 libFuzzer 靶 (ML-KEM/Kyber/Frodo/BIKE/HQC/NTRU/McEliece…) | ✅ 41 KEM 规格 |
| PQC-SIG | liboqs | C | 每算法一个靶 (ML-DSA/Falcon/SLH-DSA/MAYO/CROSS/OV/SNOVA…) | ✅ 221 SIG 规格 |
| FHE | Microsoft SEAL | C++ | BFV 同态正确性/分配律 property 靶 | ✅ |
| 传统-单库 | OpenSSL | C | SHA-256 / AES-256-GCM / HMAC 靶 | ✅ |
| **传统-多库差分** | OpenSSL + libsodium + mbedTLS + Crypto++ | C/C++ | 同一原语跨库比对 (SHA-256/512, HMAC, AES-256-GCM, ChaCha20-Poly1305) | 🟡 本轮 |
| 跨语言差分 | Go crypto / RustCrypto / ring | Go/Rust | 子进程或 FFI 比对同一测试向量 | ⬜ 规划 |
| PQC 真实 bug 复现 | 旧版 liboqs | C | 版本回退跑现有靶，复现 CIFT/CVE | ⬜ 规划 |

## 4. 本轮扩展的选择理由
- 优先"易构建 + 算法面广 + 差分价值高"的 C/C++ 库：**libsodium、mbedTLS、Crypto++**。三者与
  已接入的 OpenSSL 在 SHA-2 / HMAC / AES-GCM / ChaCha20-Poly1305 上都有实现，可立即组成
  **多库差分 oracle**（Cryptofuzz 的核心能力），一次性把"被测库"从 1 扩到 4、并让每个共有
  算法获得跨实现交叉验证。
- 跨语言（Go/Rust）差分价值最高但工程量大（需 FFI/子进程桥接 + 统一测试向量编码），列为下一步。
- PQC 侧"扩算法"已在 liboqs 内做到（262 规格，覆盖全部启用算法），扩"库"的下一步是接
  **Botan/PQClean** 做 PQC 跨库差分。
