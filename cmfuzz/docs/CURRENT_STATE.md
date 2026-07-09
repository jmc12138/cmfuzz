# CMFuzz 当前状态（CURRENT_STATE）

> 维护说明：这是**活文档**，只记录"此刻真正做好、跑通"的实现与算法（小而稳的测试集）。
> 每次新增/验证一个实现或算法，就更新这里；未来目标不写这里（见 `docs/ROADMAP_MATRIX.md`）。
> 最近更新：2026-07-09。

## 0. 一句话现状
在一个**小而扎实**的测试集上，三支柱（规格+oracle / 功能+常量时间双检测 / PQC·FHE·多库差分）
端到端跑通：**10 个实现库 × 5 类原语 + PQC(262 规格) + FHE**，0 误报，且有故障注入自测证明 oracle 有效。
BoringSSL / aws-lc（符号冲突）+ wolfCrypt（原生 wc_* API）+ Botan（C++ Botan:: 命名空间），均走**独立子进程差分**（主控 OpenSSL 做参照）。

---

## 1. 已接入的实现（库 + 版本）

| 库 | 版本 | 语言 | 构建产物 | 用途 |
|---|---|---|---|---|
| OpenSSL | 3.0.2 | C | 系统 libcrypto | 传统算法（差分 + 单库靶） |
| libsodium | 1.0.20 | C | `libs/libsodium/build/lib/libsodium.a` | 传统算法差分 |
| Mbed-TLS | 3.6.2 | C | `libs/mbedtls/build/library/libmbedcrypto.a` | 传统算法差分 |
| Crypto++ | 8.9.0 | C++ | `libs/cryptopp/libcryptopp.a` | 传统算法差分 |
| liboqs | 0.16.0-rc1 | C | `libs/liboqs/build/lib/liboqs.a` | PQC KEM/签名 |
| Microsoft SEAL | 4.3.3 | C++ | `libs/SEAL/build/lib/libseal-4.3.a` | FHE(BFV) |
| BoringSSL | rolling (`e748fac`, 2026-07-09) | C/C++ | `libs/boringssl/build/libcrypto.a` | 子进程差分 + L3 EVP_AEAD 误用靶 |
| aws-lc | rolling (awslc 5.1.0, 2026-07-09) | C/C++ | `libs/aws-lc/build/crypto/libcrypto.a` | 子进程差分 + L3 EVP_AEAD 误用靶（需 Go≥1.20） |
| wolfSSL/wolfCrypt | rolling (2026-07-09) | C | `libs/wolfssl/src/.libs/libwolfssl.a` | 子进程差分 + L3 AES-GCM 误用靶（原生 wc_* API，需 autotools） |
| Botan | 3.8.1 | C++ | `libs/botan/botan_all.{h,cpp}`（amalgamation） | 子进程差分 + L3 AEAD_Mode 误用靶（需 python3 + C++20） |

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

### 2.6 L2 组合层 —— 传统通用组合（Encrypt-then-MAC / TLS1.3 记录层）【新】
靶：`build/harness/comp_trad`（~7.2M runs/90s，**0 违反**）。证明 L2 组合层对**传统算法**同样适用。

- **Encrypt-then-MAC (EtM)** = AES-256-CBC 加密 + HMAC-SHA256(iv‖ct)（可证明安全的通用组合）：
  - **O5-roundtrip**：先验 MAC 再解密，`open(seal(m))==m`；
  - **O5-ciphertext-integrity**：翻转 iv/ct/tag 任一位 → open 必须拒绝（解密前先拒）。
- **TLS1.3 记录层** = AES-256-GCM，nonce=static_iv⊕seq，记录头作 AAD：
  - **O5-roundtrip**：`open(seq, seal(seq,m))==m`；
  - **O5-seq-binding**：用错误 seq 打开 → 必须失败（顺序/nonce 绑定）；
  - **O5-tamper**：翻转 ct/tag → 必须失败。

### 2.7 L2 组合层 —— 认证 KEM（KEM+签名）与 KDF 链【新】
**认证 KEM**（“对封装物签名”式 AKE）：发送方 KEM 封装 + 对 `enc` 签名，接收方先验签再解封装。

| 靶 | 后端 | campaign | 结果 |
|---|---|---|---|
| `build/harness/comp_authkem_classic` | X25519 + Ed25519 | ~0.11M runs/45s | 0 违反 |
| `build/harness/comp_authkem_pqc` | ML-KEM-768 + ML-DSA-65 | ~0.10M runs/45s | 0 违反 |

- **O5-roundtrip**：验签成功 + 解封装后双方同密钥 + AEAD 记录往返一致；
- **O5-transcript-binding**：篡改 `enc`（保留签名）→ 验签必须失败。认证 KEM 的核心就是
  “签名必须绑定 KEM 密文”，否则攻击者可替换封装物（未绑定的 transcript）。

**KDF 链 / ratchet**（`build/harness/comp_kdfchain`，~1.3M runs/60s，0 违反）：
k₀=HKDF(ikm)、kᵢ₊₁=HKDF(kᵢ)，每消息用自己的 kᵢ 做 AES-GCM：
- **O5-roundtrip**：消息 i 在 kᵢ 下正确解开；
- **O5-key-separation**：用 kⱼ（j≠i）解消息 i 必须失败（链每步密钥独立；链不前进则败）。

### 2.8 L3 序列/误用层 —— 有状态 AEAD 契约（O6）【新】
靶：`build/harness/seq_aead`（~12M runs/60s，**0 违反**）。不同于 L1/L2 测“单次调用/固定组合”，
L3 测**操作序列**是否遵守库的使用契约（首个 O6 靶，传统 AES-256-GCM）：

- **O6-nonce-uniqueness**：正确协议每消息从 nonce 源取**新** nonce；nonce 源重复 (key,nonce)
  对则违反。重用时 GCM 退化为 two-time pad，`ct1⊕ct2==m1⊕m2`（密钥流泄露）——作为
  具体后果一并报告。这是经典的 GCM 灾难性 nonce 复用 CVE 类。
- **O6-release-before-verify**：AEAD 契约 = **在 DecryptFinal（验 tag）成功前绝不使用**
  `DecryptUpdate` 产出的明文。对篡改密文，Final 失败 → 明文必须丢弃；若仍交付则违反
  （未验证明文释放）。

### 2.9 L3 序列/误用层 —— 签名 nonce 与 KEM 密钥混淆（O6）【新】

| 靶 | 后端 | campaign | 结果 |
|---|---|---|---|
| `build/harness/seq_ecdsa` | ECDSA P-256（可控 nonce 源） | ~0.41M runs/60s | 0 违反 |
| `build/harness/seq_pqc_kem` | ML-KEM-768（liboqs） | ~0.63M runs/60s | 0 违反 |

- **O6-ecdsa-k-uniqueness**：ECDSA 安全依赖每签名唯一且保密的 nonce k。对两个不同消息
  签名，其 r 分量必须不同（r=x(k·G)）；r 相等 ⇔ k 被复用（经典 Sony PS3 / Android
  SecureRandom 事故）。复用时直接从 (r,s1,s2,z1,z2) **恢复长期私钥** 作为具体后果报告。
- **O6-kem-key-confusion**：会话中误用密钥（向 A 封装但用 B 的 sk 解封）时，安全 KEM
  （ML-KEM 隐式拒绝）必须**不产生匹配的共享密钥**（不能虚假协商）；同时正确密钥
  解封必须与发送方一致（O6-kem-roundtrip）。

### 2.10 L3 序列/误用层 —— EVP 状态机 + CBC IV 可预测性（O6）【新】
靶：`build/harness/seq_evp`（~16.8M runs/60s，**0 违反**）。补齐 PLAN 1.4 列出的
"EVP 状态机误用 / CBC 可预测 IV"两项，与 `seq_aead` 互补：

- **O6-iv-unpredictability**：CBC 机密性要求每消息用**新鲜、不可预测**的 IV。正确实现
  用随机 IV 时，同一明文两次加密应得到**不同**密文；固定/可预测 IV 使两次密文相同，
  泄露"明文相等"（TLS1.0 可预测 IV / BEAST 类）。
- **O6-ctx-use-after-free**：`EVP_CIPHER_CTX` 契约禁止在 `EVP_CIPHER_CTX_free()` 后再
  触碰上下文；故障注入在 free 后继续 `EncryptUpdate` → 有状态 API 误用
  （把 O4 内存安全并入 L3 序列层）。

### 2.11 阶段 2.1 —— 子进程差分扩库（BoringSSL / aws-lc / wolfCrypt / Botan）+ 专属 L3 误用靶【新】
PLAN 2.1 起把差分从 4 库扩到更多库。BoringSSL/aws-lc 重定义 OpenSSL 符号，**无法同进程链接**；
wolfCrypt 用自己的 wc_* API；Botan 是 C++、活在 Botan:: 命名空间。四者一律采用**独立子进程靶**
架构（`harness/subproc/`）：

- `diff_subproc`（主控，链接 OpenSSL 作参照）按行协议把 5 类原语的测试向量喂给每个后端
  子进程，逐字节比对（O1 差分）。协议见 `compute_common.h`（key‖nonce‖aadlen‖aad‖msg，
  两端共用一份解析器，一致性由构造保证）。
- `compute_boringssl`（独立 CLI，**只链接 BoringSSL**）：SHA-256/512、HMAC-SHA256、
  ChaCha20-Poly1305、AES-256-GCM。AEAD 用 BoringSSL 的一次性 **EVP_AEAD** API。
  实测 **5000 向量对 OpenSSL 全部一致**；`CMF_DIFF_FAULT` 变体翻转输出 → 主控正确报
  `DIFF_mismatch`（差分自测有效）。
- `compute_aws_lc`（独立 CLI，**只链接 aws-lc**）：aws-lc 是 AWS 的 BoringSSL fork，同一套
  EVP_AEAD API。实测 **OpenSSL + BoringSSL + aws-lc 三方 5000 向量全一致**；侦5向 fault
  同样被 `DIFF_mismatch` 捕获。（aws-lc cmake 需 **Go ≥ 1.20**，Ubuntu 22.04 apt 的 1.18
  不够，需手装 Go；缺失时自动跳过。）
- `compute_wolfssl`（独立 CLI，**只链接 wolfCrypt**）：wolfCrypt 用原生 wc_* API
  （`wc_Sha256Hash` / `wc_HmacSetKey` / `wc_ChaCha20Poly1305_Encrypt` / `wc_AesGcmEncrypt`），
  状态机与 EVP 完全不同。实测 **OpenSSL+BoringSSL+aws-lc+wolfCrypt 四方 5000 向量全一致**；
  俴5向 fault 同样被 `DIFF_mismatch` 捕获。（需 autotools 构建；缺失时自动跳过。）
- `seq_boringssl` / `seq_aws_lc`（各自专属 **L3 误用靶**，libFuzzer+ASan，~8.5M runs/15s，
  **0 违反**）：针对 EVP_AEAD 一次性 seal/open 状态机（aws-lc 与 BoringSSL 共享该状态机）——
  - **O6-nonce-uniqueness**：GCM(EVP_AEAD) 同 (key,nonce) 重用 → `ct1⊕ct2==m1⊕m2` 密钥流泄露；
  - **O6-release-before-verify**：`EVP_AEAD_CTX_open()` 对伪造密文返回 0，契约要求仅在返回 1
    时使用输出；对篡改密文仍交付明文即违反。
- `seq_wolfssl`（wolfCrypt 专属 **L3 误用靶**，~5M runs/15s，**0 违反**）：针对 wolfCrypt
  一次性 `wc_AesGcmSetKey`+`wc_AesGcmEncrypt`/`wc_AesGcmDecrypt` 状态机——同样两个 O6 oracle
  （nonce 唯一性；`wc_AesGcmDecrypt` 对篡改密文返回非 0，未成功即不得交付明文）。
- `compute_botan`（独立 CLI，**只链接 Botan**）：Botan 用 `HashFunction`/`MessageAuthenticationCode`/
  `AEAD_Mode` 对象建模（`set_key`→`set_associated_data`→`start(nonce)`→`finish(buf)`）。实测
  **OpenSSL+BoringSSL+aws-lc+wolfCrypt+Botan 五方 5000 向量全一致**；篡改 fault 被 `DIFF_mismatch` 捕获。
  （用 Botan 3.8.1 amalgamation 编译，需 python3 + C++20；缺失时自动跳过。）
- `seq_botan`（Botan 专属 **L3 误用靶**，~0.33M runs/15s，**0 违反**）：针对 Botan `AEAD_Mode`
  状态机——两个 O6 oracle（nonce 唯一性；解密 `finish()` 对篡改密文**抛异常**，未成功即不得交付明文）。

### 2.12 阶段 2.2 —— 差分算法扩展（SHA-3 家族）【新】
PLAN 2.2 在既有库上加算法。第一批：**SHA-3 家族**，接入子进程差分协议为 op 5–8：
- op5 **SHA3-256**、op6 **SHA3-512**（定长摘要）；op7 **SHAKE128**、op8 **SHAKE256**（XOF，
  分别定长挤出 32B / 64B，使差分良定义）。
- 各后端实现：OpenSSL 参照 = `EVP_sha3_*` / `EVP_DigestFinalXOF`；aws-lc 同 EVP API；
  wolfCrypt = `wc_Sha3_256Hash` / `wc_Sha3_512Hash` / `wc_Shake128/256_*`；
  Botan = `HashFunction("SHA-3(256)"/"SHAKE-128(256)")`（名字里编码输出比特数）。
- **能力协商**：本 BoringSSL 构建未经 EVP 暴露 SHA-3/SHAKE，其 CLI 对 op5–8 回 `NA`，
  主控**跳过该后端该 op**（非分歧）——这是让"算法支持随库不同"而不产生假阳的通用机制。
- 实测 **OpenSSL+aws-lc+wolfCrypt+Botan 四方 5000 向量（含 SHA-3/SHAKE）全一致**，且
  `SHA3-256("abc")` / `SHAKE128("abc",32)` 对齐 NIST 已知向量；faulted CLI 仍被 `DIFF_mismatch`
  捕获（差分自测覆盖 op0–8）。

**第二批：KDF（HKDF / PBKDF2）** —— op9 **HKDF-SHA256**（IKM=msg、salt=key、info=aad，
定长挤出 42B）、op10 **PBKDF2-HMAC-SHA256**（password=msg、salt=key、4096 迭代、32B）：
- 五后端均支持（BoringSSL 对 KDF 不再 `NA`，回归差分）：OpenSSL 参照用 `EVP_KDF("HKDF")` +
  `PKCS5_PBKDF2_HMAC`；BoringSSL/aws-lc 用一次性 `HKDF()` + `PKCS5_PBKDF2_HMAC`；wolfCrypt
  用 `wc_HKDF` + `wc_PBKDF2`；Botan 用 `KDF("HKDF(SHA-256)")` + `PasswordHashFamily("PBKDF2(SHA-256)")`。
- 实测 **五方（OpenSSL+BoringSSL+aws-lc+wolfCrypt+Botan）3000 向量（含 op9/op10）全一致**；
  Botan amalgamation 再加 `hkdf,pbkdf2` 模块。参数固定（迭代数/输出长）以让差分良定义。

**第三批：公钥（Ed25519 / X25519）** —— op11 **Ed25519 签名**（seed=key、message=msg → 64B 签名，
RFC 8032 纯 Ed25519 确定性，故字节级可比）、op12 **X25519**（scalar=key、peer 公钥=msg[0:32]
→ 32B 共享密钥，RFC 7748 确定性）：
- 五后端均实现：OpenSSL 参照用 `EVP_PKEY_new_raw_private_key(ED25519/X25519)` + `EVP_DigestSign`
  / `EVP_PKEY_derive`；BoringSSL/aws-lc 用 `ED25519_keypair_from_seed`+`ED25519_sign` 与一次性
  `X25519()`；wolfCrypt 用 `wc_ed25519_*` 与 `wc_curve25519_*`；Botan 用 `Ed25519_PrivateKey::from_seed`
  +`PK_Signer` 与 `X25519_PrivateKey::agree`。
- **两处库间行为差异（已处理，非算法分歧）**：
  ① wolfCrypt `wc_ed25519_make_public` 只把公钥写进输出缓冲、不写回 key 对象，需再 `import_public`
     回去，否则签名对全零公钥做哈希得到错误的 S（R 相同、S 不同）；
  ② 本 wolfSSL 构建启用了 **curve25519 blinding**，`shared_secret` 需先 `wc_curve25519_set_rng`
     绑定 RNG（否则返回 `BAD_FUNC_ARG`）——盲化只随机化中间量、共享密钥不变。
  另：X25519 peer 公钥在向量生成时清零 bit 255（RFC 7748 规范形式）——OpenSSL/BoringSSL/Botan
  内部会 mask 该位，而 wolfCrypt 对非规范 peer 直接拒绝；统一到规范形式使差分良定义。
- 实测 **五方 6000 向量（含 op11/op12）全一致**（seed 42/777 均通过），wolfCrypt X25519 对齐
  **RFC 7748 已知向量**；Botan amalgamation 再加 `x25519,ed25519` 模块。

**第四批：ECDSA-P256 验签互操作（op13）** —— RSA/ECDSA 的密钥是结构化对象、且 ECDSA 的 `k`
随机化使签名字节不可比，故不套用"字节级输出差分"，改用**验签互操作 oracle**：参照端
（OpenSSL）生成 P-256 密钥对并用 ECDSA-SHA256 签名（约半数向量故意篡改 message），把
`(pubkey ‖ signature ‖ message)` 打包进向量的 msg 区（新增 `cmf_verify_parse`），每个后端只
回 **1 字节判定**（`01`=接受/`00`=拒绝），五方必须对判定一致——完全复用既有"字节级一致"机制。
随机化不破坏差分（只比判定，不比签名字节），同时顺带检验**跨库密钥/签名编码解析**（SEC1
未压缩点、ASN.1 DER）。
- 五后端：OpenSSL 参照 `EVP_DigestSign/Verify`（DER 签名，公钥经 `EVP_PKEY_get1_encoded_public_key`
  导出为 65B 未压缩点）；BoringSSL/aws-lc 用 `EC_POINT_oct2point`+`ECDSA_verify`；wolfCrypt 用
  `wc_ecc_import_x963`+`wc_ecc_verify_hash`（对 SHA-256 摘要）；Botan 用 `EC_AffinePoint`
  +`ECDSA_PublicKey`+`PK_Verifier`（`Signature_Format::DerSequence`）。
- **两处 Botan 构建差异（已处理）**：① 命名曲线须用 `EC_Group::from_name("secp256r1")`（字符串
  构造函数按 PEM/OID 解析、会抛"Unknown ECC group"）；② minimized amalgamation 需显式加
  `ecdsa,pcurves_secp256r1` 模块，否则 P-256（OID 1.2.840.10045.3.1.7）"not supported"。
- 实测 **五方 11000 向量（含 op13 接受/拒绝两类）全一致**（seed 42×6000 + 777×5000）。

**第五批：RSA-PSS 验签互操作（op14）** —— 同 op13 的验签互操作模式：参照端（OpenSSL）用一把
**RSA-2048** 密钥（整轮复用，keygen 昂贵）做 **RSA-PSS(SHA-256, MGF1-SHA-256, salt=32)** 签名
（约半数向量篡改 message），后端只回 1 字节接受/拒绝判定，五方必须一致。
- **公钥编码取巧**：不传结构化 DER，`pubkey` 字段只放**裸模数 n**（大端），公钥指数固定 65537，
  避开各库 SPKI/PKCS#1 DER 解析差异，直接由 (n, 65537) 重建公钥。
- 五后端：OpenSSL 参照 `EVP_DigestSign/Verify` + `EVP_PKEY_CTX_set_rsa_pss_saltlen(32)`；
  BoringSSL/aws-lc 用 `RSA_set0_key(n,e)`+`RSA_verify_pss_mgf1`（对 SHA-256 摘要，saltlen=32）；
  wolfCrypt 用 `wc_RsaPublicKeyDecodeRaw`+`wc_RsaPSS_VerifyCheck`；Botan 用 `RSA_PublicKey(n,e)`
  +`PK_Verifier("PSS(SHA-256)")`（salt 长度自动识别）。Botan amalgamation 再加 `rsa,emsa_pssr,mgf1`
  模块。
- 实测 **五方 11000 向量（含 op14 接受/拒绝两类）全一致**（seed 42×6000 + 777×5000）。

### 2.13 阶段 2.3 —— PQC 跨库差分（liboqs vs PQClean）【新】
此前 PQC 只有 O2（性质/变形 oracle），缺 O1（跨实现差分）。本阶段接 **PQClean** 参照实现，
对两个 NIST 标准方案 **ML-KEM-768（FIPS 203）**、**ML-DSA-65（FIPS 204）** 与 liboqs 做 O1 差分。
- **构建**：`scripts/build_pqclean.sh` 编出 `libpqclean.a`（ml-kem-768/clean + ml-dsa-65/clean +
  common/fips202 + randombytes）。PQClean 每方案符号带前缀（`PQCLEAN_MLKEM768_CLEAN_*` 等），liboqs
  用 `OQS_*`/`OQS_SHA3_*` 前缀，二者**无符号冲突**，同一二进制内可并链。
- **oracle 设计**（随机化 KEM encaps / ML-DSA 签名使字节级不可比，同 op13/op14 思路改比"互操作结果"）：
  - **KEM 互操作（双向）**：A 库 keygen → B 库 encaps（对 A 的公钥）→ A 库 decaps，两个共享密钥必须相等；
    正反两向都测，检验跨库公钥/密文线编码兼容性。
  - **SIG 验签互操作（双向）**：A 库签名后，A/B 两库对同一 (pk, sig, message) 及其篡改副本的
    接受/拒绝判定必须一致。
- 实测 **liboqs↔PQClean 双向 5000 迭代（ML-KEM-768 KEM + ML-DSA-65 sign/verify）全一致**
  （seed 42×2000 + 777×5000），故障注入自测正确触发 `O1_kem_interop`。

### 2.14 阶段 2.4 —— 跨语言差分（Go crypto vs OpenSSL）【新】
把差分从"跨 C 库"扩展到"跨语言"：新增 Go 后端 `harness/gobridge`，与 stage 2.1 的子进程
runner（`diff_subproc`）说**同一套线协议**（stdin 每行 `<op> <hex>`，stdout 每行 hex/`01`/`00`/
`NA`/`ERR`），但用 **Go 标准库 + golang.org/x/crypto** 而非 C 库实现全部 15 个 op。Go 的密码栈是
独立实现血统（非 OpenSSL/BoringSSL 派生），故与 OpenSSL 参照逐字节一致是**真正的跨语言 O1 差分**。
- **覆盖**：op0–14 全部——SHA-256/512、HMAC、ChaCha20-Poly1305、AES-256-GCM、SHA3-256/512、
  SHAKE128/256、HKDF、PBKDF2、Ed25519 签名、X25519、ECDSA-P256 验签互操作、RSA-PSS 验签互操作。
  ChaCha/SHA3/SHAKE/HKDF/PBKDF2/X25519 走 `x/crypto`（v0.17.0，pin 在 `harness/gobridge/go.mod`），
  其余走 Go stdlib。ECDSA 用 `ecdsa.VerifyASN1`（直接吃 DER），RSA-PSS 用 `rsa.VerifyPSS`
  （saltlen=32、SHA-256），与 op13/op14 的裸模数/SEC1 点编码约定一致。
- **构建**：`scripts/build_go_diff.sh` 编 runner + Go 后端；`faultMode=1`（ldflags 注入）出故障自测变体。
- 实测 **Go↔OpenSSL 11000 向量全一致**（seed 42×6000 + 777×5000，覆盖全部 15 op），故障注入
  正确触发 `DIFF_mismatch`。

---

## 3. 已跑通的检测能力（oracle）

| 类型 | 内容 | 状态 |
|---|---|---|
| 功能 metamorphic | KEM 正确性、SIG EUF/SUF、AEAD 往返/篡改拒绝、错误密钥 | ✅ |
| **L2 组合(O5)** | HPKE（X25519+ML-KEM-768）；EtM 密文完整性；TLS1.3 记录层 seq 绑定；认证 KEM transcript 绑定（古典+PQC）；KDF 链 key-separation | ✅ |
| **L3 序列/误用(O6)** | AES-256-GCM：灾难性 nonce 复用、AEAD 未验证明文释放；ECDSA-P256 签名 nonce(k) 复用→私钥恢复；ML-KEM-768 密钥混淆免虚假协商；AES-256-CBC：可预测/复用 IV；EVP 上下文 use-after-free；**BoringSSL + aws-lc EVP_AEAD + wolfCrypt/Botan AES-GCM：nonce 复用、release-before-verify** | ✅ |
| 差分 | 同算法跨 4 库输出一致性（同进程）；**BoringSSL + aws-lc + wolfCrypt + Botan 独立子进程差分**（`diff_subproc`，op0–14＝哈希/HMAC/AEAD + SHA-3/SHAKE + HKDF/PBKDF2 + Ed25519/X25519 + ECDSA-P256/RSA-PSS 验签互操作，vs OpenSSL 五方一致）；**PQC 跨库 O1 差分 liboqs↔PQClean**（ML-KEM-768 KEM 互操作 + ML-DSA-65 验签互操作，双向）；**跨语言 O1 差分 Go crypto↔OpenSSL**（`diff_subproc` go 后端，op0–14 全覆盖） | ✅ |
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
`tests/negative_tests.sh` ✅ **29/29**（含差分库 + BoringSSL + aws-lc + wolfCrypt + Botan + PQClean + Go；
无 Go 时 28；只到 Botan 27；只到 wolfCrypt 24；只到 aws-lc 21；只到 BoringSSL 18；仅差分库 15；最小 14）：
BoringSSL / aws-lc / wolfCrypt / Botan 各贡献 **L3 nonce 复用 + release-before-verify + 子进程 DIFF_mismatch**
三项，PQClean 贡献 **PQC 跨库差分 O1_kem_interop**，Go 贡献 **跨语言差分 DIFF_mismatch**
（各自仅在对应库/工具链可用时运行，否则 SKIP）。故障注入使以下 oracle 全部正确触发——
KEM 正确性(MR1)、SIG 强不可伪造(MR3)、传统 AEAD 篡改拒绝(tamper_reject)、
**L2 HPKE 上游篡改(O5-upstream-tamper)**、**L2 EtM 密文完整性(O5-ciphertext-integrity)**、
**L2 TLS1.3 seq 绑定(O5-seq-binding)**、**L2 认证 KEM transcript 绑定(O5-transcript-binding)**、
**L2 KDF 链 key-separation(O5-key-separation)**、
**L3 灾难性 nonce 复用(O6-nonce-uniqueness)**、**L3 未验证明文释放(O6-release-before-verify)**、
**L3 ECDSA nonce(k) 复用(O6-ecdsa-k-uniqueness)**、**L3 KEM 密钥混淆(O6-kem-key-confusion)**、
**L3 可预测 IV(O6-iv-unpredictability)**、**L3 EVP 上下文 use-after-free(O6-ctx-use-after-free)**、
多库差分(DIFF_mismatch)。

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
- 2026-07-09（夜·11）：**PLAN 阶段2.4（跨语言差分 Go crypto vs OpenSSL）** —— 把差分从跨 C 库
  扩到跨语言。新增 Go 后端 `harness/gobridge`（Go stdlib + x/crypto v0.17.0，pin 在 go.mod），复用
  stage 2.1 的 `diff_subproc` 线协议，实现全部 15 个 op（op0–14）。Go 密码栈独立血统，与 OpenSSL
  参照逐字节一致＝真正的跨语言 O1 差分。`scripts/build_go_diff.sh` 编 runner + Go 后端
  （`faultMode=1` 出故障自测变体）。**Go↔OpenSSL 11000 向量全一致**（seed 42×6000 + 777×5000）；
  负向自测升 **29/29**（新增跨语言 DIFF_mismatch 故障注入）。build_all 已接入。本阶段 0 新发现。
- 2026-07-09（夜·10）：**PLAN 阶段2.3（PQC 跨库差分 liboqs vs PQClean）** —— 补上 PQC 缺的 O1
  跨实现差分（此前仅 O2）。接 PQClean 参照实现，对 ML-KEM-768（FIPS 203）、ML-DSA-65（FIPS 204）
  与 liboqs 做差分。因 KEM encaps / ML-DSA 签名随机化、字节不可比，用互操作 oracle：KEM 双向
  keygen/encaps/decaps 跨库、共享密钥必须相等；SIG 双向签名后两库对同一 (pk,sig,msg) 及篡改副本
  的接受/拒绝判定必须一致。PQClean 符号带方案前缀、与 liboqs `OQS_*` 无冲突，同一二进制并链
  （`scripts/build_pqclean.sh` → `libpqclean.a`；`scripts/build_pqc_diff.sh` → `build/harness/pqc_diff`）。
  **双向 5000 迭代全一致**（seed 42×2000 + 777×5000）；负向自测升 **28/28**（新增 PQC O1_kem_interop
  故障注入）。build_all + Dockerfile 已接入。本阶段 0 新发现。
- 2026-07-09（夜·9）：**PLAN 阶段2.2（差分算法扩展·第五批 RSA-PSS 验签互操作）** —— 子进程
  差分协议加 op14，验签互操作模式：参照端 OpenSSL 用一把复用的 RSA-2048 密钥做
  RSA-PSS(SHA-256, MGF1-SHA-256, salt=32) 签名（约半数篡改），后端只回 1 字节判定。公钥编码
  取巧——`pubkey` 字段只放裸模数 n、指数固定 65537，避开各库 DER 解析差异。五后端：BoringSSL/
  aws-lc `RSA_set0_key`+`RSA_verify_pss_mgf1`；wolfCrypt `wc_RsaPublicKeyDecodeRaw`+
  `wc_RsaPSS_VerifyCheck`；Botan `RSA_PublicKey(n,e)`+`PK_Verifier("PSS(SHA-256)")`（salt 自动识别），
  amalgamation 加 `rsa,emsa_pssr,mgf1` 模块。**五方 11000 向量（含 op14 双判定）全一致**
  （seed 42×6000 + 777×5000）。负向自测仍 **27/27**（DIFF_mismatch 覆盖 op0–14）。本阶段 0 新发现。
- 2026-07-09（夜·8）：**PLAN 阶段2.2（差分算法扩展·第四批 ECDSA-P256 验签互操作）** —— 因
  RSA/ECDSA 密钥结构化且 ECDSA `k` 随机化、签名字节不可比，改用**验签互操作 oracle**：子进程
  差分协议加 op13，参照端 OpenSSL 生成 P-256 密钥对 + ECDSA-SHA256 签名（约半数篡改 message），
  把 `(pubkey‖sig‖message)` 打包进 msg 区（新增 `cmf_verify_parse`），后端只回 1 字节判定
  （`01`/`00`），五方对接受/拒绝判定一致——复用既有字节级一致机制。五后端：BoringSSL/aws-lc
  `EC_POINT_oct2point`+`ECDSA_verify`；wolfCrypt `wc_ecc_import_x963`+`wc_ecc_verify_hash`；Botan
  `EC_AffinePoint`+`PK_Verifier(DerSequence)`。Botan 需 `EC_Group::from_name` 且 amalgamation 加
  `ecdsa,pcurves_secp256r1` 模块；wolfSSL 加 `--enable-ecc`。**五方 11000 向量（含 op13 双判定）
  全一致**（seed 42×6000 + 777×5000）。负向自测仍 **27/27**（DIFF_mismatch 覆盖 op0–13）。本阶段 0 新发现。
- 2026-07-09（夜·7）：**PLAN 阶段2.2（差分算法扩展·第三批 公钥 Ed25519/X25519）** —— 子进程
  差分协议加 op11 **Ed25519 签名**（seed=key/msg=msg，64B，RFC 8032 确定性）、op12 **X25519**
  （scalar=key/peer=msg[0:32]，32B，RFC 7748 确定性）。五后端均实现：OpenSSL 参照
  `EVP_PKEY_ED25519/X25519`；BoringSSL/aws-lc `ED25519_*`/`X25519()`；wolfCrypt `wc_ed25519_*`
  /`wc_curve25519_*`；Botan `Ed25519_PrivateKey`/`X25519_PrivateKey`。处理三处库差异：wolfCrypt
  Ed25519 需 `make_public`→`import_public` 回写公钥；wolfCrypt X25519 blinding 需 `set_rng`；
  X25519 peer 统一清零 bit 255（RFC 7748 规范形式）。**五方 6000 向量（含 op11/op12）全一致**
  （seed 42/777），wolfCrypt X25519 对齐 RFC 7748 已知向量；Botan amalgamation 加 `x25519,ed25519`
  模块。负向自测仍 **27/27**（DIFF_mismatch 覆盖 op0–12）。本阶段 0 新发现。
- 2026-07-09（夜·6）：**PLAN 阶段2.2（差分算法扩展·第二批 KDF）** —— 子进程差分协议加
  op9 **HKDF-SHA256**（IKM=msg/salt=key/info=aad，42B）、op10 **PBKDF2-HMAC-SHA256**
  （password=msg/salt=key/4096 迭代/32B）。五后端均实现（BoringSSL 对 KDF 回归差分、不再
  `NA`）：OpenSSL 参照 `EVP_KDF("HKDF")`+`PKCS5_PBKDF2_HMAC`；BoringSSL/aws-lc 一次性
  `HKDF()`+`PKCS5_PBKDF2_HMAC`；wolfCrypt `wc_HKDF`+`wc_PBKDF2`；Botan `KDF("HKDF(SHA-256)")`+
  `PasswordHashFamily("PBKDF2(SHA-256)")`。**五方 3000 向量（含 op9/op10）全一致**；Botan
  amalgamation 加 `hkdf,pbkdf2` 模块。负向自测仍 **27/27**（DIFF_mismatch 覆盖 op0–10）。本阶段 0 新发现。
- 2026-07-09（夜·5）：**PLAN 阶段2.2（差分算法扩展·第一批 SHA-3 家族）** —— 子进程差分
  协议加 op5–8：**SHA3-256 / SHA3-512 / SHAKE128(32B) / SHAKE256(64B)**。四后端实现
  （OpenSSL 参照 `EVP_sha3_*`/`EVP_DigestFinalXOF`、aws-lc 同 EVP、wolfCrypt `wc_Sha3_*Hash`/
  `wc_Shake*`、Botan `HashFunction("SHA-3(256)"/"SHAKE-128(256)")`）。新增 **`NA` 能力协商**：
  本 BoringSSL 构建未暴露 SHA-3 → 其 CLI 回 `NA`，主控跳过该 op（不算分歧）。**四方
  （OpenSSL+aws-lc+wolfCrypt+Botan）5000 向量全一致**，且 `SHA3-256("abc")`/`SHAKE128("abc",32)`
  对齐 NIST 已知向量；Botan amalgamation 加 `sha3,shake` 模块重建。负向自测仍 **27/27**
  （DIFF_mismatch 自测已覆盖 op0–8）。本阶段 0 新发现。
- 2026-07-09（夜·4）：**PLAN 阶段2.1（差分扩库·第四个库 Botan）** —— Botan（C++）用
  `AEAD_Mode`/`HashFunction`/`MAC` 对象状态机接入子进程差分：新增 `compute_botan` CLI +
  `seq_botan` L3 AEAD 误用靶 + `scripts/build_botan.sh`（Botan 3.8.1 amalgamation，只启用
  sha2_32/sha2_64/hmac/gcm/aes/chacha20poly1305 模块）。**五方（OpenSSL+BoringSSL+aws-lc+
  wolfCrypt+Botan）5000 向量全一致**；seq_botan campaign 0.33M runs 0 违反。负向自测升到
  **27/27**。Botan 解密 `finish()` 靠抛异常（而非返回码）拒绝伪造，release-before-verify oracle
  据此判定。`build_subproc.sh` 可选构建、缺失即跳过。本阶段 0 新发现。
- 2026-07-09（夜·3）：**PLAN 阶段2.1（差分扩库·第三个库 wolfCrypt）** —— wolfCrypt 用
  原生 wc_* API（与 EVP 完全不同的状态机）接入子进程差分：新增 `compute_wolfssl` CLI +
  `seq_wolfssl` L3 AES-GCM 误用靶 + `scripts/build_wolfssl.sh`。**四方（OpenSSL+BoringSSL+
  aws-lc+wolfCrypt）5000 向量全一致**；seq_wolfssl campaign 5M runs 0 违反。负向自测升到
  **24/24**。wolfCrypt 用 autotools 构建（需 autoconf/automake/libtool），`build_subproc.sh`
  可选构建、缺失即跳过。本阶段 0 新发现。
- 2026-07-09（夜·2）：**PLAN 阶段2.1（差分扩库·第二个库 aws-lc）** —— aws-lc（AWS 的
  BoringSSL fork，同一套 EVP_AEAD API）接入子进程差分：新增 `compute_aws_lc` CLI +
  `seq_aws_lc` L3 误用靶 + `scripts/build_aws_lc.sh`。**OpenSSL+BoringSSL+aws-lc 三方 5000
  向量全一致**；seq_aws_lc campaign 8.4M runs 0 违反。负向自测升到 **21/21**（新增 aws-lc
  L3 两项 + 子进程 DIFF_mismatch）。aws-lc cmake 需 Go≥15，`build_aws_lc.sh` 优先用
  `/usr/local/go`；Dockerfile 改装 Go 1.22。本阶段 0 新发现。
- 2026-07-09（夜·1）：**PLAN 阶段2.1（差分扩库·第一个库 BoringSSL）** —— 新增
  **子进程差分框架** `harness/subproc/`（`diff_subproc` 主控 + `compute_boringssl` CLI）：
  BoringSSL 因符号冲突走独立子进程，5 类原语对 OpenSSL **5000 向量全一致**；并新增
  **BoringSSL 专属 L3 误用靶** `seq_boringssl`（EVP_AEAD：O6-nonce-uniqueness +
  O6-release-before-verify，8.5M runs 0 违反）。负向自测升到 **18/18**（新增两条 BoringSSL
  L3 + 子进程 DIFF_mismatch）。新增 `scripts/build_boringssl.sh`、`scripts/build_subproc.sh`
  （已接入 `build_all.sh`，缺 Go 时自动跳过）。本阶段 0 新发现。
- 2026-07-09（晚·3）：**PLAN 阶段1.4 补齐** —— 新增 **L3 EVP 状态机 harness**
  (`seq_evp_harness.c`，O6)：AES-256-CBC 可预测/复用 IV（O6-iv-unpredictability）、
  EVP 上下文 use-after-free（O6-ctx-use-after-free），补齐 PLAN 1.4 本来列出但 seq_aead
  未覆盖的两项。campaign 16.8M runs 0 违反；负向自测升到 **15/15**（含差分；无差分库 14/14）。
  环境已在新 VM 重建，附 `Dockerfile`+`docs/REBUILD.md` 一键复现。本阶段 0 新发现。
- 2026-07-09（晚·2）：**PLAN 阶段1.5** —— 新增 **L3 签名 nonce 与 KEM 密钥混淆
  harness**（O6）：`seq_ecdsa_harness.c`（ECDSA-P256 可控 nonce，k 复用→私钥恢复）、
  `seq_pqc_harness.c`（ML-KEM-768 密钥混淆免虚假协商）。各 campaign 0 违反；
  负向自测升到 **13/13**（新增 O6-ecdsa-k-uniqueness、O6-kem-key-confusion）。
  至此 **PLAN 阶段1（1.1–1.5）全部完成**，L2/O5 与 L3/O6 创新主线落地。本阶段 0 新发现。
- 2026-07-09（晚·1）：**PLAN 阶段1.4** —— 新增 **L3 序列/误用 harness**
  (`seq_aead_harness.c`，O6)：AES-256-GCM 灾难性 nonce 复用、AEAD 未验证明文释放。
  campaign 12M runs 0 违反；负向自测升到 **11/11**（新增 O6-nonce-uniqueness、
  O6-release-before-verify）。本阶段 0 新发现。
- 2026-07-09（傍晚·3）：**PLAN 阶段1.3** —— 新增 **L2 认证 KEM**
  (`comp_authkem_harness.c`，X25519+Ed25519 与 ML-KEM-768+ML-DSA-65 两后端，transcript 绑定)
  与 **KDF 链/ratchet**(`comp_kdfchain_harness.c`，key-separation)。各 campaign 0 违反；
  负向自测升到 **9/9**（新增 transcript-binding、key-separation）。本阶段 0 新发现。
- 2026-07-09（傍晚·2）：**PLAN 阶段1.2** —— 新增 **L2 传统组合 harness**
  (`harness/comp_trad_harness.c`)：Encrypt-then-MAC(AES-CBC+HMAC) 密文完整性、
  TLS1.3 记录层(AES-GCM, seq nonce) 往返/seq 绑定/篡改。campaign 7.2M runs 0 违反；
  负向自测升到 **7/7**（新增 EtM 完整性、记录层 seq 绑定两个故障注入）。本阶段 0 新发现。
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
