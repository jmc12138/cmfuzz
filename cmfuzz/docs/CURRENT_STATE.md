# CMFuzz 当前状态（CURRENT_STATE）

> 维护说明：这是**活文档**，只记录"此刻真正做好、跑通"的实现与算法（小而稳的测试集）。
> 每次新增/验证一个实现或算法，就更新这里；未来目标不写这里（见 `docs/ROADMAP_MATRIX.md`）。
> 最近更新：2026-07-09。

## 0. 一句话现状
在一个**小而扎实**的测试集上，三支柱（规格+oracle / 功能+常量时间双检测 / PQC·FHE·多库差分）
端到端跑通：**7 个实现库 × 5 类原语 + PQC(262 规格) + FHE**，0 误报，且有故障注入自测证明 oracle 有效。
BoringSSL 因与 OpenSSL 符号冲突，走**独立子进程差分**（主控 OpenSSL 做参照）。

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

### 2.11 阶段 2.1 —— 子进程差分扩库（BoringSSL）+ 专属 L3 误用靶【新】
PLAN 2.1 起把差分从 4 库扩到更多库。BoringSSL/aws-lc 重定义 OpenSSL 符号，**无法同进程链接**，
故采用**独立子进程靶**架构（`harness/subproc/`）：

- `diff_subproc`（主控，链接 OpenSSL 作参照）按行协议把 5 类原语的测试向量喂给每个后端
  子进程，逐字节比对（O1 差分）。协议见 `compute_common.h`（key‖nonce‖aadlen‖aad‖msg，
  两端共用一份解析器，一致性由构造保证）。
- `compute_boringssl`（独立 CLI，**只链接 BoringSSL**）：SHA-256/512、HMAC-SHA256、
  ChaCha20-Poly1305、AES-256-GCM。AEAD 用 BoringSSL 的一次性 **EVP_AEAD** API。
  实测 **5000 向量对 OpenSSL 全部一致**；`CMF_DIFF_FAULT` 变体翻转输出 → 主控正确报
  `DIFF_mismatch`（差分自测有效）。
- `seq_boringssl`（BoringSSL 专属 **L3 误用靶**，libFuzzer+ASan，~8.5M runs/15s，**0 违反**）：
  针对 BoringSSL 独有的 EVP_AEAD 一次性 seal/open 状态机——
  - **O6-nonce-uniqueness**：GCM(EVP_AEAD) 同 (key,nonce) 重用 → `ct1⊕ct2==m1⊕m2` 密钥流泄露；
  - **O6-release-before-verify**：`EVP_AEAD_CTX_open()` 对伪造密文返回 0，契约要求仅在返回 1
    时使用输出；对篡改密文仍交付明文即违反。

---

## 3. 已跑通的检测能力（oracle）

| 类型 | 内容 | 状态 |
|---|---|---|
| 功能 metamorphic | KEM 正确性、SIG EUF/SUF、AEAD 往返/篡改拒绝、错误密钥 | ✅ |
| **L2 组合(O5)** | HPKE（X25519+ML-KEM-768）；EtM 密文完整性；TLS1.3 记录层 seq 绑定；认证 KEM transcript 绑定（古典+PQC）；KDF 链 key-separation | ✅ |
| **L3 序列/误用(O6)** | AES-256-GCM：灾难性 nonce 复用、AEAD 未验证明文释放；ECDSA-P256 签名 nonce(k) 复用→私钥恢复；ML-KEM-768 密钥混淆免虚假协商；AES-256-CBC：可预测/复用 IV；EVP 上下文 use-after-free；**BoringSSL EVP_AEAD：nonce 复用、release-before-verify** | ✅ |
| 差分 | 同算法跨 4 库输出一致性（同进程）；**BoringSSL 独立子进程差分**（`diff_subproc`，5 算法 vs OpenSSL 一致） | ✅ |
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
`tests/negative_tests.sh` ✅ **18/18**（含差分库 + BoringSSL；仅差分库 15；最小 14）：
新增 **L3 BoringSSL EVP_AEAD nonce 复用 / release-before-verify**、**子进程差分 DIFF_mismatch**
三项（仅在 BoringSSL 已编时运行，否则 SKIP）。故障注入使以下 oracle 全部正确触发——
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
