# CMFuzz 执行计划：从当前小测试集 → ROADMAP_MATRIX 全覆盖

> 这份是"每一步做什么"的施工计划。原则不变：**先在小集合上做扎实，每一步都可跑通、可自测、
> 更新 CURRENT_STATE，再进下一步**。计划把三份文档串起来：
> - `METHODOLOGY.md` = 方法（3 层目标 L1/L2/L3 × 6 类 oracle O1–O6）
> - `ROADMAP_MATRIX.md` = 目标全集（33 库 × 算法）
> - 本文 = 把方法逐库逐算法铺开的**顺序与验收标准**

每一步统一的**验收标准（DoD）**：
1. harness/引擎能编译、能跑（campaign 无崩溃或崩溃即真 bug）；
2. 有对应**负向自测**（故障注入让该 oracle 必 fire）——不许只会打印"0 违反"；
3. 更新 `docs/CURRENT_STATE.md`（新增了什么实现/算法/oracle）；
4. 通过隧道同步到本地。

图例：✅ 完成 · 🟡 进行中 · ⬜ 计划

---

## 阶段 0（已完成）：L1 底座 + 传统四 oracle
- ✅ 6 库：OpenSSL / libsodium / mbedTLS / Crypto++ / liboqs / SEAL
- ✅ O1 差分（4 库：SHA-256/512、HMAC、ChaCha20-Poly1305、AES-256-GCM）
- ✅ O2 metamorphic（PQC KEM/SIG + 传统 AEAD/hash/HMAC）
- ✅ O3 常量时间（PQC decaps/sign + 传统 AES/memcmp）
- ✅ O4 内存安全（全靶 ASan/UBSan）
- ✅ 负向自测 4/4

---

## 阶段 1：补齐 L2（组合，O5）与 L3（序列，O6）—— 本工作的创新主线

> 先把新维度在**已有的可信库（OpenSSL/liboqs）**上打通，证明方法有效，再谈扩库。
> 这样创新点（L2/L3）不依赖"接更多库"，风险最低。

### 步骤 1.1 ⬜ L2 第一个案例：HPKE 组合 harness（KEM + KDF + AEAD）
- 实现：`harness/comp_hpke_harness.c`。用 OpenSSL/liboqs 组合：
  `Encaps→HKDF-SHA256→AES-256-GCM`（经典 KEM 用 X25519，PQC 用 ML-KEM-768，做两版）。
- oracle：
  - **O5-往返**：接收端明文 == 发送端明文；
  - **O5-上游缺陷放大**：按 O2 已知的可锻造方式改 enc/pk → 组合层必须"解密失败/双方 key 不一致被检出"；
  - **O5-上下文绑定**：改 info/aad → 解密必须失败；
  - 复用 O4（ASan/UBSan）。
- 负向自测：注入"改 enc 后仍解出旧 key"→ O5 必 fire。
- DoD 全部满足后更新 CURRENT_STATE。

### 步骤 1.2 ⬜ L2 传统组合案例：Encrypt-then-MAC / TLS1.3 记录层密钥调度
- `harness/comp_trad_aead_harness.c`：**传统算法同样有组合问题**——
  - Encrypt-then-MAC vs MAC-then-Encrypt 的组合正确性与篡改拒绝；
  - TLS1.3 记录层：`HKDF -> traffic key -> AEAD`，改 nonce 序号/上下文必须失败；
  - 混合 KEM（X25519 + ML-KEM 组合成 hybrid，验证任一份额被篡改都应失败）。
- 负向自测：注入"MAC 未覆盖密文"→ O5 必 fire。

### 步骤 1.3 ⬜ L2 第三个案例：KEM+签名 认证组合 & KDF 链
- `comp_kem_sig_harness.c`：签名覆盖 KEM 公钥/密文，验证"篡改公钥后签名必失效"；复现
  CIFT 的"pk'≠pk 仍验证通过 / 隐式拒绝 FO 变体"在认证场景的后果。
- `comp_kdf_chain_harness.c`：HKDF-Extract/Expand 级联；改任一环 salt/info → 下游全变。

### 步骤 1.4 ✅ L3 第一个案例：AEAD nonce 重用 / EVP 状态机误用（传统）
> 已实现 `harness/seq_aead_harness.c`：O6-nonce-uniqueness（灾难性 nonce 复用，two-time pad 明文异或泄露）+ O6-release-before-verify（DecryptFinal 验证前禁止使用明文）。campaign 12M runs 0 违反，负向自测 2 例均 fire。
- `harness/seq_aead_misuse_harness.c` + 一个小**操作 DSL**（字节流→操作码序列）。
- O6 断言：同 key+nonce 加密两条不同消息 → 标记灾难性 nonce 重用（能异或出明文差即证明）；
  CBC 可预测 IV / IV 链；非法调用序列（Final 前读输出、ctx free 后再用）→ 必须报错/被 ASan 抓 UAF。
- 负向自测：构造一个"nonce 重用未被检出"的错误实现桩 → fire。

### 步骤 1.5 ✅ L3 第二个案例：签名随机数复用 & KEM/SIG API 误用
> 已实现 `harness/seq_ecdsa_harness.c`（ECDSA-P256 可控 nonce，k 复用→从 (r,s1,s2,z1,z2) 恢复私钥）与 `harness/seq_pqc_harness.c`（ML-KEM-768 密钥混淆免虚假协商）。各 campaign 0 违反，负向自测 2 例均 fire。**阶段1（1.1–1.5）全部完成。**
- **传统**：ECDSA 的 `k` 复用 / 可预测 → **可恢复私钥**（经典 PS3 事故），是最有说服力的传统
  有状态误用；harness 主动构造 k 复用并断言"能解出私钥=危险"。
- **PQC**：`seq_pqc_misuse_harness.c`：非法长度密文喂 Decaps（应拒绝不崩）、keypair 未生成就 sign。

**阶段 1 出口**：L2 三案例（含传统组合）+ L3 两案例（含传统 nonce/k 复用），各自带负向自测；
CURRENT_STATE 的"目标×oracle"矩阵 O5/O6 列由空变实——**且传统与 PQC 都进入 L2/L3**。

---

## 核心认知：测试面是二维矩阵，扩库同时放大 L1/L2/L3（回应"阶段2/3/4 和阶段1 什么关系"）

阶段划分**不是**"阶段1 创新、之后只是广度"的割裂关系。真实的测试面是：

```
测试面 = { 目标：库 × 算法 × 组合 × 序列 }  ×  { oracle：O1–O6 }
```

每接入一个新库/新算法，**同时**在三层都长出新格子，而不只是 L1：
- **L1**：多一份实现 → 更多 O1 差分对、更多 O2/O3/O4；
- **L2（O5）**：新库可作为组合的实现载体（它自己的 HPKE、Encrypt-then-MAC、RSA-KEM+AEAD），
  还能做**跨库组合差分**（同一 HPKE 用不同库拼，结果应一致）；
- **L3（O6）**：**每个库都有自己独特的 API 状态机**（OpenSSL EVP、mbedTLS、Botan、wolfCrypt 各不同），
  所以每接一个库就多一批 O6 误用靶——这恰恰是扩库对创新主线的直接贡献。

**所以阶段2/3/4 会持续放大阶段1 的 L2/L3 创新面**，不是脱节的两件事。因此扩库时的规矩是：
每接入一个新库，除了接 L1 差分，**同时**为它补一个 L3 API 误用靶、并让它参与至少一个 L2 组合。

---

## 阶段 2：横向扩库（每个新库同时接 L1 差分 + L2 组合 + L3 误用）

> 不只是"多库差分"，而是让每个新库都进入 L1/L2/L3 三层。

### 步骤 2.1 ✅ 差分再加 4 库：BoringSSL / aws-lc / wolfCrypt / Botan
- BoringSSL/aws-lc 与 OpenSSL 符号冲突 → 各自**独立子进程靶**，主控做差分比对。
- 先覆盖已有 5 个算法，验证 8 库一致；**并为每个新库补 1 个 L3 API 误用靶**（各库状态机不同）。

### 步骤 2.2 ✅ 差分算法扩展（在现有库上加算法）
- 顺序：SHA-3/SHAKE → AES-CCM/EAX/OCB、AES-GCM-SIV → HKDF/PBKDF2 → 经典公钥
  （RSA-PSS/OAEP、ECDSA P-256、Ed25519、X25519）。每个算法：O1 差分 + O2 性质 + (公钥) O3 + O4。

### 步骤 2.3 ✅ PQC 跨库差分：接 PQClean
- ML-KEM/ML-DSA/Falcon 在 liboqs vs PQClean 之间做 O1 差分（此前 PQC 只有 O2，现补 O1）。
- 已接 ML-KEM-768（FIPS 203）+ ML-DSA-65（FIPS 204）：随机化使字节不可比 → 互操作 oracle
  （KEM 双向 keygen/encaps/decaps 共享密钥相等；SIG 双向签名后两库判定一致）。双向 5000 迭代
  全一致，负向自测 28/28。待续 Falcon-512（PQClean 压缩签名格式差异是 CIFT 关注点，价值高）。

### 步骤 2.4 ✅ 跨语言差分：Go crypto ✅ + RustCrypto ✅（均走子进程桥）
- 统一"测试向量编码"（算法 id + 输入槽），C 链接、Rust、Go 子进程共用同一输入。
- ✅ Go：复用 `diff_subproc` 线协议，`harness/gobridge` 用 Go stdlib + x/crypto 实现全部 15 op
  （op0–14），Go↔OpenSSL 11000 向量全一致（seed 42/777）。
- ✅ Rust：`harness/rustbridge` 用 RustCrypto crates + dalek 实现全部 15 op，走同一线协议，
  Rust↔OpenSSL 11000 向量全一致（seed 42/777）。三方（OpenSSL/Go/Rust）跨语言血统互证，
  负向自测 30/30。全环境 Docker 化（clang+cmake+Go 1.22+Rust 1.83）。

### 步骤 2.5 ✅ FHE：OpenFHE↔SEAL BFV 跨库差分（O1）；SEAL 扩 CKKS（误差界 oracle O2）
- **BFV 跨库差分**（`harness/fhe_diff_harness.cpp`）：OpenFHE 与 Microsoft SEAL 两套独立
  同态库，统一明文模 t=65537、多项式度 8192。对随机 a,b,c∈[0,t) 各自做
  同态 add / mul / 分配律 a·(b+c)，解密结果必须两库一致且等于明文域结果 (mod t)。
  密文格式/RNS 布局各异且加密随机，故比对**解密明文**而非密文字节（与 PQC、公钥
  验签互操作差分同思路）。分歧触发 `O1_fhe_bfv_interop`。
- **CKKS 误差界**（`harness/fhe_ckks_harness.cpp`）：CKKS 近似算术无精确明文可比，
  改用误差界 oracle——|Dec(Enc(a)op Enc(b)) − (a op b)| 须落在按 scale 2^40 设定的
  绝对误差界内（add 1e-2、mul 1.0+相对项）。越界触发 `O2_ckks_error_bound`。
- 构建：`scripts/build_openfhe.sh`（克隆+编译 OpenFHE 静态库 v1.2.3）、
  `scripts/build_fhe_diff.sh`（g++/clang++ 链接 SEAL+OpenFHE），接入 `build_all.sh`。
- 负向自测：`negative_tests.sh` 新增两条——fault 变体（`CMF_FHE_FAULT`）分别令 BFV
  一库结果错位、CKKS 结果越界，确认两 oracle 均能捕获。
- 验证：BFV 差分 seed 42/777 各 1000 迭代全一致；CKKS 同样 2×1000 迭代全在误差界内；
  fault 变体分别触发 `O1_fhe_bfv_interop` / `O2_ckks_error_bound`。

---

## 阶段 3（P2）：生态扩展（进行中）
- ✅ **PyCryptodome 子进程桥**（`harness/subproc/compute_pycryptodome.py`）：纯独立实现
  （非 OpenSSL 封装），复用 stage 2.1 的 `diff_subproc` 线协议实现 op0–14（X25519 不支持→NA）。
  Python 成为第四条独立语言血统（继 OpenSSL/Go/Rust）。PyCryptodome↔OpenSSL 6000 向量全一致
  （seed 42/777 各 3000），fault 变体（`CMF_PY_FAULT`）触发 `DIFF_mismatch`。接入 build_all/
  negative_tests/Dockerfile（pip 装 pycryptodome）。
- ⬜ libgcrypt / NSS(freebl) / nettle 静态库或独立靶；
- ⬜ BouncyCastle(Java) / pyca 子进程桥（注：pyca 底层即 OpenSSL，差分意义有限）；
- ⬜ dalek 曲线差分；TFHE-rs / HElib（FHE 扩展）。

## 阶段 4（P3，探索）
- Tink 高层 API 误用（天然契合 L3/O6）；swift-crypto / Zig std.crypto 子进程桥；
- ZK：arkworks / gnark / libsnark —— 证明验证 / 电路一致性 oracle（几乎空白，最具探索性）。

---

## 工程支撑（随阶段 2 起逐步建设，为大规模接入铺路）
> 其中"差分根因定位"与"跨库组合(O5)"是让扩库真正放大创新面的关键，不只是堆库数。

1. **统一输入编码**：一份 fuzzer 字节 → (算法 id, 输入槽)，让 C/Rust/Go/子进程共用，降低接库成本。
2. **差分根因定位**：不一致时多数投票指认可疑实现，并缩小到中间值/步骤（把"发现分歧"推进到"解释分歧"）。
3. **每库独立 sanitizer 靶**：内存 bug 与差分/性质/常量时间三 oracle 解耦，互不干扰。
4. **spec 生成器接 LLM**：从 FIPS/RFC 文档自动实例化 O2/O5 关系（Pillar 1 的自动化上限）。
5. **CI 化**：build_all + negative_tests + 短 campaign 一键回归，防止扩库时旧靶回退。

---

## 覆盖进度追踪（每完成一步在此打勾，并同步更新 CURRENT_STATE）
- [x] 阶段0 L1 四 oracle
- [x] 1.1 HPKE 组合(O5)
- [x] 1.2 传统组合 Encrypt-then-MAC / TLS1.3 记录层(O5)
- [x] 1.3 KEM+SIG 组合 & KDF 链(O5)
- [x] 1.4 AEAD nonce 重用 / release-before-verify(O6，传统)
- [x] 1.5 ECDSA k 复用→私钥恢复 & PQC KEM 密钥混淆(O6)
- [x] 2.1 +BoringSSL/aws-lc/wolfCrypt/Botan（子进程差分，8 库一致；各库 1 个 L3 误用靶）
- [x] 2.2 差分算法扩展(SHA-3/KDF/公钥)——SHA-3 家族(op5–8: SHA3-256/512、SHAKE128/256)、
      KDF(op9 HKDF-SHA256、op10 PBKDF2-HMAC-SHA256)、公钥(op11 Ed25519 签名、op12 X25519)、
      **ECDSA-P256 验签互操作(op13)** 与 **RSA-PSS 验签互操作(op14)**——后两者因密钥结构化且
      ECDSA k / PSS salt 随机化、签名字节不可比，改用验签互操作 oracle：参照端签名(约半数篡改)，
      后端只回 1 字节接受/拒绝判定，五方判定一致(op13/op14 各一万一千向量、seed 42/777)。
      AEAD 模式(CCM/OCB/GCM-SIV)因 OpenSSL/后端支持不齐暂缓
- [x] 2.3 PQClean PQC 跨库差分（ML-KEM-768 KEM 互操作 + ML-DSA-65 验签互操作，liboqs↔PQClean 双向一致）
- [x] 2.4 Go/Rust 跨语言差分（Go crypto↔OpenSSL + RustCrypto↔OpenSSL，全 15 op 一致，两条独立语言血统）
- [x] 2.5 OpenFHE↔SEAL BFV 跨库差分(O1_fhe_bfv_interop) + SEAL CKKS 误差界(O2_ckks_error_bound)
- [~] 阶段3 生态扩展（PyCryptodome 跨语言差分✅；libgcrypt/NSS/nettle/BouncyCastle/dalek/TFHE-rs/HElib 待做）
- [ ] 阶段4 ZK/Tink/其他语言
