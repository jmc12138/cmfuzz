# CMFuzz 测试方法学（重整版）

> 目的：把"传统四 oracle"和新增的**组合/协议层(方向4)**、**API 序列/误用层(方向5)** 统一成
> 一张清晰的方法学。对**每一个算法、每一个协议/组合实现**，明确"我们要做什么测试"。
> 原来的四个 oracle 一个都不放弃，只是把被测对象从"单函数"抬升到"组合 + 有状态序列"。

---

## 0. 总纲：被测目标分三层 × oracle 六类

### 被测目标三层
| 层 | 代号 | 被测对象 | 例子 |
|---|---|---|---|
| L1 单原语 | PRIM | 一个密码函数/算法本身 | SHA-256、AES-GCM、ML-KEM、ML-DSA、SEAL-BFV |
| L2 组合 / 弱协议 | COMP | 多个原语按标准方式串起来 | HPKE(KEM+KDF+AEAD)、密钥派生链、KEM+SIG 组合 |
| L3 序列 / API 状态机 | SEQ | 对同一原语/上下文的**调用序列** | EVP init→update→final 误用、nonce 重用、ctx free 后再用 |

### oracle 六类（O1–O4 保留，O5–O6 新增）
| 代号 | oracle | 判据 | 需要参照物？ |
|---|---|---|---|
| **O1** | 差分 (differential) | 多实现同输入输出必须一致 | 需 ≥2 实现 |
| **O2** | metamorphic / 性质 | 密码定义本该成立的关系（往返、篡改拒绝、EUF/SUF…） | 单实现即可 |
| **O3** | 常量时间 (dudect) | secret-dependent 操作时序不应依赖秘密 | 单实现即可 |
| **O4** | 内存安全 (ASan/UBSan) | 无越界/UB/泄漏 | 单实现即可 |
| **O5** | **组合不变量 (composition MR)** | 多原语串起来后端到端性质成立；上游缺陷在组合中是否被放大 | 单/多实现 |
| **O6** | **序列/误用 oracle (stateful)** | 非法/危险调用序列必须被拒绝或不产生灾难性后果 | 单实现即可 |

> 说明：O1–O4 作用在 L1（也可用于 L2 的子步骤）；**O5 是 L2 的核心**；**O6 是 L3 的核心**。
> 一个被测目标通常同时被多类 oracle 覆盖（见下方矩阵）。

---

## 1. L1 单原语：每个算法做什么（O1–O4）

对每个原语，按其"密码学契约"实例化 O2，能凑够多实现的加 O1，含 secret 分支的加 O3，全部加 O4。

### 1.1 哈希 / XOF（SHA-256/512、SHA3、SHAKE）
- **O2**：确定性 `H(m)==H(m)`；分块一致 `H(a∥b)==update(a);update(b)`；(XOF) 前缀一致 `SHAKE(m,n)` 是 `SHAKE(m,n')` 的前缀 (n<n')。
- **O1**：OpenSSL/libsodium/mbedTLS/Crypto++ 四库逐字节比对。
- **O3**：一般数据无关，可抽查。 **O4**：全程。

### 1.2 MAC（HMAC、Poly1305、KMAC）
- **O2**：确定性；密钥敏感（翻转 key 一位 → tag 必变）；验证一致 `verify(k,m,MAC(k,m))==1`。
- **O1**：多库比对。 **O3**：tag 比较必须常量时间（`CRYPTO_memcmp` vs 朴素比较，见已实现）。 **O4**：全程。

### 1.3 AEAD（AES-GCM、ChaCha20-Poly1305、AES-CCM/SIV）
- **O2**：往返 `Dec(Enc(m))==m`；篡改拒绝（改 1 位 ct/tag/aad → 解密失败）；错误 key/nonce 失败。
- **O1**：多库比对（相同 key/nonce/aad → 相同 ct∥tag）。
- **O3**：AES 查表实现 / tag 比较的时序。 **O4**：全程。

### 1.4 KEM（ML-KEM、Kyber、Frodo、BIKE、HQC…）
- **O2**：正确性 `Decaps(sk,Encaps(pk))==ss`；密文不可锻造（改密文 → ss 变或拒绝）；错误 sk 失败；解封装确定性。
- **O1**：标准化算法 vs PQClean/pqcrystals/OpenSSL3.5+（**未来接入**）。
- **O3**：`decaps`（secret-dependent）。 **O4**：全程。

### 1.5 签名（ML-DSA、Falcon、SLH-DSA…）
- **O2**：`Verify(pk,m,Sign(sk,m))==1`；EUF（改消息/签名 → 验证失败）；SUF（不能产生第二个对同一 (m) 有效的签名）；错误 pk 失败。
- **O1**：vs PQClean/pqcrystals（**未来**）。
- **O3**：`sign`（注意 Dilithium 拒绝采样本身数据相关，属公开随机不泄密钥——O3 需正确解读）。 **O4**：全程。

### 1.6 FHE（SEAL BFV/CKKS）
- **O2**：同态运算 vs 明文域 `Dec(Enc(a)⊙Enc(b))==(a∘b) mod t`；等价改写 `a*(b+c)==a*b+a*c`；(CKKS) 近似误差在界内。
- **O1**：vs OpenFHE/HElib（**未来**）。 **O4**：全程（O3 对 FHE 一般不适用）。

---

## 2. L2 组合 / 弱协议：每个组合做什么（核心 = O5，复用 O1–O4）

> 甜点：**不实现完整通信协议**，只把原语按标准方式串起来，测端到端不变量，
> 并专门检验"L1 发现不了、但组合层会暴露"的问题（如 CIFT 的可锻造公钥/SUF 缺失在组合中的后果）。

### 2.1 HPKE = KEM + KDF + AEAD（第一个案例）
组合流程：`Encaps(pk)->(enc,ss)`；`ss -> HKDF -> key,nonce`；`AEAD.Enc(key,nonce,aad,m)`；接收端反向。
- **O5-往返**：接收端解出的明文 == 发送端明文。
- **O5-上游缺陷放大**：把 KEM 公钥/密文按 O2 已知的"可锻造"方式篡改，检验组合层是否
  出现"双方派生出不同 key 但都不报错"或"篡改 enc 仍解出旧 key"——即**把 CIFT 单原语发现抬到组合层看真实后果**。
- **O5-上下文绑定**：`aad`/info 改变必须导致解密失败（HPKE 的 key-committing / 上下文绑定性质）。
- 复用：每个子步骤仍受 O1/O2/O4 覆盖；派生用的 AEAD 仍查 O3。

### 2.2 KEM + 签名 组合（认证密钥交换骨架）
- **O5**：`Sign` 覆盖 KEM 公钥/密文，验证"篡改公钥后签名应失效"；检验 CIFT 的
  "pk'≠pk 仍验证通过 / 隐式拒绝 FO 变体"在认证场景是否导致接受伪造对端。

### 2.3 密钥派生链（KDF chain：HKDF-Extract/Expand 级联）
- **O5**：链式派生确定性与单调性；改 salt/info 任一环 → 下游全部密钥应改变；
  长度扩展 / 前缀无关性。

### 2.4 传统组合（传统算法同样有组合问题）
- **Encrypt-then-MAC vs MAC-then-Encrypt**：往返 + 篡改拒绝；MAC 必须覆盖密文与关联数据。
- **TLS1.3 记录层**：`HKDF -> traffic key -> AEAD`，改 nonce 序号/上下文必须失败。
- **混合 KEM（hybrid）**：X25519 + ML-KEM 组合，任一份额被篡改都应导致失败。

### 2.5 （可选，中协议）Noise/X3DH 片段
- 用现成库（noise-c 等）当被测对象，只测密钥协商那段的 O5 不变量，不自研协议。

---

## 3. L3 序列 / API 状态机：每个实现做什么（核心 = O6）

> 这里"协议"= **库自己的使用契约（state machine）**，不是通信协议。
> 输入模型不同：生成的是**有状态的操作序列**，不是一段无状态字节。

### 3.1 AEAD / 分组模式 误用（传统）
- **O6-nonce 重用**：同 key+nonce 加密两条不同消息 —— 对 GCM 应可被检测为灾难（能恢复
  认证密钥 / 异或出明文差）；harness 主动构造并断言"这是危险状态"。
- **O6-CBC IV**：可预测/复用 IV；IV 链式复用。
- **O6-顺序**：`Final` 前读取输出、`Update` 在 `Final` 之后、未设置 IV 就加密 —— 必须报错而非静默产出。

### 3.1b 签名随机数复用（传统，最有说服力）
- **O6-ECDSA k 复用/可预测**：复用或可预测的 `k` → **可恢复私钥**（经典 PS3 事故）。
  harness 主动构造两次同 `k` 的签名并断言"能解出私钥 = 危险状态被检出"。

### 3.2 EVP / 上下文状态机（OpenSSL EVP_CIPHER_CTX、EVP_MD_CTX）
- **O6**：init→update→final 之外的非法转移；ctx 释放后再用（配 ASan 抓 UAF）；
  重复 final；混用 encrypt/decrypt 上下文。

### 3.3 KEM/SIG API 误用
- **O6**：用未初始化/长度不符的 buffer；对 `Decaps` 喂长度非法的密文（应拒绝不崩）；
  keypair 未生成就 sign。

### 3.4 输入模型
- 用一个小的**操作 DSL**（字节流 → 操作码序列 + 参数），libFuzzer 变异操作序列本身，
  ASan/UBSan(O4) 兜内存问题，O6 断言"危险/非法状态被正确处理"。

---

## 4. 总矩阵：目标 × oracle

| 目标 | 层 | O1 差分 | O2 性质 | O3 常量时间 | O4 内存 | O5 组合 | O6 序列 |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|
| SHA-256/512 | PRIM | ✅ | ✅ | ○ | ✅ | — | — |
| HMAC | PRIM | ✅ | ✅ | ✅(tag比较) | ✅ | — | — |
| AES-GCM / ChaCha20-Poly1305 | PRIM | ✅ | ✅ | ✅ | ✅ | — | ◑(→L3) |
| ML-KEM/Kyber/… | PRIM | ◔(未来) | ✅ | ✅(decaps) | ✅ | — | — |
| ML-DSA/Falcon/SLH-DSA | PRIM | ◔(未来) | ✅ | ✅(sign) | ✅ | — | — |
| SEAL BFV/CKKS | PRIM | ◔(未来) | ✅ | — | ✅ | — | — |
| **HPKE(KEM+KDF+AEAD)** | COMP | — | (子步) | (AEAD) | ✅ | ✅ | — |
| **KEM+SIG 认证** | COMP | — | (子步) | — | ✅ | ✅ | — |
| **KDF chain** | COMP | — | ✅ | — | ✅ | ✅ | — |
| **AEAD nonce 重用 / EVP 状态机** | SEQ | — | — | — | ✅ | — | ✅ |
| **KEM/SIG API 误用** | SEQ | — | — | — | ✅ | — | ✅ |

图例：✅ 计划做 / ◔ 未来接入(需第二实现) / ○ 抽查 / ◑ 部分 / — 不适用。

---

## 5. 创新定位（相对以往工作）

以往密码 fuzzing **几乎都停在 L1（单原语、无状态）**：Cryptofuzz=L1+O1，CLFuzz=L1+O2(人工)，
CIFT=L1+O2(性质)，dudect=L1+O3。**本工作的创新不是"把它们拼起来"，而是把测试对象从
L1 抬升到 L2/L3**：
1. **L2 组合层 metamorphic(O5)**：首次系统地在"原语组合/HPKE/密钥链"层做性质 fuzzing，
   并把 CIFT 等在单原语发现的"特性/缺陷"放到组合层验证其**真实可利用后果**（以往只停在"这是个 feature"）。
2. **L3 序列层误用检测(O6)**：把无状态 fuzzing 扩展为**有状态操作序列** fuzzing，覆盖 nonce 重用、
   EVP 状态机等真实 CVE 高发区。
3. O1–O4 作为**底座**继续对每个原语生效，保证组合层发现的问题能下钻定位到具体原语。

验证有效性：用**旧版 liboqs / 已知 CVE 版本**复现真 bug（L1），并构造组合层场景证明 O5/O6 能发现 L1 漏检的问题。

---

## 6. 落地顺序
1. （已完成）L1 四 oracle：diff / trad-metamorphic / ct-dudect / ASan-UBSan。
2. L2 第一个案例 **HPKE 组合 harness**（O5：往返 + 上游缺陷放大 + 上下文绑定）。
3. L3 第一个案例 **AEAD nonce-reuse / EVP 状态机 harness**（O6 + 操作 DSL）。
4. 旧版 liboqs 复现真 bug，串起 L1→L2 的"发现→定位"闭环。
5. 逐步接第二实现（PQClean/OpenFHE）打开 PQC/FHE 的 O1 差分。
