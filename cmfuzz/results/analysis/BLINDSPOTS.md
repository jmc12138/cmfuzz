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

---

## 修复状态（2026-07-10，按优先级 H→G→E→B→C→A→D→F 落地）

全部改动均在 Linux 开发克隆上编译+功能验证（含故障注入负向自测），经隧道同步到本地仓库并 `commit` + `push` 到 GitHub。每条列出提交哈希与验证结论。

- **H 工程/运行**（`3a6135f` `1ade012` `413c108`）：`run_campaign.sh` 用 `-help=1` 探针只跑真正的 libFuzzer 靶，compute_*/diff_subproc/cmf_*/fhe_* 自动跳过；子进程差分用 `fork/exec` 取代 `popen`，无 shell，路径含引号/空格/元字符不再破；新增 `classic_openssl` 种子语料 + 按靶自动挂载 `dicts/`、`seeds/`。验证：探针正确跳过三个 CLI；6000 向量差分经 fork/exec 全通过。
- **G 恒定时间**（`dbe8ca6` `5f1fca8`）：传统 dudect 按「期望恒定/期望变时」分级并接真实算法靶（AES-NI、CRYPTO_memcmp、naive_memcmp、**AES-CBC PKCS#7 padding-oracle(op3)**、**HMAC-SHA256 内容(op4)**）；PQC 按算法白名单分级（ML-DSA/Falcon 设计变时不再淹没真信号）。验证：5 个 trad op 判定全部符合预期（op3 EXPECTED_VARTIME，op4 OK）。
- **E 多库差分**（`802402d`）：`diff_multilib` 扩到 SHA-1 / SHA3-256 / SHA3-512 / HMAC-SHA512 / HKDF-SHA256 跨 4 库（OpenSSL/libsodium/MbedTLS/Crypto++）。验证：20 万输入 0 分歧；故障构建即触发 DIFF_mismatch。
- **B 对抗/边界输入**（`84f50ca`）：注入块边界(15/16/17/31/32/33/63/64/65)、超长、全零/全 FF 等边界；**移除 X25519 的 bit255 屏蔽并纳入低阶点/非规范坐标向量**成为 oracle 目标。验证：差分覆盖 X25519 边缘向量，honest 运行无误报。
- **C Oracle 设计**（`882c2de`）：改星型单参照为**跨库多数投票**（OpenSSL + 各后端共同表决 ground truth，OpenSSL 与某后端共享 bug 也能暴露）；**NA 暴露**（每后端 answered/NA/diverged 计数，静默不实现可见）；verify 篡改更强。验证：故障后端触发时输出 `majority=...`，多数表决生效。
- **A 原语覆盖**（`699ec7b` `2ec73bc` `56335cd`）：ops 15-26 —— 额外摘要(SHA-1/224/384/512-256/MD5)、HMAC(SHA-1/384/512)、AEAD/MAC(AES-128/192-GCM、Poly1305、CMAC-AES-256)，覆盖 ref(OpenSSL)+nettle+libgcrypt；`CMF_NUM_OPS` 15→27。验证：6000 向量 0 分歧，NA 计数正确（nettle 无裸 Poly1305 落 NA）；两个后端故障变体各触发 1600+ 分歧。
- **D PQC**（`5ce0220` `4072a2e`）：`pqc_diff` 从写死 ML-KEM-768/ML-DSA-65 扩到**全部 6 个参数集**(ML-KEM-512/768/1024 + ML-DSA-44/65/87) liboqs↔PQClean 双向互操作；新增**确定性 NIST-KAT 字节级跨库比对**（共享 AES-256-CTR-DRBG，两库同种子输出应逐字节相同）。验证：6 方案差分全通过；KAT 6 方案 pk/sk/ct/ss、pk/sk/sig 全字节相同；故障构建即触发 O1_kat_bytes。
- **F ZK/FHE**（`95fd0d0` `5df485d` `94756c7`）：新增 **CKKS 跨库差分**（OpenFHE↔SEAL，误差界 + 跨库容差双 oracle）；ZK Groth16 加**畸形证明(篡改 C 群元)**与**错误 CRS(独立 setup)**两条 soundness 检查；TFHE 因无第二成熟 TFHE/CGGI 库无法跨库，改为补齐单库度量——加**加密比较(gt/lt/eq/ne)与位运算(and/or/xor)**（比较是 TFHE 区别于 BFV/CKKS 的能力）。验证：三者 honest 均通过，故障构建均触发各自 oracle。

---

## 全量运行 & 挖洞结果（2026-07-10）

在 VM 后台构建全部后端（nettle/gcrypt/go/rust/pycryptodome/BouncyCastle/BoringSSL/aws-lc/Botan）+ 全部重型靶（SEAL/OpenFHE/TFHE/ZK/PQClean），挂长时间差分 + libFuzzer + PQC/CT campaign 找真实漏洞。

**结果：被测库中未发现真实密码学漏洞（成熟库的预期干净结果，且证明预言机不误报）。**
- 子进程差分 campaign：200 seed × 3000 向量 × 9 后端 = **540 万次判定，0 分歧**。
- diff_multilib libFuzzer：**3290 万 exec，0 crash / 0 分歧**（cov 1484）。
- pqc_diff 6 方案双向互操作全一致；pqc_kat 6 方案 pk/sk/ct/ss/sig 逐字节相同。
- fhe_diff(BFV) 与 fhe_ckks_diff(CKKS) OpenFHE↔SEAL 均在误差界内一致；ZK Groth16 完备性+可靠性成立；TFHE 算术/位运算/比较正确。
- 全部故障注入自测仍能正确触发违例 → 预言机确能抓真 bug。

**唯一的分歧模式（已定性为良性并修复预言机）**：验签 op（ECDSA-P256 op13）上，篡改后的 DER 签名让 OpenSSL 干净拒绝（`00`），而 BouncyCastle 抛 DER 解析异常（`ERR`）——**二者都不接受**，只是错误信号形式不同，非漏洞。此前严格字符串比较把这个良性差异误报为分歧（600k 向量约 197 次）。

**修复（`58baba5`）**：验签 oracle（op13/14）改为只比较 accept 位，把 `ERR` 规范化为「不接受」等同 `00`。这样良性的 reject-vs-error 不再误报，但两类真 bug 仍能抓到——(1) 有效签名被拒（`openssl=01` 而后端 `00/ERR`）、(2) 伪造被接受（`openssl=00` 而后端 `01`）。用「永远接受」的恶意后端验证：修复后仍正确触发 VERIFY_mismatch；对良性 reject-vs-error 则不再报。修复后重跑 200 seed campaign 归零。
