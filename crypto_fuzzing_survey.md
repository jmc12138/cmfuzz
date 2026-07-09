# 密码库 Fuzzing 现状调研与创新点分析

> 面向"CLFuzz 及其他密码库 fuzzing"的技术调研。分三部分：(A) 现有工作梳理，(B) 各类方法的共性局限，(C) 可做的创新点。文末附参考链接。

---

## 一、CLFuzz 详解

**论文**：CLFuzz: Vulnerability Detection of Cryptographic Algorithm Implementation via Semantic-aware Fuzzing（TOSEM 2023，清华 WingTecher 组，Yuanhang Zhou / Fuchen Ma / Yu Jiang 等）
**代码**：https://github.com/THU-WingTecher/CLFuzz

### 核心思路
CLFuzz 是一个**面向密码算法的生成式(generation-based)、语义感知的 fuzzer**。它认为通用 fuzzer（AFL/libFuzzer）不适合密码算法，因为：
1. 不同算法对输入有**多样化的语义约束**（如 AES-128 要求 128-bit key，key 长度不对就直接被校验拦截，主逻辑根本触发不到 → 大量无效执行）；
2. 密码实现有**复杂的函数变换**，随机变异很难触发边界/易错情形（极端长度、特殊值）；
3. 某些算法**实现数量少**，无法做有效的差分测试（差分需要 ≥2 个实现来交叉验证）。

### 三个关键技术
1. **语义信息提取**：为每个算法抽取"密码专属约束(cryptographic-specific constraints)"和"函数签名(function signatures)"，明确各输入字段的数据结构与取值约束。
2. **自适应输入生成**：针对不同数据结构字段做定向构造，提高触发边界情形（boundary conditions）的概率，而不是纯随机/覆盖引导变异。
3. **三阶段交叉检查(three-stage cross-check)做 bug oracle**：
   - **差分测试**（跨实现/跨版本对比结果）；
   - **运行时监控**（sanitizer 抓内存/崩溃/挂起）；
   - **逻辑交叉检查(logical cross-check)**——利用算法间的逻辑关系跨多轮测试验证（如 encrypt/decrypt 互逆、多种计算模式应等价），解决"实现数量太少无法差分"的问题。
配套"oracle recycling pool"（`recyclepool.cpp`）复用历史结果。

### 成果
> 注：以下为论文自报的单次评测数据（同一评测环境/target 集合下），引用时宜标注来源、不宜当作独立复现结论。
- 在 54 个算法的主流实现上评测；相比 Cryptofuzz **覆盖率提速 3.4×、最终覆盖率 +14.4%**；相比 CDF 覆盖率 +538%。
- 发现 12 个未知实现 bug（OpenSSL CMAC、SymCrypt Message Digest 等），7 个进入 NVD/CNVD，2 个获微软赏金。

---

## 二、其他密码库 Fuzzing 工作

### 1. 差分 fuzzing（跨实现对比）
- **Cryptofuzz**（Guido Vranken，跑在 OSS-Fuzz 上）：密码库差分 fuzzing 的事实标准。三类 oracle：(a) 内存/崩溃/挂起 bug（配 ASan/UBSan）；(b) **库内自差分**（同一库多种计算方式结果应一致，如 chunked vs 非 chunked 更新）；(c) **多库差分**（同一 primitive 多实现结果应一致，"至少一个实现是对的"假设）。支持 OpenSSL/BoringSSL/LibreSSL/Crypto++/libgcrypt/libsodium 等。当前主要由 MozillaSecurity 维护其仓库（`MozillaSecurity/cryptofuzz`）。
  - https://github.com/MozillaSecurity/cryptofuzz , https://guidovranken.com/2019/05/14/differential-fuzzing-of-cryptographic-libraries/
- **CDF (Crypto Differential Fuzzing)**：另一差分 fuzzer，覆盖 PRF、对称加解密、DSA、ECDSA，用无效参数做边界测试。
- **Project Wycheproof**（Google）：不是 fuzzer，而是**面向已知密码学缺陷精心设计的定向测试向量集**（弱曲线点、边界值、历史攻击）。与 Cryptofuzz 的"机会主义广撒网"互补。
- **官方测试向量生态（NIST CAVP / ACVP）**：CAVP 的 KAT 与 **ACVP（Automated Cryptographic Validation Protocol）**自动生成/验证测试向量，本质上是"官方权威参考源"——可作为差分测试的黄金参考、或作为 metamorphic oracle 的种子来源（对应第四部分创新点8）。
- **形式化验证过的"黄金参考实现"**：HACL\*/EverCrypt、fiat-crypto 等经过机器验证的实现，可直接作为差分基准，天然满足"至少一个实现是对的"假设（详见创新点8）。

### 2. 侧信道 / 常量时间(constant-time)检测
密码实现的另一大类 bug 是**时序侧信道**（非功能正确性）。这里进一步区分"动态/统计检测"与"（半）形式化验证"两类：

**(a) 动态 / 统计检测**
- **dudect**（Oscar Reparaz, `oreparaz/dudect`）：固定 vs 随机输入两类，测时间分布做 t 检验，判断是否常量时间。经典基线。
- **ctgrind**（Adam Langley，基于 Valgrind/Memcheck 把密钥标记为 uninitialized，检测其是否影响分支/访存地址）：动态污点式常量时间检测的先驱。
- **ct-fuzz**（arXiv 1904.07280）：把常量时间建模为 **2-safety 属性**（关于两条执行轨迹的等价性），让覆盖引导 greybox fuzzer 能检测时序泄漏。
- **SideFuzz**（phayes）：遗传算法最大化两输入间执行指令数差异 + t 统计，针对编译到 wasm 的密码代码。
- **Tacet**（tacet.sh）：贝叶斯建模 + Wasserstein-1 距离，给出 Pass/Fail/Inconclusive 三态判定，专为 CI 场景做统计严谨性；有实验性的功耗/EM 侧信道支持。

**(b) 静态 / 形式化验证（功能 fuzzer 基本不覆盖，融合时需交代与之的关系）**
- **ct-verif**、**Binsec/Rel**、**FlowTracker/CT-Verif 家族**：对二进制/中间表示做常量时间的（半）形式化验证。
- **常量时间语言/编译**：**FaCT**、**Jasmin**——从语言层面保证生成代码常量时间。
- Trail of Bits 的 **constant-time-analysis 插件**（静态分析编译后汇编，跨架构/编译器/优化级别检测 `DIV`/`FDIV`/条件分支等变时指令，如 KyberSlash 类问题）。

### 3. LLM 驱动的 fuzz driver / 输入生成（通用库，可迁移到密码库）
- **PromptFuzz**（CCS 2024）：覆盖引导的 prompt fuzzing 迭代生成 fuzz driver，含指导式程序生成、错误程序校验、覆盖引导 prompt 变异、fuzzer 调度；比 OSS-Fuzz/Hopper 分支覆盖高 1.6×，报 33 个新 bug。
- **OSS-Fuzz-Gen**（Google，已在 OSS-Fuzz 真实部署）：用 LLM 自动生成/改进 fuzz harness，并已在真实项目上发现新 bug、提升覆盖。相比 PromptFuzz 更能支撑"LLM 自动 driver"落地性的论据（见创新点1）。
- **"How Effective Are They?"**（ISSTA 2024）：首个系统研究 LLM 生成 fuzz driver 的效果；结论——对**规格复杂的 API（密码 API 正属此类）LLM 生成 driver 仍吃力**，缺少语义 oracle 来查逻辑 bug。
- **Chat4Seed**（QRS 2025）：LLM 生成高度结构化（含二进制）种子语料。
- **ELFuzz**（USENIX Security 2025）：用 LLM 在"fuzzer 空间"上演化，自动合成生成式 fuzzer，可扩展到百万行级 SUT。

### 4. 通用库 API fuzzing（方法可借鉴）
- **NEXZZER**（NDSS 2025）：模块化 driver 架构 + 中间 API 描述(Liblang) + 动态 APIGraph 学习 API 关系，自动过滤 API 误用、动态调度 API 调用序列。对"密码库多 API、有状态调用序列"的场景很有参考价值。
- **结构化 fuzzing 基础设施**：**libprotobuf-mutator**、Google **FuzzTest**（把 property-based 测试与覆盖引导 fuzzing 合一）——这正是"覆盖引导 + 语义生成融合"（创新点6）的现成工程载体，做原型时可直接站在其上。

### 5. 协议状态机 fuzzing（有状态密码交互，现有密码 fuzzer 的明显缺口）
密码库真实使用几乎都是**有状态、多步**的（握手、init/update/final、KEM 多步），单次原语调用的 fuzzer 覆盖不到这类 bug：
- **Protocol State Fuzzing of TLS**（de Ruiter & Poll, USENIX Security 2015）：用**主动自动机学习(active automata learning)**推断 TLS 实现的状态机，找出非法/多余状态转移（如 CCS 注入类问题）。
- **DTLS 状态学习**（"Analysis of DTLS Implementations Using Protocol State Fuzzing", USENIX Security 2020）：把上述方法扩展到 DTLS。
- **tlsfuzzer**（Hubert Kario, Red Hat）：面向 TLS 的差分/回归测试与 Bleichenbacher/timing oracle 检测框架。
- **TLS-Attacker**（Ruhr-Uni Bochum）：可编程构造任意 TLS 消息流，做协议层 fuzzing。
这条线对 **PQC 握手（如 ML-KEM 混合密钥交换）几乎无人系统研究**，是明显机会（对应局限4/创新点5）。

### 6. 后量子密码(PQC) / 新兴密码 fuzzing
- **KAT-Seeded Fuzzing of Stateful Hash-Based Signature Verification in liboqs**（eprint 2026/1107）：用 Known Answer Test 向量一次性初始化合法公钥/签名/消息，避开昂贵的密钥生成，高吞吐变异**验证路径**（专打 XMSS/XMSSMT、LMS/HSS-LMS）；10 分钟 ASan 跑出 `xmssmt_core_sign_open` 里的 **OID 混淆越界读(out-of-bounds read)**，分配 **CVE-2026-46344**，已在 **liboqs 0.16.0** 修复。
- **crypto-condor + 差分 fuzzing（Quarkslab）**：一致性检查 + 韧性测试工具链，在 HQC（第五个 PQC 标准）参考实现里发现两个关键 bug（CVE-2024-54137）。
- **Cryptographically-Informed Functional Testing (CIFT)**（TCHES 2026，Fenzi/Gilcher/Virdia，EPFL/ETH/Surrey；代码 https://github.com/jangilcher/cryptoTesting）：详见下方专节。
- **Eidolon**（清华 WingTecher，FSE 2026）：面向**全同态加密(FHE)**库的 noise-aware fuzzing——用剩余 noise budget 做反馈引导变异；用"**等价表达式变换**(Standard/Factored/Horner 等数学等价但结构不同的表达式)"互相对比构造 oracle，评测 SEAL/OpenFHE/HElib/TFHE。这是 CLFuzz 团队把语义感知思路迁移到 FHE 的延续。

### 7. 零知识证明(ZK) 电路测试（新兴、工具化程度低但非空白）
ZK 电路的核心缺陷是 **under-constrained（约束不足）** bug：见证可被恶意构造却仍通过验证。已有一批工作，说明这不是空白、而是"相对薄弱/工具尚未成熟"：
- **Ecne**：静态检查 R1CS 约束系统是否唯一确定输出。
- **Picus / QED²**：形式化判定 Circom 电路是否 under-constrained。
- **CODA**（PLDI 2023 方向）、**Circomspect**（Trail of Bits 静态 linter）、**SnarkProbe**（对 SNARK 库的安全分析）。
密码 fuzzing 视角下，把"soundness/completeness/约束唯一性"作为 oracle 系统化仍有空间。

### 8. 深入案例：CIFT（性质导向的功能测试）
**Finding Bugs and Features Using Cryptographically-Informed Functional Testing**，TCHES 2026，Fenzi(EPFL)/Gilcher(ETH)/Virdia(Surrey)，代码 https://github.com/jangilcher/cryptoTesting 。

- **出发点**：延续 Mouha 等人对 NIST SHA-3 参赛实现的事后审查（黑盒搜索"违反哈希应有性质"的反例，在含 2 个决赛者在内的多个实现里查出未知 bug），本文把方法**从哈希扩展到 KEM 和 DSS**——对应 PQC 两大类原语。
- **核心方法：密码学知识指导的 metamorphic testing**。不靠"另一实现做参考"（差分），而是把**密码学定义本应成立的性质**当 oracle，自动搜反例：
  - KEM 正确性：`Decaps(sk, Encaps(pk).c) == Encaps(pk).ss`（除可忽略概率）；
  - DSS 正确性：`Verify(pk, m, Sign(sk,m)) == 1`；
  - 叠加安全性推出的性质：IND-CCA KEM 密文应**不可锻造**、EUF/SUF 签名应不可伪造/改写。
  - 贡献之一：把测试过程**形式化成一套 DSL/syntax**，同一套逻辑跨 primitive/库/fuzzer 复用，接新算法成本极低；并显式建模实现里的**返回值语义**（理论定义忽略返回值，但实现常用它表示成败，是 bug 高发点）。
- **实验对象**：**LibOQS 多个历史版本**（覆盖 PQC 标准化不同阶段）+ SUPERCOP。
- **发现分三档**：
  1. 软件 bug：段错误、内存溢出；
  2. 密码学 bug：声称 IND-CCA 的 KEM 出现**密文可锻造(ciphertext malleability)**；
  3. **"反直觉但不违反安全性"的 feature**（最有意思）：Falcon 压缩签名格式缺**强不可伪造性(SUF)**（spec v1.1，Falcon 团队独立发现）；Rainbow/Falcon 公钥可改成 `pk'≠pk` 仍验证通过（LibOQS 0.4.0，源于隐式拒绝 FO 变体的通病）；随机化 Dilithium 在随机源故障时被改的 sk 仍能生成合法签名。这些不违反 IND-CCA/EUF-CMA，但会让用户意外，且可能在协议组合层出问题。
- **与传统 fuzzing 对比**：对 LibOQS/SUPERCOP 跑传统 fuzzing harness 做对照，结论——传统 fuzzing 在暴露**软件 bug + 逻辑 bug 上明显更弱**，因为没有"密码学期望性质"这个 oracle，只能靠崩溃/sanitizer。
- **对 CLFuzz 方向的启示**：CIFT 的 oracle **直接来自安全定义(IND-CCA/EUF-CMA)**、且不需多实现，比 CLFuzz 的人工逻辑交叉检查更进一步；其 **DSL 化可复用测试规格**正是"自动生成 metamorphic oracle"的现成骨架，可考虑用 LLM 从安全定义自动实例化，或把它接到 CLFuzz 的覆盖引导输入生成上做"性质导向 + 覆盖导向"融合。此外，"区分实现 bug / 方案定义特性 / 协议组合风险"本身就是一个有价值的贡献维度。

---

## 三、共性局限（= 创新机会的来源）

1. **Oracle 局限**：差分/自差分依赖"多实现"或"多计算路径"；单一实现或独占算法难验证。逻辑交叉检查覆盖的性质仍是人工枚举的有限集。
2. **只查功能正确性 + 内存安全**：主流密码 fuzzer（CLFuzz/Cryptofuzz）基本不管**侧信道/常量时间**；侧信道工具又基本不做功能 fuzzing——两条线割裂。
3. **语义约束靠人工**：CLFuzz 的"密码专属约束"、Cryptofuzz 的字段构造都需专家为每个算法手写，扩展到新算法（尤其 PQC/FHE/ZK）成本高。
4. **状态 & 序列覆盖弱**：密码 API 常是有状态多步调用（init/update/final、密钥协商握手），现有生成式 fuzzer 偏"单次原语调用"，对调用序列/状态机探索不足（协议状态机 fuzzing 那条线其实已给出范式，但尚未迁移到密码库/PQC）。
5. **协议层、组合层缺失**：多为单算法/单 primitive；跨算法组合（AEAD 拼装、KEM+DEM、TLS record 层）、参数协商引发的 bug 少有覆盖。
6. **可复现性/根因定位差**：多库差分报不一致时，"谁错"要人工判定；缺自动化 root-cause 与最小化。
7. **评测方法学不统一**：不同工具用不同覆盖指标、不同 target 集、不同 bug 去重/ground-truth 口径，横向比较困难——这本身就是一个需要在论文里正面交代的问题。

---

## 四、可做的创新点（按可行性/新颖度排序）

### A. 高价值、较可行
1. **LLM 自动合成"语义约束 + driver + oracle"**：CLFuzz 最大人工成本在于为每个算法手写约束和签名。用 LLM 从 RFC/NIST 标准文档 + 头文件 + 参考实现自动抽取输入约束、函数签名、并生成 metamorphic oracle（如"encrypt∘decrypt=id"、"多模式等价"）。正好补上 ISSTA 2024 指出的"LLM 缺语义 oracle 查逻辑 bug"的短板，也让工具能一键扩展到新算法。
   - **与 CIFT 的界限（务必写清，否则易被判为"自动化已有工作"）**：CIFT 已经用**手工 DSL** 把"从安全定义生成 oracle"这件事做了；本方向的增量必须明确落在"**用 LLM 自动实例化这套 DSL / 自动从 spec 生成性质**"，并有可量化的省人工 + 新 bug 证据。建议第一个里程碑很具体：从 **FIPS 203/204** 自动抽 ML-KEM/ML-DSA 的性质，拿 **LibOQS 历史 bug** 做回归验证。
2. **统一功能 + 常量时间的双 oracle fuzzer**：在一次 fuzzing 里同时跑差分/逻辑 oracle（功能 bug）和 dudect/2-safety 风格的时序 oracle（侧信道），共享输入生成器与语义约束。目前两类工具完全割裂，融合有明显价值（尤其对 PQC 常量时间要求高）；论文里需交代与 ct-verif/Binsec-Rel 等（半）形式化方法的定位差异。这是较现实、可单独成文的单点课题。
3. **面向 PQC/FHE/ZK 的语义感知 fuzzer**：把 CLFuzz 的思路系统迁移到后量子（ML-KEM/ML-DSA/SLH-DSA/HQC）、FHE、零知识证明库。这些库新、bug 多、oracle 难（Eidolon、liboqs KAT、CIFT 已开头但覆盖有限）。ZK（证明系统 soundness/completeness、约束系统 under-constrained bug）工具化程度仍低（Ecne/Picus/Circomspect 已起步），把它纳入统一 fuzzing 框架仍有空间。

### B. 中等难度、较新颖
4. **metamorphic / 代数关系自动挖掘作 oracle**：不止人工枚举 encrypt/decrypt，而是自动发现算法的代数不变量（同态性、双线性配对等式、承诺可加性）作为跨轮 oracle，突破"实现数量少无法差分"的限制。Eidolon 的"等价表达式变换"是雏形，可推广。
5. **状态/序列感知的密码 API fuzzing**：借鉴 NEXZZER 的 APIGraph 与协议状态机学习(de Ruiter & Poll / DTLS 状态学习)，为有状态密码 API（流式 AEAD、握手状态机、KEM 多步）建模合法调用序列，探索 init/update/final 顺序错误、context 复用、nonce 重用等**误用类 bug**（这类 bug 在真实 CVE 里占比很高，如 nonce 复用、Bleichenbacher/ROBOT padding oracle、invalid-curve）。**PQC 混合握手**几乎无人做，是空白。
6. **覆盖引导 + 语义生成融合**：CLFuzz 是纯生成式，Cryptofuzz 基于 libFuzzer 覆盖引导。把语义约束编码进结构化变异（structure-aware mutation，可基于 libprotobuf-mutator / FuzzTest 实现），既保证输入有效性又保留覆盖反馈，理论上兼得两者优点。

### C. 更前沿/探索性
7. **差分不一致的自动根因定位**：多库结果不一致时，用 delta-debugging + 覆盖对比 + LLM 解释自动指出"哪个库、哪一步偏离规范"，把差分 fuzzing 从"报警"升级到"定位"。
8. **形式化规格作 oracle（可执行规范差分）**：用 HACL\*/fiat-crypto 等经过形式化验证的实现，或 NIST ACVP/CAVP 官方向量作为"黄金参考"与被测库差分，天然解决"至少一个对"的假设问题。
9. **编译器/优化级别引起的常量时间回归 fuzzing**：结合静态汇编分析（ToB constant-time-analysis 插件、Binsec/Rel）的多编译器/多架构视角，做"源码常量时间但某优化级别/架构下泄漏"的差分回归检测（KyberSlash 类问题的系统化）。

---

## 五、给 CLFuzz 方向的具体延伸建议
若目标是"在 CLFuzz 基础上做下一步工作"，最有故事性的组合是：
**"LLM 自动抽取语义约束 + 自动生成 metamorphic oracle" × "功能 + 常量时间双检测" × "覆盖 PQC/FHE"**——即把 CLFuzz 的人工瓶颈用 LLM 打通，把 oracle 从功能扩展到侧信道，把目标从传统算法扩展到后量子/同态。三者任一单独都可成文，组合则是完整系统。

**动手第一步（建立基线）**：先把 CLFuzz + Cryptofuzz 跑起来、固定一组 target 建立可复现基线，并明确评测口径（覆盖指标、bug ground-truth、去重），再选切口。这一步也能顺带核对第一部分中论文自报的数据。

--- 

## 参考链接
- CLFuzz 代码：https://github.com/THU-WingTecher/CLFuzz ；论文：https://doi.org/10.1145/3628160
- Cryptofuzz：https://github.com/MozillaSecurity/cryptofuzz ；差分 fuzzing 博文：https://guidovranken.com/2019/05/14/differential-fuzzing-of-cryptographic-libraries/
- Project Wycheproof：https://github.com/C2SP/wycheproof ；NIST ACVP：https://pages.nist.gov/ACVP/
- 常量时间：ct-fuzz https://arxiv.org/pdf/1904.07280 ；dudect https://github.com/oreparaz/dudect ；ctgrind https://github.com/agl/ctgrind ；SideFuzz https://github.com/phayes/sidefuzz ；Tacet https://tacet.sh/ ；ToB constant-time-analysis https://github.com/trailofbits/skills/tree/main/plugins/constant-time-analysis ；Jasmin https://github.com/jasmin-lang/jasmin
- LLM/driver：PromptFuzz https://doi.org/10.1145/3658644.3670396 ；OSS-Fuzz-Gen https://github.com/google/oss-fuzz-gen ；LLM fuzz driver 研究 https://doi.org/10.1145/3650212.3680355 ；ELFuzz https://www.usenix.org/system/files/usenixsecurity25-chen-chuyang.pdf
- API/结构化：NEXZZER https://chluo1997.github.io/papers/ndss25_nexzzer.pdf ；FuzzTest https://github.com/google/fuzztest ；libprotobuf-mutator https://github.com/google/libprotobuf-mutator
- 协议状态机：Protocol State Fuzzing of TLS（de Ruiter & Poll, USENIX Security 2015）；tlsfuzzer https://github.com/tlsfuzzer/tlsfuzzer ；TLS-Attacker https://github.com/tls-attacker/TLS-Attacker
- PQC：liboqs KAT fuzzing https://eprint.iacr.org/2026/1107 ；HQC bugs（Quarkslab）https://blog.quarkslab.com/finding-bugs-in-implementations-of-hqc-the-fifth-post-quantum-standard.html ；CIFT https://doi.org/10.46586/tches.v2026.i1.425-447 ，代码 https://github.com/jangilcher/cryptoTesting
- FHE：Eidolon http://www.wingtecher.com/themes/WingTecherResearch/assets/papers/paper_from_26/Eidolon.pdf
- ZK：Ecne https://github.com/franklynwang/EcneProject ；Circomspect https://github.com/trailofbits/circomspect
