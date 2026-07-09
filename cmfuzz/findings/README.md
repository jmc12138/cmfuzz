# CMFuzz Findings（发现库）

本目录保存 fuzzing 过程中发现的**每一个问题**，一个问题一份独立文档，说明"如何发现 + 如何复现"。

## 目录结构
```
findings/
├── README.md            # 本文件：索引 + 命名规范 + 工作流
├── TEMPLATE.md          # 新发现的模板（复制它来写）
├── repro/               # 复现所需的输入样本（crash 输入、种子），按 finding id 建子目录
│   └── FIND-YYYYMMDD-NN/
│       └── <reproducer files>
└── FIND-YYYYMMDD-NN-<slug>.md   # 每个发现一份
```

## 命名规范
- 文档：`FIND-<日期>-<当天序号>-<短名>.md`，如 `FIND-20260709-01-ecdsa-k-reuse.md`
- 复现样本目录：`repro/FIND-<日期>-<当天序号>/`
- 日期用发现当天（UTC）；序号当天从 01 递增。

## 严重程度（severity）
- **critical**：可导致密钥泄漏 / 伪造 / 明文恢复（如 ECDSA k 复用、AEAD 认证被绕过）。
- **high**：违反安全定义但需特定条件（可锻造、SUF 缺失）。
- **medium**：功能/一致性错误（差分不一致、metamorphic 违反但影响有限）。
- **low**：健壮性 / 崩溃（无内存破坏后果）/ 反直觉 feature。
- **info**：非 bug 的观察（如"这是方案特性不是实现 bug"）。

## 类别（category，对应方法学）
`L1-diff` · `L1-metamorphic` · `L1-ct` · `L1-mem` · `L2-composition` · `L3-sequence`

## 工作流
1. campaign 跑出崩溃 / oracle 违反 → 保存触发输入到 `repro/FIND-.../`。
2. 复制 `TEMPLATE.md` 为 `FIND-....md`，填全"如何发现 / 如何复现"。
3. 用最小化后的输入验证复现命令能稳定重现。
4. 在下方**索引表**登记一行。
5. 通过隧道同步到本地。

> 说明：若某阶段 campaign 跑完 **未发现问题**，不写 finding 文档，只在 `docs/CURRENT_STATE.md`
> 的变更记录里记"某靶 campaign N runs / 0 违反"。findings 目录只放**真实发现**。

## 索引
| ID | 日期 | 目标(库/算法) | 层/oracle | severity | 状态 | 摘要 |
|---|---|---|---|---|---|---|
| —（暂无发现） | | | | | | |
