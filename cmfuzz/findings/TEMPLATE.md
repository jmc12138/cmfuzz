# FIND-YYYYMMDD-NN: <一句话标题>

- **ID**: FIND-YYYYMMDD-NN
- **发现日期(UTC)**: YYYY-MM-DD
- **目标库/版本**: <e.g. OpenSSL 3.0.2 / liboqs 0.16.0-rc1>
- **算法/组合**: <e.g. AES-256-GCM / HPKE(X25519+HKDF+AES-GCM)>
- **层 / oracle**: <L2-composition / O5-context-binding>
- **severity**: <critical|high|medium|low|info>
- **状态**: <new|confirmed|explained-as-feature|fixed-upstream|wontfix>

## 1. 摘要
<两三句：违反了什么性质 / 崩溃在哪 / 后果是什么。>

## 2. 如何发现
- **harness**: `harness/xxx.c`（哪个靶）
- **oracle**: 违反的具体断言（贴 CMF_VIOLATION 那行 / sanitizer 报告）
- **campaign**: 命令 + 运行时长 + 第几次触发
```
<触发时的 stderr / ASan 摘要>
```

## 3. 如何复现（精确、可稳定重现）
- **构建**:
```
<build 命令>
```
- **复现输入**: `findings/repro/FIND-YYYYMMDD-NN/<file>`（已最小化）
- **运行**:
```
<run 命令，喂入 repro 输入>
```
- **预期**: 无违反/正常拒绝；**实际**: <触发的现象>

## 4. 根因分析
<为什么发生：实现 bug / 方案特性 / 组合层放大 / API 误用未被拦。>

## 5. 影响与建议
<可利用性、影响范围、修复或缓解建议、是否已上报上游。>
