# WAF 规则调试台 (SecLang → Rust → WASM)

把 WAF 规则引擎核心用 Rust 实现、编译成 WASM 跑在浏览器里的调试台。
贴一段原始 HTTP 请求，就能逐条规则、逐个变量、逐个 transform 看匹配过程，
上线前验证规则会不会误杀。全部计算在本地浏览器内完成，请求不会外发。

## 快速开始

```sh
./serve.sh          # 构建 WASM 并起本地服务, 默认 http://localhost:8080
# 或者分步:
cargo build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/waf_debug.wasm web/
cd web && python3 -m http.server 8080
```

运行测试: `cargo test` (32 个用例覆盖正则/transform/HTTP 解析/SecLang/引擎语义)

## 支持的 SecLang 子集

**指令**: `SecRule` / `SecAction` / `SecRuleEngine` / `SecDefaultAction` / `SecMarker`,
支持 `\` 续行和 `#` 注释。

**变量**: `REQUEST_METHOD` `REQUEST_URI(_RAW)` `REQUEST_FILENAME` `QUERY_STRING`
`REQUEST_LINE` `REQUEST_PROTOCOL` `REQUEST_BODY` `REQUEST_CONTENT_TYPE(_LENGTH)`
`REQUEST_HEADERS(_NAMES)` `REQUEST_COOKIES(_NAMES)` `ARGS` `ARGS_GET` `ARGS_POST`
及对应 `_NAMES`、`FILES` `TX` `MATCHED_VAR(S)` `REMOTE_ADDR` `SERVER_NAME`
`MULTIPART_STRICT_ERROR` `REQBODY_ERROR`。
支持 `:selector`、`!/regex/` 选择器、`!` 排除、`&` 计数。

**操作符**: `rx` `pm`/`pmFromFile` `contains` `containsWord` `streq` `beginsWith`
`endsWith` `within` `eq` `ne` `gt` `ge` `lt` `le` `validateByteRange`
`unconditionalMatch`,支持 `!` 取反和参数里 `%{...}` 宏展开。不带 `@` 的模式按 `rx` 处理。

**Transform**: `urlDecode` `urlDecodeUni` `htmlEntityDecode` `lowercase` `uppercase`
`removeNulls` `removeWhitespace` `compressWhitespace` `trim(Left/Right)` `cmdLine`
`normalisePath(Win)` `length` `none`。链式依次执行,页面展示每一步的中间值。

**动作**: `id` `phase(1/2)` `msg` `logdata` `tag` `severity` `log/nolog`
`pass/block/deny/drop/allow` `status` `capture` `setvar`(tx.*,支持 `+N`/`-N`/`%{...}`)
`chain` `skip`/`skipAfter` `ctl:ruleRemoveById(支持区间)` `ctl:ruleRemoveByTag`
`ctl:ruleRemoveTargetById` `ctl:ruleEngine`。

**异常评分**: 异常模式下 `block/deny` 按 severity 加分
(CRITICAL=5 ERROR=4 WARNING=3 NOTICE=2,未写 severity 默认 5),
分数直接累加进 `tx.anomaly_score`(trace 里能看到 TX 变化);
规则自己 `setvar:tx.anomaly_score=...`(CRS 风格)或变量里引用了 `TX`
(如 949 阈值判定规则)时不重复加分。最终 `tx.anomaly_score >= 阈值` 判 BLOCK。
预定义 `tx.critical/error/warning/notice_anomaly_score` 和
`tx.inbound_anomaly_threshold`(= 页面阈值),可以直接贴 CRS 风格的评分规则。

## 正则引擎

自研回溯式正则(无第三方依赖),支持:字面量、`.`、字符类、`\d\w\s\b\B\xHH`、
`^$`、捕获组/`(?:)`、`|`、`* + ? {n,m}`(含懒惰模式)、反向引用 `\1..\9`、
`(?i)` `(?s)`。带 200 万步执行预算,超限记为 "regex timeout" 写进 trace,
**不会** ReDoS 卡死。与 PCRE 的差异:不支持 `\K`、环视、原子组等高级特性。

## HTTP 解析(容错)

- 请求行/头部:容忍裸 LF、obs-fold 折叠头、重复头
- Body:`Content-Length`(截断/超长都标记)、`Transfer-Encoding: chunked`
  (含 chunk 扩展、trailer;坏 chunk 标记 `REQBODY_ERROR` 并保留已解码部分)
- `application/x-www-form-urlencoded` → `ARGS_POST`
- `multipart/form-data` → 字段进 `ARGS_POST`、文件进 `FILES`,
  缺 boundary/缺结尾等置 `MULTIPART_STRICT_ERROR`
- 畸形输入只产生错误标记,引擎永远不崩(全量边界检查 + 输入 4MiB 上限)

## 页面功能

- 贴规则 + 贴原始请求 → 运行(Ctrl+Enter)
- 上一条/下一条单步,或点任意规则展开
- 每个变量:原始值 → 每个 transform 后的中间值 → 操作符 → 匹配结果/捕获组
- chain 子规则嵌套展示、TX 变化前后值、执行的动作、最终 TX 集合
- 请求解析面板:头部/ARGS/Cookies/Body 预览/解析异常

## 已知限制

- 只评估 phase 1/2(请求阶段);phase 3-5 的规则不执行
- 不支持 `SecRuleUpdate*`、`SecAction` 以外的指令多数忽略、`ipMatch`、
  `detectSQLi/detectXSS`(libinjection)、`inspectFile`、`geo` 等
- `pm` 是朴素子串匹配(大小写敏感,与 ModSecurity 一致,CRS 规则通常先 `t:lowercase`)
- JSON/XML body 不解析成 ARGS(只进 `REQUEST_BODY`)
