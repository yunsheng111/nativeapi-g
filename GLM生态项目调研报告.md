# GLM 生态项目调研报告（chatgpt2api / gptGrok2api ×2 / turb-gpt-free-register）

> 日期：2026-09-16
> 调研对象：`_research/` 下四个本地克隆（只读，四并行 subagent 深挖 + 主代理汇总）
> 目的：对比本项目（glm2api 底座 + glmrelay 扩展）现状，提炼可落地的设计与做法
> 关联文档：`docs/技术选型融合方案.md`（〇章进展快照、第十二章施工记录）、`docs/架构设计.md`

---

## 〇、一页结论

1. **四个项目与本项目中转定位同构**（网页逆向 → OpenAI 兼容 API），其架构共识反向验证了本项目已有设计：全文重放拍平上下文（三项目全部无 conversation 复用）、每账号稳定设备身份、分层退避、流式收尾兜底。
2. **最大可借鉴缺口**：①错误分类「权威 body 标记」判定（防误摘账号）；②HAR 对齐工作流（把指纹优势变成可回归测试，正是 P2.5 第二批既定的 `check_fingerprint.py`）；③SSE 首帧预取 + 硬超时看门狗；④账号级指纹钉扎；⑤429 冷却时长精确化。
3. **负面结论**：自动注册补号路线**不建议**——turb 项目一手信号：OpenAI 级风控下纯协议注册已被作者自己降级为「不建议」（默认改用指纹浏览器）；gptGrok2api 的 Go 重写版干脆整块砍掉注册。chatglm 注册需手机号，门槛更高。账号供给维持「游客槽 + 手动登录导入」。

---

## 一、四项目速览

| | chatgpt2api (basketikun) | gptGrok2api-auu (AuuCoder) | gptGrok2api-lichao | turb-gpt-free-register |
|---|---|---|---|---|
| 定位 | ChatGPT 网页逆向 → OpenAI/Anthropic API，重心图片/可编辑文件 | ChatGPT+Grok 双引擎统一网关（Python 原版，v1.2.1） | 前者的 **Go 重写版**（v1.2.4-go，~31k 行） | OpenAI 账号批量自动注册 + Codex OAuth 授权工厂 |
| 技术栈 | FastAPI + curl_cffi + uv，Next.js 面板 | FastAPI/granian + curl_cffi + SQLite/Redis，Vue3 | Go 1.23 纯 net/http + tls-client（仅 2 依赖）+ JSON 原子写 | Python + curl_cffi + selenium/playwright + Node vm + Flask/SQLite |
| 活跃度 | v1.8.0，2026-07-29 | v1.2.1 | 2026-09 重写发布 | 活跃（2FA 并发/查活优化） |
| 许可证 | MIT | 双 MIT（kunkun + Chenyme） | MIT | MIT |
| 账号供给 | 导入 + refresh_token 自动刷新 + 密码重登 | 注册中心（临时邮箱/Cloudflare 域名/Outlook 池）+ 恢复 | **砍掉注册**，假设外部供给 | 注册本身就是产品 |
| 反检测 | curl_cffi chrome110 + PoW + Turnstile 纯 Python VM | curl_cffi + 指纹一致性三件套 + FlareSolverr | tls-client + 头序保持 + Sentinel dx VM（纯 Go） | 指纹浏览器矩阵 + HAR 对齐 + GeoIP locale |
| 对本项目价值 | 账号池生命周期 + SSE 兜底组合拳 | 账号状态机/反馈分类（同类项目最完整） | lease 状态机 + 存储优化 + 精简架构取舍 | HAR 对齐方法论 + 指纹一致性框架 + 后台队列模板 |

---

## 二、逐项目要点

### 2.1 chatgpt2api（MIT，Python）

**核心功能**：`/v1/chat/completions`、`/v1/responses`、`/v1/messages`（Anthropic）、`/v1/images/*`、`/v1/models`（按账号套餐聚合上游目录）+ 管理面板。上游为 chatgpt.com `/backend-api`，SSE JSON Patch 方言解析。

**架构**：api/ 路由 → services/ 领域（account_service 号池、openai_backend_api 上游客户端 2763 行、protocol/ 协议转换、proxy_service）→ utils/（SSE 封装、PoW、Turnstile VM）。全同步线程模型（`run_in_threadpool`）。

**六维度亮点**：
- **账号池**（`services/account_service.py`）：
  - **token 轮换别名表**（:390-435）：刷新后 `aliases[old]=new`，所有查找走别名链，在途并发计数随 token 迁移——并发下安全换 key 的核心设计。
  - **暂缓摘除三条件**（:1255-1299）：新号 10 分钟宽限 + `invalid_count>1` 才计数 + 30s 确认窗，防上游抖动误杀。
  - **refresh_token keepalive**（:329-353）：3 天锚点周期 + 每轮限量 3 个 + 失败退避 6h，防 refresh_token 长期不用被回收。
  - access_token JWT 解码、剩余 ≤24h 判临期；巡检线程每 5 分钟（TLS/网络错不计账号失败）。
- **API 转换**：`sse_json_stream`（`utils/helper.py:194-226`）先发 `: stream-open` 注释帧、异常就地转协议错误帧、终帧无条件 `[DONE]`；**首 chunk 预取**（`log_service.py:250-269`）让上游错误变成真 HTTP 4xx/5xx；`UpstreamHTTPError` 携带 `status_code/body/retry_after` 结构化字段，字符串匹配只兜底 curl 层错误。
- **反检测**：curl_cffi impersonate + **账号级指纹**（fp dict：UA/device-id/session-id 每账号稳定，非每请求随机）；sentinel prepare/finalize 两步 + sha3-512 PoW + **Turnstile dx 纯 Python VM**（`utils/turnstile.py`）；WARP 栈是「稳定出口 + cf_clearance 刷新」而非 IP 池轮换。
- **节奏**：轮询首等 10s+抖动（注释：立即轮询触发瞬时 429）、指数退避封顶 16s、尊重 Retry-After；**SSE 硬超时看门狗**（`threading.Timer` 强关挂死流，曾观测单流挂 29.5 分钟）。
- **上下文**：全文重放 + `history_and_training_disabled:true`，无会话复用；上游整段回显历史时前缀剥离还原增量。
- **教训**：凭据明文含密码落盘、每状态变更全量重写 accounts.json 无原子写、import 期单例、硬编码版本常量易腐。

### 2.2 gptGrok2api-auu（Python 原版，双 MIT）

**核心功能**：Grok SSO 账号池（basic/super/heavy 三档池）+ console.x.ai + xAI CLI OAuth 三条上游；`/v1/*` 全家桶 + 管理台；注册中心（临时邮箱/iCloud Privacy Mail/Outlook 池）。host（chatgpt2api 线）与内嵌 Grok 运行时（app/）经 `EmbeddedGrokRuntime` 桥接。

**六维度亮点**：
- **账号状态机（全生态最完整）**（`app/control/account/` + `app/dataplane/account/`）：
  - **「只有权威 body 标记才判死」**（`app/dataplane/reverse/protocol/xai_usage.py:274-308`）：`blocked-user / invalid-credentials / token revoked` 等标记 + 400/401/403 才算凭据失效；TLS/网络/429/5xx 一律 `unknown`——单一事实源，误摘率降一个量级。
  - **冷却惰性推导**（`state_machine.py:101-111`）：`cooldown_until` 时间戳读取时动态判活，无需后台定时器。
  - **健康度乘法衰减 + 加法恢复**（`feedback.py:18-24`）：403 ×0.25 / 429 ×0.45 / 5xx ×0.75，成功 +0.12，夹 [0.05,1]；选号打分 `health*100 + quota*25 − inflight*20 − fails*4 − recent*15`，60s 内用过按剩余比例扣分（强制轮换覆盖长思考）。
  - **非权威 429 不清零配额**（`feedback.py:57-59`）——CHANGELOG 1.0.2 修的「通用 429 清零本地估算额度」事故。
  - **CAS 式换 SSO**（`grok_account_store.py:576-654`）：自动重登换 token 时校验旧值未被并发修改；**注册档案（含凭据）与无凭据运行镜像分离**；tempfile + 0600 + os.replace + .bak 安全写。
  - token 归一化 validator（零宽字符/`sso=` 前缀清洗，粘贴防呆）。
- **选号/轮询**（`app/dataplane/account/selector.py`）：quota/random 双策略进程级切换（零 if）；quota 策略打分选号，random 策略零探测；配额窗口**选择时内联重置**（reset_at 过期即重置，不依赖后台任务）。
- **反检测**：**指纹一致性三件套**——UA → client hints 派生、UA → curl_cffi impersonate 推导（反射支持列表降级）、动态随机 x-statsig-id（模拟前端真实错误文案）；ResettableSession（403 惰性重建 TLS 会话）；cf_clearance **build-then-swap**（刷新成功才原子替换，失败保留旧 bundle）。
- **退避四层**：传输层重建 → 流内 error 帧映射回 429 → 换号（excluded 列表 + retry.on_codes）→ 选号降级（AUTO→FAST）+ on-demand 刷新兜底（300s 最小间隔防击穿）。
- **API 转换**：流式 **ToolSieve**（text delta 前缀状态机，见 `<tool_calls` 即缓冲，闭合即解析）；工具解析 4 级 fallback + `saw_tool_syntax` 标志；reasoning_content 分流（正文开始后的「迟到 thinking」只进 buffer）；inline citation 还原成带绝对字符位置的 `url_citation` annotations。
- **上下文**：Grok 侧完全无状态（每请求 `conversations/new` + `temporary:true`）；**自产内容回流清洗**（注入隐藏标记行 `[grok2api-sources]: #`，多轮时剥除）。
- **教训**：SQLite 多线程 WAL 死锁（引入进程级连接串行锁 `utils/sqlite_runtime.py`）、双世界架构胶水 610 行、per-worker 状态不一致。

### 2.3 gptGrok2api-lichao（Go 重写版）

**核心功能**：同 auu 版功能面（GPT+Grok 双池、图片/视频/可编辑文件）+ **go-image-gateway**（Redis 队列削峰微服务）。Vue3 控制台，约 70 条管理路由。

**架构**：Go 1.23 纯 `net/http.ServeMux`（无框架），主模块仅 tls-client/fhttp 两个依赖；`internal/accounts/pool.go` 438 行零 I/O lease 模块；JSON 原子写（tmp+fsync+rename）。

**六维度亮点**：
- **账号 lease 模型**（`pool.go`）：`Reserve/Release/Feedback` 三接口 + least-inflight 选号 + 旋转起点公平性 + `close(wake)` 广播；`Release` 用 sync.Once 幂等；401 → 10 分钟固定冷却 + `onInvalid` 回调，**auto_remove 保护条件 = 有无 refresh_token**（可救账号不删）；429 从错误文本正则解析冷却时长（`"3 hours"/"30 分钟"`）。
- **存储写放大治理**：写时复制快照 + revision + `time.AfterFunc(1s)` 合并刷盘（`store/json.go`）——Python 版「每次反馈全量重写」的解法。
- **SSE 骨架**（`server.go:989-1096`）：bufio.Scanner 放大 buffer → data: 剥离 → `[DONE]` → 逐帧 Flush；**`emitted` 标志控制「首帧前才允许换号重试」**（首帧后重试会导致重复输出）。
- **代理组调度器**（`proxy/transport.go` 1082 行零依赖）：节点 limit/inFlight/EWMA 延迟/冷却/逐出；稳定节点优先 + 每 20 次放一个 canary 探测；**「不把上游正常慢计入代理评分」**的口径分离；per-proxy RoundTripper 缓存 = 每出口一条连接池。
- **指纹**：tls-client Chrome_110 + **`fhttp.HeaderOrderKey` 保持头序**；账号 fp 字段覆盖。
- **图片结果过滤五规则**（参考图污染修复，一周 6 个补丁的结晶）：只认 tool/assistant 记录、按 create_time 排序、输入文件 ID 集排除、**sha256 字节级比对**、时序假设——对任何「上传参考图 → 生成图」上游通用。
- **取舍信号**：重写时**砍掉注册/打码/iCloud/Checkout**，从「养号+API 一体机」收窄成「纯 API 网关」；伪流式（Anthropic/工具聚合后重放）是重写代价。

### 2.4 turb-gpt-free-register（MIT，注册工厂）

**核心功能**：OpenAI 账号批量注册 + 2FA(TOTP) 自动开启 + 查活 + 查套餐/试用资格 + Codex OAuth 授权 + 邮箱换绑 + 对接下游 API 网关（CPA/sub2api）。5 种注册驱动（protocol 纯 HTTP / roxy / cloak 指纹浏览器 / browser_use / skyvern 云浏览器）。

**关键发现（对本项目）**：
- **HAR 对齐工作流（最可复用资产）**：抓完整会话 HAR（`Default-all-domains-*.json`，236 条请求）→ `tools/analyze_har_protocol.py` 抽取 → `docs/protocol_fingerprint_har_analysis.md` 逐条分析（链路顺序/指纹字段表/已对齐项）→ 每个存疑参数留 `.env` 开关（如 `SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE=False`，按 HAR 证据默认不发）。
- **单一画像数据源 + 一致性校验**（`config/browser.py:1-11,308-380`）：curl_cffi 头、Sentinel p 数组、Node VM 参数同源于一个 profile dict；启动时 `validate_browser_profile()` 校验 UA/platform/sec-ch-ua 自洽——「TLS=146 而 UA=149 的跨版本拼接」是封禁诱因。
- **会话级熔断器**（`core/session.py:656-689`）：403 → 冷却 900s、429 → Retry-After（上限 3600s）；恢复时**只清熔断、保留 Cookie（含新下发的 `__cf_bm`）**同会话退避重试。
- **任务级指纹钉扎**（`core/account_liveness.py:66-100`）：每任务一次性 seed（uuid5 派生 device/session/画像），同任务重试复用完整身份、任务间隔离；落库剥离会话级标识只留环境画像。
- **GeoIP → locale 跟随**（`core/session.py:329-368`）：出口 IP 地理决定 Accept-Language/时区/Cookie locale 三处一致。
- **后台服务队列模板**（`core/plan_check_service.py` / `twofa_service.py`）：`ThreadPoolExecutor + BoundedSemaphore 队列上限 + 全局限速（单调时钟排片 + jitter）+ DB claim/running/result + recover_interrupted_*`（崩溃后悬挂任务恢复）。
- **查活 cheap-first**：本地 JWT 解码 exp 先行，过期才走网络；AT 预热登录态 → 稳定链路。
- **负面一手信号**：protocol 驱动自评「容易封号，不建议」（`config/roxybrowser.py:12`），默认 roxy 指纹浏览器——**OpenAI 级风控下纯协议注册已接近不可行**。
- **红线**：`core/flow_trigger.py` 把 access_token POST 给硬编码第三方 IP 且 `verify=False`；邮箱素材经第三方代收服务——绝不可模仿。

---

## 三、与本项目逐维度对比

| 维度 | 本项目现状 | 生态最佳实践 | 差距判定 |
|---|---|---|---|
| 账号池存储 | token.txt + accounts.json（原子写 ✅、mask_token ✅、指纹去重） | 别名表 / CAS 替换 / 无凭据镜像 / 0600 | 刷新路径加固项缺失（B2） |
| 状态机/摘除 | 风控冷却 600s + 通用熔断 600s 分源、半开重试、健康探测摘除 | 权威标记判定 / 暂缓摘除三条件 / 惰性恢复 | **权威标记判定缺失（A1）**；固定时长（A5） |
| 配额 | AccountState 统计（请求数/成功率） | 真实额度查询 + 配额来源分级 + 内联窗口重置 | chatglm 无公开额度接口，维持统计即可 |
| 轮询/选号 | 顺序 failover + 单身份单飞（inflight=1） | lease + least-inflight / 健康度打分 / 双策略 | 池规模小，暂不追平（B6 观察） |
| API 转换 | translator 拍平 + DSML 抢救层 + 双协议实测 | Sieve / 多级 fallback / 伪流式反例 | **基本对齐**；无首帧预取（A3） |
| SSE 稳定性 | keepalive 30s 语义 + 流尾兜底 | 首帧预取 / 硬超时看门狗 / `: stream-open` | **看门狗缺失（A4）** |
| 反检测 | CDP fetch 真指纹 + 禁止头剔除 + 全端点统一 | HAR 对齐 / 指纹一致性三件套 / 账号级指纹钉扎 / ResettableSession | **check_fingerprint.py 未做（A2）**；账号级指纹（B1） |
| 上下文 | 全文拍平 + 体积治理 + 信任壳 | 三项目同为无状态全文重放 | **对齐（生态共识验证了本设计）** |
| 自动注册 | 无（游客槽 + 手动导入） | turb：指纹浏览器路线；lichao：砍掉注册 | **维持现状（负面结论，见 C5）** |
| 并发/节奏 | 并发 6 + 单飞 + 抖动 + 错峰（D3） | 单号 inflight 上限 + 打分扣分 + 全局限速 | 对齐 |
| 可观测 | 面板 runtime 列 + 探活按钮 + 失败样本落盘 | 分阶段监控 / transport 记录 / 脱敏出口标签 | transport 记录待做（B5，canary 前置） |

---

## 四、可落地改进建议（按优先级）

### 高优先级（并入 P2.5 第二批或紧随其后，全部小成本）

| # | 建议 | 依据 | 落点与规模 |
|---|---|---|---|
| A1 | **错误分类收口：权威 body 标记才判死账号**。401/403/风控 429 命中冷却前，先检查响应体是否含上游权威标记（如明确的账号封禁/凭据失效文案）；未命中只记 `total_failures`（走通用熔断的连续计数），不进风控冷却、不换 device_id。401 网关抖动不再误伤身份 | auu `xai_usage.py:274-308`；本项目 `glm_auth.py:386-405` 现按状态码+10061 豁免分类 | `glm_auth.py` `classify_risk_event` 增加 body 标记判定；+30 行；check_riskctrl 增断言 |
| A2 | **HAR 对齐工作流落地 `check_fingerprint.py`**（10.8.6 既定项）：CDP Network 域抓真实前端 stream 请求 vs bridge fetch 请求，断言头集合/头序无 tell-tale 差异；存疑参数（如 Referer 形态）留 `.env` 开关。借鉴 turb 的「HAR → 分析 md → 参数开关」三件套 | turb 全仓方法论；本项目 10.8.6 | 新脚本 `tools/check_fingerprint.py` + 抓包分析文档；P2.5 第二批既定 |
| A3 | **SSE 首帧预取**：`server.py` 三处 `_stream_*`（如 `:438-451`）在发 200/SSE 头之前先消费 stream_iter 首帧，上游 4xx/5xx 映射为真 HTTP 状态码，而非 200 + 流内错误 | chatgpt2api `log_service.py:250-269`；实测本项目先发头后取帧 | server.py 底座三处各 ~10 行；verify_base 回归 |
| A4 | **SSE 硬超时看门狗**：整个流的最长时长上限（如 `GLM_STREAM_MAX_SECONDS`，默认 600s），`threading.Timer` 到点关闭 response 强制解除阻塞读；触发时记日志留样本 | chatgpt2api（单流挂 29.5 分钟事故） | `glm_client.py` `_iter_sse_events` 外层；+20 行 |
| A5 | **429 冷却时长精确化**：优先读 `Retry-After` 头；其次正则解析错误文本时长（「请稍后再试」类）；都没有才用固定 600s | lichao `retryAfterDuration`；auu `retry_after_ms` 优先 | `glm_auth.py` 冷却赋值处；+15 行 |

### 中优先级（P2.5 第二批设计吸收 / P3 之前）

| # | 建议 | 依据 | 说明 |
|---|---|---|---|
| B1 | **账号级指纹钉扎**：每账号稳定全套指纹 profile（UA / Accept-Language / 时区 + 已有 deid），importer 导入时按 seed 派生落 accounts.json；CDP 路径与 BrowserContext 1:1 绑定同步建立，urllib 路径按账号选头 profile | turb fingerprint_seed；chatgpt2api fp dict；auu client-hints 派生 | 消除「同账号每请求指纹漂移」信号；与 D2 BrowserContext 池同批实施 |
| B2 | **token 别名表 + CAS 替换**：refresh 成功后旧 token 指纹 → 新 token 别名链；更新 accounts.json 校验旧值未被并发修改 | chatgpt2api `_apply_refreshed_tokens`；auu `replace_sso_after_recovery` | 防在途请求引用悬空；health.py 刷新路径激活时必做 |
| B3 | **健康探测 keepalive 批处理**：每轮限量 N（如 3）个临期账号主动续命，失败退避 6h，防长期闲置账号被上游回收 | chatgpt2api keepalive 调度 | health.py 加批处理；chatglm refresh_token 回收策略未知，作为保险 |
| B4 | **暂缓摘除三条件**：新导入账号宽限期（如 10min）+ 失败计数 >1 才计 + 时间窗内不重复计数，防上游抖动误杀新号 | chatgpt2api `:1255-1299` | 叠加在现有熔断之上，+20 行 |
| B5 | **每请求 transport 记录 + 脱敏出口标签**：日志/统计记录 `transport=urllib|cdp` 与账号指纹掩码，作为 canary A/B 的数据前置 | lichao monitor；本项目 10.8.4/11.4 既定 | canary 判据需要这份数据 |
| B6 | （观察）**least-inflight 选号 / 健康度加权打分**：池规模 >20 或导入账号增多后再引入；当前 6 游客槽 + 少量导入账号，均匀轮换 + 错峰已够 | lichao pool.go；auu selector | 现在引入是过度设计 |

### 低优先级 / 触发式

| # | 建议 | 触发条件 |
|---|---|---|
| C1 | 代理池 + per-账号出口（lichao 代理组调度器为蓝图；auu ResettableSession 403 重建 TLS 会话） | 风控开始打 IP / 部署环境需要多出口 |
| C2 | canonical-body 缓存 + inflight singleflight（TTL 60s） | 多客户端同问场景真实出现 |
| C3 | 写时复制快照 + 延迟刷盘（store.py 现为每变更全量原子写） | 账号池规模上到数百 |
| C4 | 工具解析 `saw_tool_syntax` 标志（区分「解析失败但看到语法」与纯正文） | probe_tools 失败样本持续累积时 |
| C5 | **自动注册补号：不建议做**。turb 一手信号：纯协议注册在 OpenAI 风控下已被作者弃用（默认指纹浏览器）；lichao Go 版整块砍掉注册。chatglm 注册需手机号，门槛更高。账号供给维持「游客槽 + 手动登录导入」；若未来真要做，turb 的后台队列模板（claim/running/result + recover_interrupted）与邮箱多源兜底是参考，但须先做成本（代理 + 指纹环境 + 邮箱/手机）与损耗率测算 | — |

### 明确不学清单（生态教训）

- 凭据明文 + 第三方代收/上传（turb `flow_trigger`、邮箱代收）——本项目「凭据零入库」红线不变。
- 每状态变更全量重写无原子写（chatgpt2api accounts.json）。
- import 期单例 + 巨型文件（chatgpt2api 2763 行客户端、lichao 2376 行 server.go、turb 148KB db.py）。
- `.orig` 文件复制式发布/回滚（lichao）——git 基线 + 单 commit 单回滚已优于。
- 伪流式（lichao Anthropic/工具聚合后重放）——本项目双协议真实流式已优于。

---

## 五、对既有设计的验证性结论

1. **「全文拍平、无会话复用」是生态共识**：chatgpt2api（`history_and_training_disabled:true`）、Grok 两侧（`temporary:true`）、Go 重写版刻意放弃会话复用，均与本项目 translator 拍平同构。上游会话状态的复杂性不值得引入——本项目无需改变。
2. **每账号稳定设备身份是反检测第一课**：三个转换器全部从「每请求随机」演进到「每账号稳定 fp/deid」，与本项目 D1 决策（真实 deid 接线、废除 8 次轮换）方向一致，且「全套指纹钉扎」（B1）是其自然延伸。
3. **「少伪装 = 少被识别」再次被验证**：curl_cffi/tls-client 派别是「用真指纹库模拟」；本项目 CDP fetch 路线（真实浏览器网络栈）是同目标的更强实现——但必须补上 A2 的可回归验证，否则指纹优势只是信仰。
4. **账号池的核心竞争力在「不误摘」而非「敢摘除」**：auu 的权威标记判定、chatgpt2api 的暂缓摘除、lichao 的 auto_remove 保护条件，三家的演进方向一致——先保守摘除、权威确认、可救账号留后路。本项目 P1-b 熔断框架已就位，缺的正是 A1/B4 这层语义。

---

## 附：调研方法

四个并行只读 Explore subagent（每仓库一个，very thorough，引用一律 `相对路径:行号`），主代理汇总 + 与本项目代码（`relay/src/`）交叉核对（`glm_auth.py:386-438` 风控分类、`server.py:438-451` 流式路径、`health.py` 探活、`store.py` 原子写）。四份原始调研底稿见会话记录；本文件为提炼汇总。
