# 两个 GLM 开源项目研究报告与对比

> 研究对象：
> - `t479842598/glm2api-manage`（下称 **glm2api**）
> - `wuyiliu391-hub/glm-web-code`（下称 **glm-web-code**）
>
> 研究方法：完整克隆两个仓库，逐文件阅读源码 + 官方文档，并核对 GitHub API 元数据。
> 研究时间：2026-09-15

---

## 一、结论速览：它们解决的是两个完全不同的问题

| 维度 | glm2api-manage | glm-web-code |
|------|----------------|--------------|
| 一句话定位 | 把 chatglm.cn 网页接口**转成标准 API**给别人用 | 把 chatglm.cn 网页版**变成能干活的编程 Agent** |
| 交付形态 | 无头 HTTP 服务（可部署到云） | 本地桌面 GUI 应用（Windows WebView2） |
| 核心产物 | OpenAI / Anthropic 兼容端点 | 文件系统 / Shell / MCP 操作结果 |
| 技术栈 | Python ≥3.12，**纯标准库零依赖** | Go ≥1.26 + Wails v3 + Vite 5 + goja |
| 版本 | v0.3.0 | 0.4.0 |
| 许可证 | AGPL-3.0 | GPL-3.0 |
| Stars / Forks | 14 / 8 | 0 / 0 |
| 首次提交 | 2026-06-26 | 2026-09-14（开源快照） |
| 最后推送 | 2026-07-28 | 2026-09-14 |
| 代码规模 | ~14 个 Python 模块，约 27 万字节源码 | 主包 24 个 Go 文件 + 12 个 internal 包 + 前端 |
| 测试数量 | 59 个（pytest） | ~121 个（go test） |

**一句话总结差异**：glm2api 卖的是「**接口**」，glm-web-code 卖的是「**生产力**」。

---

## 二、项目一：glm2api-manage 详解

### 2.1 它是什么

一个**零外部依赖**的本地代理服务，把 `chatglm.cn` 的网页接口转换成 OpenAI / Anthropic 兼容接口。任何兼容 OpenAI API 的客户端（OpenAI SDK、Cherry Studio、Open WebUI、LobeChat）都能直接接上，用上 GLM 的免费额度。

### 2.2 提供的接口

| 端点 | 说明 |
|------|------|
| `POST /v1/chat/completions` | OpenAI 聊天（流式 + 非流式） |
| `POST /v1/responses` | OpenAI Responses API |
| `POST /v1/messages` | Anthropic Messages API 兼容 |
| `POST /v1/images/generations` | 图片生成 |
| `GET /v1/models` | 模型列表（返回 78 个可用模型） |
| `GET /health` | 健康检查 |
| `GET /admin` | 内置管理面板 |

### 2.3 核心功能点

**账号与风控对抗（这是它最花心思的地方）**

- **游客模式**：不填任何 token 自动走游客模式，开箱即用
- **多账号负载均衡**：`token.txt` 每行一个 refresh_token，自动轮换，某个账号失败自动切换下一个
- **device_id 池 + 主动轮换**：每个账号维护独立 device_id，累计 8 次请求后自动轮换，避免触发智谱游客频控（"您已多次体验过对话"）；chat / image / delete / upload 全部统一使用账号级 device_id
- **并发队列**：`GLM_MAX_CONCURRENCY` 默认 3 个上游槽位，`GLM_BUSY_RETRY_INTERVAL` 处理"请等待其他对话生成完毕"
- **上游忙碌重试 30 次**、队列等待超时 600 秒

**流式稳定性（其更新日志里占比最大的部分）**

- **SSE keepalive 心跳**：推理模型（GLM 5.2）思考阶段长达数分钟不产文本，前端会 idle-timeout。方案从「穿透 socket 设超时」一路演进到「后台线程读上游 + 主线程 `queue.get(timeout=25)` 发 `: keepalive`」，25 秒间隔确保低于各前端 45 秒 IDLE 限制
- **流尾兜底**：无论上游是否正常结束，都补一个合法的 `finish_reason="stop"` + `data: [DONE]`
- **服务端工具调用即时流式发送**：GLM 原生 `type:"tool_calls"` 内容项改为流式过程中即时以 delta 发送，修复"推理数分钟无输出 → 客户端 Broken pipe → 工具调用全丢"
- **`_server_side_tool_calls_emitted` 游标**：避免 finalize 重复发送
- **流中断三重误判修复**：event 级别 error 才致命，part 级别 `status:"error"` 只是内部生命周期

**协议适配**

- `core/openai_compat.py`：标准响应 ID（`chatcmpl-` / `resp_` / `msg_` / `call_` / `req_`）、`system_fingerprint` 动态指纹、OpenAI 格式 error envelope
- `core/tokenizer.py`：字符类启发式 token 计数（CJK ~1 token/char，英文 ~4 chars/token），usage 从固定 1 改为真实估算
- `utils/tool_parser.py` + `tool_protocol.py`：DSML/XML 工具调用流式解析，含解析失败诊断日志
- 三个独立适配器：`translator.py`（OpenAI）、`anthropic_adapter.py`、`responses_adapter.py`

**管理面板（Vue 3 + Naive UI，静态文件本地内置，无 CDN 依赖）**

| 页面 | 功能 |
|------|------|
| 概览 | 账号数、模型数、并发上限、请求成功率 |
| 配置 | 前 5 条关键运行时配置 |
| Token | 脱敏浏览各账号 token，分页（每页 10 条） |
| 日志 | 实时日志流，按级别着色，支持过滤和自动刷新 |
| 请求记录 | 最近 500 条（方法 / 路径 / 模型 / 状态码 / 耗时） |
| API Key | 增删改查 + 启用禁用切换 |
| 对话测试 | 选模型、Prompt、System Prompt，看返回结果 |

**API Key 工作机制**：默认无 Key 时全接口免认证（向后兼容）；一旦添加至少一个启用的 Key，接口就需要认证；禁/删完恢复免认证。Key 自动持久化到 `.env` 的 `GLM2API_API_KEYS`。

**部署广度（6 种方式）**

Vercel 一键部署（含 `api/index.py` WSGI 适配器） / Docker / Railway·Render·Zeabur / Windows NSSM 服务 / Linux systemd / VPS 一键脚本（rsync + systemd + Nginx + certbot）

**工程规范**

- GitHub Actions CI/CD：Python 3.12/3.13 矩阵，push/PR 自动跑 pytest + import 验证
- 运维脚本：`scripts/start.sh`（后台 + PID + health check）、`stop.sh`（SIGTERM→SIGKILL）、`status.sh`
- 59 个测试全部通过（在 Python 3.12.3 隔离环境验证）
- `progress.md` 记录每次变更的验证证据与**回滚点**（git revert 哪个 commit）

### 2.4 已知风险与短板

- 依赖逆向 `chatglm.cn` 网页接口，**上游一改就可能失效**——其更新日志中大量 bugfix 都是这个原因
- Vercel Hobby 计划函数超时 10 秒，长回答会被截断
- 硬编码了 `GLM_ASSISTANT_ID` 等上游常量
- 迭代已停滞于 2026-07-28，约 1.5 个月无提交
- 本质上是绕过官方收费/限制的行为，可能违反服务条款

---

## 三、项目二：glm-web-code 详解

### 3.1 它是什么

**零 Token 成本的 AI Agent 桌面端**。把智谱清言网页版嵌进本地 WebView，用系统提示词引导 AI 输出 `glm-web-code` 代码块，在本地 goja 沙箱执行后回灌结果，形成「思考 → 行动 → 观察」的完整工具循环。**不调 API、不要 Key**。

仓库描述写着 `glm2api cdp tools code`——说明它与 glm2api 是同源思路的另一条分支。

### 3.2 架构：双窗口 + 三通道

```
main 窗口   → https://chatglm.cn/      （AI 站，CDP 9222）
panel 窗口  → /panel.html (embed.FS)   （无边框置顶控制面板，880×560 三栏）
chat 工作台 → /chat.html               （可选工作台 UI）
```

| 通道 | 方向 | 机制 |
|------|------|------|
| Panel → Go | 面板 | Wails 绑定 `App.X` |
| 主窗口 → Go | AI 页 | **CDP 邮箱桥**（主）：用 DOM `#glmweb-mbox` 的 `textContent` 当传输层 |
| 主窗口 → Go | AI 页 | HTTP 桥 `127.0.0.1:34116`（备，严格 CSP 下不可用） |
| Go → 主窗口 | — | `WindowExecJS` + CDP `Runtime.evaluate` |

**CDP 邮箱桥的设计巧思**：AI 站有严格 CSP，`connect-src` 不含 127.0.0.1，页面内任何网络请求都会被拦。所以用 DOM 文本节点当传输层——**不发一个请求**就完成了双向通信。

**执行链路**：

```
AI 回复 ```glm-web-code 代码块
  → CDP 轮询抓取（glmwebScrapeJS，1.5s 间隔）
  → tools.GlobalRunner.Execute（goja 沙箱）
  → fenceToolPayload → pushToolResultToGLM 回灌输入框
```

### 3.3 核心功能点

**20 个内置工具**（`internal/tools/`，注册于 `registry.go`）

| 类别 | 工具 |
|------|------|
| 文件读取 | `read`、`read_lines`、`file_read` |
| 文件写入 | `write`、`file_write` |
| 文件编辑 | `edit`、`file_edit` |
| 搜索 | `glob`、`grep` |
| 命令执行 | `bash`、`pwsh` |
| 任务管理 | `todowrite` |
| 危险操作 | `file_delete` |
| 网络 | `webfetch`、`open_browser_window` |
| 数据库 | `mysql` |
| 扩展 | `inject_js` |
| MCP | `mcp_call`、`mcp_list_servers`、`mcp_get_tools` |

**安全体系（多层防护）**

- **工具白名单**：`Registry.SetAllowedTools` 是**物理移除**而非靠 AI 自觉；面板提供「全开 / 只读 / 读写码 / 自定义」四档
- **goja 沙箱加固**：`sandboxHardenJS` 禁用 `eval` / `Function` / `AsyncFunction` / `GeneratorFunction` 的字符串编译逃逸（对齐 Electron `codeGeneration:{strings:false}`），有单测覆盖
- **安全阀**：命令 30s、沙箱 60s、1MB 输出上限、`dangerous_cmds.go` 危险命令正则确认
- **注入幂等**：新脚本必须带 `__glmweb*` 守卫

**工具循环的工程细节（这是真正难的部分）**

- **长文本分片协议（硬性）**：单次 write/edit 内容超 15000 字符必须分片，每块首行 `// [Part i/N] seq=<seq>`，最后一块加 `// [END Part N/N]`；缺片时系统返回 `part-batch-incomplete`，25 秒内续推 ≤2 次
- **空块防御 + 稳定门控**：避免抓到残缺代码块就执行
- **分片 Part 回灌**：长输出（>18k）自动切为 `[TOOL RESULT Part i/N]` 多段回灌，全文落地 `.openclaw-attachments/run-*.md`
- **自动静默初始化**：目录恢复 → 提示词缓存 → 按 cid 去重推送

**UI 层**

- **DreamSkin 主题引擎**：劫持 `:root` CSS 变量打皮，**零业务节点改动**；预设 `dark-ink` / `official-light`，配 `safe-css-policy.json`
- **折叠卡片（fold）**：流式锁高 36px + 800ms 稳定后折叠（实测无 2↔36px 抽搐）
- **write/edit Diff 视图**：`+N -M` 统计 + 行级绿红高亮
- 面板可管理 Profile（多账号/多窗口）、MCP Server、主题、工具策略、通道状态

**扩展能力**

- **MCP 支持**：`mark3labs/mcp-go` v0.32.0，配置格式兼容 Claude Desktop
- **Skills**：标准 `SKILL.md` 技能包加载，启用后全局注入提示词
- **多 Provider 框架**：内置收敛为单一智谱清言（id=`zhipu`，别名 `chatglm`），但保留 `custom-providers.json` 自定义扩展；`internal/prompt/templates/` 里还留着 chatgpt / claude / deepseek 的提示词模板
- **自动更新**：GitHub Releases 检查（开源版默认关闭）

### 3.4 文档质量：这个项目的最大亮点

`docs/PROJECT.md` 被明确声明为**唯一权威文档**，旧 README / ARCHITECTURE / HANDOFF / CHANGELOG / CONTRIBUTING 全部删除。里面包含：

- 文件地图（每个文件的行数 + 职责）
- 分阶段升级蓝图（P0/P1/P2/P3 及落地状态）
- 测试覆盖表 + **无测试模块清单**
- **技术债按优先级排列**
- **「改代码前必读」的关键契约**（如：改 CDP 邮箱协议必须同步 JS 侧和 Go 侧，否则静默卡死 90s；`WindowExecJS` 异步无返回值，日志「done」≠ 执行成功）

这种坦诚程度在个人开源项目里相当少见。

### 3.5 已知风险与短板

作者自己列出的技术债：

1. **双通道无主备仲裁** — bridge 与 cdpbridge 同时映射同一组方法
2. **MCP 闭环未验证** — AI 主动 `mcpCall`、http 远程 server 未真机跑通；`MCPStore` 与新 client 双写冗余
3. **注入去重双命名空间** — 前端局部守卫 vs `window.__glmweb*` 不同步（历史 P0）
4. **版本三处对齐** — `constants.go` / `build/config.yml` / `frontend/package.json` 需同步改
5. **bridge / cdpbridge / injector / cdp 零测试**——恰好是通信最关键的部分

其他风险：

- 只有 Windows WebView2 路径明确可用，跨平台未经充分验证
- 依赖 chatglm.cn 前端 DOM 结构，上游改版即失效
- Wails v3 还在 beta（v3.0.0-beta.20），升级有破坏性风险
- 刚开源一天、0 star，未经社区实战检验
- 构建门槛高（要装 Go 1.26+、Wails v3 CLI、Node 18+）

---

## 四、逐维度对比

### 4.1 接入方式：逆向 HTTP vs 真实浏览器

- **glm2api** 直接用 `urllib` 调 `chatglm.cn` 的**后端接口**，自己管理 refresh_token / guest token / device_id。轻、快、可水平扩展，但要持续对抗风控。
- **glm-web-code** 用 CDP 控制**真实浏览器**加载网页。天然带登录态和真实前端，无需对抗风控，但只能在有 GUI 的环境跑，且受 DOM 改版影响。

一个有趣的推论：glm2api 更新日志里 80% 的 bug（流式中断、keepalive 失效、工具调用丢失）在 glm-web-code 里**根本不存在**——因为后者直接读渲染好的 DOM，不解析 SSE。反过来，glm-web-code 要处理的分片、折叠、注入幂等，glm2api 也全都不需要。**技术选型直接决定了 bug 清单。**

### 4.2 消费者与复用性

- **glm2api**：一对多。服务跑起来后，Cherry Studio、Open WebUI、LobeChat、任何 OpenAI SDK 都能接，还能多账号共享额度。
- **glm-web-code**：一对一。它就是"我自己用的那个 AI 编程助手"，一个窗口一个会话。

### 4.3 能力边界

| 能力 | glm2api | glm-web-code |
|------|---------|--------------|
| 文本对话 | ✅ | ✅ |
| 图片生成 | ✅ | ❌（走网页原始能力） |
| 工具调用协议 | ✅ 仅协议适配，不执行 | ✅ 真实执行 |
| 读写本地文件 | ❌ | ✅ |
| 执行 Shell 命令 | ❌ | ✅ bash + pwsh |
| 浏览器操作 | ❌ | ✅ |
| MCP | ❌ | ✅ |
| Skills 技能包 | ❌ | ✅ |
| 多账号额度池 | ✅ | ❌ |
| 云部署 | ✅ 6 种方式 | ❌ 纯本地 |

### 4.4 工程成熟度

| 维度 | glm2api | glm-web-code |
|------|---------|--------------|
| CI/CD | ✅ GitHub Actions | ✅ 3 个 workflow（build/coverage/release） |
| 测试 | 59 个，覆盖核心协议 | 121 个，但**通信层零测试** |
| 文档 | README 详尽（23KB） | PROJECT.md 极致详尽（含技术债） |
| 部署难度 | 低（pip install -e .） | 高（Go + Wails v3 + Node） |
| 社区验证 | 14 star / 8 fork | 0 star，刚开源 |
| 迭代状态 | 停滞 1.5 个月 | 活跃（4 小时内推送） |

### 4.5 两者其实是互补的

`glm-web-code` 的仓库描述 `glm2api cdp tools code` 暗示了两者是同一思路的两条分支。理想的组合方式：

- **glm2api 做底座**：提供稳定的、可多客户端复用的 API 出口
- **glm-web-code 做终端**：提供本地文件/命令级的 Agent 执行力

如果想合二为一，可行方向是：让 glm-web-code 的 `internal/providers/` 增加一个「走 glm2api 端点」的 provider——这样 Agent 循环里那些不需要真实网页上下文的调用可以走轻量 HTTP，需要网页能力（如联网搜索、图片）时再回退到 CDP。

---

## 五、选型建议

| 你的需求 | 推荐 |
|----------|------|
| 想在 Cherry Studio / LobeChat 里白嫖 GLM | **glm2api** |
| 想给自己搭个稳定的 API 中转，能多账号轮换 | **glm2api** |
| 想部署到 Vercel / 服务器给团队用 | **glm2api** |
| 想要能真的读写我项目文件的 AI 编程助手 | **glm-web-code** |
| 想用 GLM 免费额度替代 Claude Code / Cursor | **glm-web-code** |
| 想学 CDP 注入 / Agent 工具循环怎么设计 | **glm-web-code**（文档价值极高） |
| 想学怎么逆向网页接口 + 协议适配 | **glm2api** |

**两者共同的风险**：都建立在逆向 / 改造 `chatglm.cn` 之上，属于灰产边缘地带。上游一次前端改版或一次风控升级，都可能让项目直接失效。它们的更新日志里那一条条 bugfix，本质上都是在追着上游跑。用作个人学习和技术研究没问题，但不建议承载任何重要的生产业务。

---

## 附：仓库元数据核对

```
glm2api-manage
  id            1280876725
  language      Python
  created_at    2026-06-26T02:51:23Z
  pushed_at     2026-07-28T15:06:14Z
  stars/forks   14 / 8
  license       GPL-3.0 (spdx)  /  仓库内 LICENSE 为 AGPL-3.0
  size          11534 KB

glm-web-code
  id            1369858507
  language      Go
  created_at    2026-09-14T12:07:25Z
  pushed_at     2026-09-14T12:23:22Z
  stars/forks   0 / 0
  license       NOASSERTION  /  仓库内 LICENSE 为 GPL-3.0
  size          527 KB
```
