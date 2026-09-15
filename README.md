# GLM2api（抗风控增强版）

基于 [t479842598/glm2api-manage](https://github.com/t479842598/glm2api-manage)（AGPL-3.0）的中转服务，本仓库在其上做**抗风控主线**增强：

- **真实设备身份**：账号从登录导入时抓取真实 `chatglm-deid`，废除"每 8 个请求换设备"的机器签名行为；
- **人类节奏**：默认并发 6、单身份单飞、请求抖动、游客槽错峰上岗；
- **风控感知**：401/403/405/真 429 分类计数，连续 3 次风控事件冷却 600s 并换匿名设备身份（真实身份保留、重启自愈）；
- **配额与熔断**：每账号请求数 / 成功率 / 最后使用时间实时统计；连续失败自动熔断摘除，到期半开重试；
- **健康探测**：后台定期探活（缓存命中零成本），失效账号自动下线，管理面板可见（含"立即探活"）；
- **上游 SSRF 防线**：全部上游请求经统一传输 seam（`glm2api/core/transport.py`），阻断环回 / 链路本地（含云元数据）/ 私网目标（TUN 代理 fake-IP 段 198.18.0.0/15 例外，可用 `GLM_TRANSPORT_BLOCK_PRIVATE=false` 放宽）；
- **工具契约修复**：客户端声明的搜索工具不再被上游原生工具黑名单误伤（`web_search` 等撞名放行）；`tool_call_id` 不匹配从静默丢弃改为显式 400 报错。

详细设计与施工记录见 `docs/技术选型融合方案.md`（第 11/12 章），上游原始文档见 `relay/README.md`。

## 安全声明

> **本仓库未通过完整安全审计，请勿默认其安全。**
>
> 静态扫描（Mimosa，边界为 `static_only_no_runtime_execution`）存在 51 条 finding，其中：
> - **9 处 SSRF 提示**：本服务是中转代理，访问部署者自配的上游（默认 `chatglm.cn`）是设计本体；客户端协议入口不存在 URL 注入点。统一传输 seam 已加协议与目标 IP 校验（环回 / 链路本地无条件阻断、私网默认阻断）。
> - **1 处 XML 实体扩展**：已在 DSML 解析前加"检测即拒绝 + 1MB 上限"防护。
> - 其余为低危/误报（错误码常量字符串、第三方库 dist 文件、抖动用途的 `random`）。
>
> 凭据文件（`.env` / `token.txt` / `accounts.json` / `_fail_samples/`）已加入 `.gitignore`，**任何情况下不要把它们提交或推送到任何仓库**；若曾泄露请立即轮换其中全部 token。

## 快速开始

```bash
cd relay
cp .env.example .env   # 按需修改 ADMIN_KEY / 端口 / 并发
PYTHONPATH=src python -m glm2api
# 健康检查
curl http://127.0.0.1:8000/health
```

自检脚本（离线 43 断言）：`python tools/check_riskctrl.py`；在线全链路：`python tools/verify_base.py`。
