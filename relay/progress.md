## 2026-07-28 - Task: 修复管理面板反向代理登录后 401

### What was done
- 将管理会话认证的请求头读取改为大小写不敏感，恢复反向代理下 Cookie 会话认证。
- 新增会话请求头和 Cookie 名称大小写混用的回归测试。
- 记录管理面板认证行为与生产验证入口，并更新项目更新日志。

### Testing
- `python -m pytest tests/ -v`（待本轮修改完成后执行）
- 生产验证将覆盖 HTTPS 登录、`x-admin-session` 和 Cookie 会话访问 `/admin/api/overview`。

### Notes
- `src/glm2api/admin.py`：规范化管理认证请求头名称后再读取会话头和 Cookie。
- `tests/test_admin.py`：覆盖会话头与 Cookie 的大小写不敏感认证。
- `README.md`：追加管理面板 401 修复更新日志。
- `docs/admin-authentication.md`：说明管理会话认证方式和生产验证标准。
- `progress.md`：记录本轮变更、验证和回滚点。
- 回滚方式：部署前使用当前 `main` 的 `2d606ab`；部署后执行 `git revert <本轮提交>` 并重启 `glm2api.service`。

## 2026-07-28 - Task: 验证管理面板会话认证修复

### What was done
- 在 VPS 的 Python 3.12 临时虚拟环境中执行新增回归测试和完整测试套件。

### Testing
- `PYTHONPATH=/opt/glm2api/src /tmp/glm2api-auth-test/bin/python -m pytest /opt/glm2api/tests/test_admin.py -v`：`1 passed`。
- `PYTHONPATH=/opt/glm2api/src /tmp/glm2api-auth-test/bin/python -m pytest /opt/glm2api/tests -v`：`59 passed`。
- 本机仅有不满足项目要求的 Python 3.9 且未安装 pytest，因此未作为验证环境；测试已在生产同版本 Python 3.12.3 的隔离环境完成。

### Notes
- `progress.md`：追加 VPS 隔离测试证据与本机验证环境限制。
- 回滚方式：执行 `git revert cdcd1cf`，同步服务器后重启 `glm2api.service`。

## 2026-07-28 - Task: 发布管理面板会话认证修复

### What was done
- 将 GitHub `main` 的修复同步到 VPS 并重启 `glm2api.service`。

### Testing
- `systemctl is-active glm2api.service`：`active`。
- `GET https://glm2api.274747.xyz/health`：`200`。
- `POST https://glm2api.274747.xyz/admin/api/login`：`200`。
- 登录后以 `x-admin-session` 请求 `GET /admin/api/overview`：`200`。
- 登录后以 `glm2api_admin_session` Cookie 请求 `GET /admin/api/overview`：`200`。

### Notes
- `progress.md`：追加生产发布和 HTTPS 端到端验证证据。
- 回滚方式：执行 `git revert cdcd1cf`，同步服务器后重启 `glm2api.service`；提交 `d40d21d` 及本记录提交仅包含文档和日志。
