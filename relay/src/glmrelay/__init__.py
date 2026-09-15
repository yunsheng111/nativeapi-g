"""glmrelay —— glm2api 的扩展层。

原则：底座 glm2api 只做最小改动（打扩展点），新逻辑一律放这里，
以保证日后 git pull 同步上游修复时冲突面最小。

模块划分：
    accounts/  账号额度池加固（配额、熔断、健康探测、登录导入）
    browser/   纯标准库 CDP 客户端（账号导入 + 浏览器操作共用）
    bridge/    协议桥（OpenAI / Anthropic 双向转换、模式路由）
    agent/     模式 B 的 agent loop
    tools/     模式 B 的工具运行时
"""

__version__ = "0.1.0"
