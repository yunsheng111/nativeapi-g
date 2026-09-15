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


def _install_device_id_hook() -> None:
    """D1：把 accounts.json 的真实设备身份接进底座 token 管理器。

    底座 glm2api 不 import glmrelay（依赖不倒挂），钩子在 glmrelay 首次被导入时
    （server.py 引入 admin 面板扩展时）安装 —— 此刻还没有任何账号槽位被创建。
    扩展层可选：安装失败不阻断底座启动，账号退回稳定随机设备身份。
    """
    try:
        from glm2api.services.glm_auth import GLMAccessTokenManager

        from .accounts.registry import resolve_device_id

        GLMAccessTokenManager.device_id_resolver = staticmethod(resolve_device_id)
    except Exception:  # pragma: no cover
        pass


_install_device_id_hook()
