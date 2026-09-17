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


def _install_token_rotation_hook() -> None:
    """B2：token 被上游轮换时登记别名链，保住真实设备身份不被断链。

    底座轮换 refresh_token 是整文件重写 token.txt，而 accounts.json 的设备身份
    条目按旧 token 指纹索引 —— 不登记别名的话，首次自动轮换后
    resolve_device_id 就查不到新 token。监听器在轮换发生时把 (旧, 新) token 对
    交给 store.rotate_token_alias（CAS 幂等）。扩展层可选：安装失败不阻断底座
    启动，仅退化为「轮换后身份解析回退稳定随机值，直到重新导入」。
    """
    try:
        from glm2api.services.glm_auth import GLMAccessTokenManager

        from .accounts.registry import _token_file
        from .accounts.store import TokenStore

        GLMAccessTokenManager.token_rotation_listener = TokenStore(_token_file()).rotate_token_alias
    except Exception:  # pragma: no cover
        pass


def _install_stats_persistence() -> None:
    """P2-5：运行统计事件驱动落盘 + 启动回填。

    底座在每个统计变更点（请求/结果/探活/风控事件）把 (账号 index, 快照)
    通报给监听者；restore_provider 在账号管理器初始化时按 index 回填累计
    计数。键是 token 指纹（index 在账号增删后会漂移），落盘文件
    accounts_stats.json 与身份元数据分离（运行时数据不污染身份文件）。
    扩展层可选：安装失败不阻断底座启动，仅退化为统计纯内存态（重启即丢，
    与 P1-b 之前的行为一致）。
    """
    try:
        from glm2api.services.glm_auth import GLMAccessTokenManager

        from .accounts.registry import _token_file
        from .accounts.store import TokenStore

        store = TokenStore(_token_file())
        GLMAccessTokenManager.stats_persist_listener = store.record_stats_for_index
        GLMAccessTokenManager.stats_restore_provider = store.stats_for_index
    except Exception:  # pragma: no cover
        pass


_install_device_id_hook()
_install_token_rotation_hook()
_install_stats_persistence()
