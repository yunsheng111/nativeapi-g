from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from .model_variants import expand_model_variants


DEFAULT_ASSISTANT_ID = "65940acff94777010aa6b796"
DEFAULT_IMAGE_ASSISTANT_ID = "65a232c082ff90a2ad2f15e2"
DEFAULT_IMAGE_MODEL_NAME = "glm-image-1"
DEFAULT_GLM_BASE_URL = "https://chatglm.cn/chatglm"
GUEST_REFRESH_TOKEN_MARKER = "__glm_guest__"
DEFAULT_BLOCKED_TOOL_NAMES = ()
BUILTIN_EXPOSED_MODELS = (
    "cogView-4-250304",
    "glm-5.2",
    "glm-5.1",
    "glm-5v-turbo",
    "glm-5-turbo",
    "glm-5",
    "glm-4.7-flash",
    "glm-4.7",
    "glm-4.6v-flash",
    "glm-4.6",
    "glm-4.5",
    "glm-4.1v-thinking-flashx",
    "glm-4",
    "glm-4-flash",
    "glm-4-air",
    "glm-4v",
    "glm-4-flashx-250414",
    "glm-4-flash-250414",
    "glm-zero-preview",
    "glm-deep-research",
    DEFAULT_IMAGE_MODEL_NAME,
)
MODEL_VARIANT_EXCLUDED_MODELS = {
    "cogView-4-250304",
    DEFAULT_IMAGE_MODEL_NAME,
}
BUILTIN_MODEL_ALIASES = {name: name for name in BUILTIN_EXPOSED_MODELS}


class ConfigError(ValueError):
    pass


def parse_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ConfigError(f"配置文件不是有效的 UTF-8 编码: {path}") from exc
    except OSError as exc:
        raise ConfigError(f"读取配置文件失败: {path} error={exc}") from exc

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        value = raw_value.strip()
        if value.startswith(("'", '"')) and value.endswith(("'", '"')) and len(value) >= 2:
            value = value[1:-1]
        values[key.strip()] = value
    return values


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_int(value: str | None, default: int) -> int:
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"整数配置值无效: {value}") from exc


def parse_float(value: str | None, default: float) -> float:
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"浮点配置值无效: {value}") from exc


def parse_list(value: str | None, default: tuple[str, ...] = ()) -> list[str]:
    if value is None or value.strip() == "":
        return list(default)
    return [item.strip() for item in value.split(",") if item.strip()]


def load_refresh_tokens(token_file_path: Path) -> list[str]:
    if not token_file_path.exists():
        return []
    tokens: list[str] = []
    try:
        lines = token_file_path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ConfigError(f"token 文件不是有效的 UTF-8 编码: {token_file_path}") from exc
    except OSError as exc:
        raise ConfigError(f"读取 token 文件失败: {token_file_path} error={exc}") from exc
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        tokens.append(line)
    return tokens


def is_guest_token_value(value: str | None) -> bool:
    if value is None:
        return False
    normalized = value.strip().lower()
    return normalized in {"guest", "guest_ck", "guest-ck", "visitor", "tourist", "游客", GUEST_REFRESH_TOKEN_MARKER}


@dataclass(slots=True)
class AppConfig:
    env_file_path: Path
    env_file_created: bool
    token_file_path: Path
    host: str
    port: int
    api_prefix: str
    log_level: str
    debug_dump_all: bool
    request_timeout: int
    glm_base_url: str
    glm_use_guest_refresh_token: bool
    glm_refresh_token: str
    glm_refresh_tokens: list[str]
    glm_assistant_id: str
    glm_image_assistant_id: str
    glm_image_model_name: str
    glm_user_agent: str
    glm_delete_conversation: bool
    glm_max_concurrency: int
    glm_queue_wait_timeout: int
    glm_busy_max_retries: int
    glm_busy_retry_interval: float
    glm_guest_max_retries: int
    glm_request_jitter_ms: int
    glm_guest_stagger_seconds: float
    glm_health_probe_seconds: int
    glm_health_keepalive_batch: int
    glm_transport_block_private: bool
    glm_transport: str
    glm_cdp_headless: bool
    glm_cdp_port: int
    glm_cdp_user_data_dir: str
    glm_cdp_origin: str
    glm_cdp_breaker_threshold: int
    glm_cdp_breaker_seconds: float
    glm_cdp_account_contexts: bool
    glm_canary_enabled: bool
    glm_canary_every_n: int
    glm_canary_failure_threshold: int
    glm_canary_cooldown_seconds: float
    glm_tool_result_max_chars: int
    glm_context_max_tokens: int
    glm_stream_max_seconds: int
    glm_account_grace_seconds: int
    glm_min_request_interval_ms: int
    blocked_tool_names: list[str]
    exposed_models: list[str]
    model_aliases: dict[str, str]
    server_api_keys: list[str]
    admin_key: str
    cors_allow_origin: str

    @property
    def refresh_url(self) -> str:
        return f"{self.glm_base_url}/user-api/user/refresh"

    @property
    def guest_refresh_url(self) -> str:
        return f"{self.glm_base_url}/user-api/guest/access"

    @property
    def chat_stream_url(self) -> str:
        return f"{self.glm_base_url}/backend-api/assistant/stream"

    @property
    def delete_conversation_url(self) -> str:
        return f"{self.glm_base_url}/backend-api/assistant/conversation/delete"


def ensure_env_file(env_path: Path) -> bool:
    if env_path.exists():
        return False

    example_candidates = [
        env_path.with_name(".env.example"),
        env_path.parent / ".env.example",
    ]
    example_path = next((candidate for candidate in example_candidates if candidate.exists()), None)
    if example_path is None:
        return False

    try:
        env_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(example_path, env_path)
    except OSError as exc:
        raise ConfigError(f"自动创建配置文件失败: source={example_path} target={env_path} error={exc}") from exc
    return True


def load_config(env_file: str = ".env") -> AppConfig:
    import logging

    logger = logging.getLogger("glm2api.config")
    env_path = Path(env_file)
    env_file_created = ensure_env_file(env_path)
    file_values = parse_dotenv(env_path)
    values = {**file_values, **os.environ}

    glm_max_concurrency = max(1, parse_int(values.get("GLM_MAX_CONCURRENCY"), 3))
    token_file_path = Path(values.get("GLM_TOKEN_FILE", "token.txt"))
    if not token_file_path.is_absolute():
        token_file_path = (env_path.parent / token_file_path).resolve()

    refresh_tokens = load_refresh_tokens(token_file_path)
    single_refresh_token = values.get("GLM_REFRESH_TOKEN", "").strip()
    explicit_guest_mode = parse_bool(values.get("GLM_USE_GUEST_REFRESH_TOKEN"), False) or is_guest_token_value(single_refresh_token)

    if explicit_guest_mode:
        refresh_tokens = [GUEST_REFRESH_TOKEN_MARKER] * glm_max_concurrency
        single_refresh_token = GUEST_REFRESH_TOKEN_MARKER
    elif not refresh_tokens and single_refresh_token:
        refresh_tokens = [single_refresh_token]
    elif not refresh_tokens:
        refresh_tokens = [GUEST_REFRESH_TOKEN_MARKER] * glm_max_concurrency
        single_refresh_token = GUEST_REFRESH_TOKEN_MARKER
        explicit_guest_mode = True

    host = values.get("HOST", "127.0.0.1").strip() or "127.0.0.1"
    api_prefix = values.get("API_PREFIX", "/v1").strip()
    if not api_prefix:
        api_prefix = "/v1"
    if not api_prefix.startswith("/"):
        api_prefix = f"/{api_prefix}"
    api_prefix = api_prefix.rstrip("/") or "/v1"
    log_level = values.get("LOG_LEVEL", "INFO").strip().upper() or "INFO"
    debug_dump_all = parse_bool(values.get("DEBUG_DUMP_ALL"), False)
    if debug_dump_all:
        log_level = "DEBUG"
    if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        log_level = "INFO"
    image_model_name = DEFAULT_IMAGE_MODEL_NAME
    exposed_models = expand_model_variants(
        BUILTIN_EXPOSED_MODELS,
        excluded_models=MODEL_VARIANT_EXCLUDED_MODELS,
    )
    model_aliases = dict(BUILTIN_MODEL_ALIASES)

    config = AppConfig(
        env_file_path=env_path,
        env_file_created=env_file_created,
        token_file_path=token_file_path,
        host=host,
        port=parse_int(values.get("PORT"), 8000),
        api_prefix=api_prefix,
        log_level=log_level,
        debug_dump_all=debug_dump_all,
        request_timeout=parse_int(values.get("REQUEST_TIMEOUT_SECONDS"), 120),
        glm_base_url=values.get("GLM_BASE_URL", DEFAULT_GLM_BASE_URL).rstrip("/"),
        glm_use_guest_refresh_token=explicit_guest_mode,
        glm_refresh_token=single_refresh_token,
        glm_refresh_tokens=refresh_tokens,
        glm_assistant_id=values.get("GLM_ASSISTANT_ID", DEFAULT_ASSISTANT_ID).strip(),
        glm_image_assistant_id=values.get("GLM_IMAGE_ASSISTANT_ID", DEFAULT_IMAGE_ASSISTANT_ID).strip(),
        glm_image_model_name=image_model_name,
        glm_user_agent=values.get(
            "GLM_USER_AGENT",
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"
            ),
        ).strip(),
        glm_delete_conversation=parse_bool(values.get("GLM_DELETE_CONVERSATION"), True),
        glm_max_concurrency=glm_max_concurrency,
        glm_queue_wait_timeout=parse_int(values.get("GLM_QUEUE_WAIT_TIMEOUT_SECONDS"), 600),
        glm_busy_max_retries=parse_int(values.get("GLM_BUSY_MAX_RETRIES"), 30),
        glm_busy_retry_interval=parse_float(values.get("GLM_BUSY_RETRY_INTERVAL_SECONDS"), 2.0),
        glm_guest_max_retries=max(0, parse_int(values.get("GLM_GUEST_MAX_RETRIES"), 3)),
        glm_request_jitter_ms=max(0, parse_int(values.get("GLM_REQUEST_JITTER_MS"), 200)),
        glm_guest_stagger_seconds=max(0.0, parse_float(values.get("GLM_GUEST_STAGGER_SECONDS"), 5.0)),
        glm_health_probe_seconds=max(0, parse_int(values.get("GLM_HEALTH_PROBE_SECONDS"), 300)),
        # P2.5 第二批 keepalive 批处理：每轮真实续命的账号上限（0 = 不限量，旧行为）
        glm_health_keepalive_batch=max(0, parse_int(values.get("GLM_HEALTH_KEEPALIVE_BATCH"), 3)),
        glm_transport_block_private=parse_bool(values.get("GLM_TRANSPORT_BLOCK_PRIVATE"), True),
        glm_transport=(lambda v: v if v in ("urllib", "cdp") else "urllib")(values.get("GLM_TRANSPORT", "urllib").strip().lower()),
        glm_cdp_headless=parse_bool(values.get("GLM_CDP_HEADLESS"), False),
        glm_cdp_port=max(0, parse_int(values.get("GLM_CDP_PORT"), 0)),
        glm_cdp_user_data_dir=values.get("GLM_CDP_USER_DATA_DIR", "").strip() or "_cdp_profile",
        glm_cdp_origin=values.get("GLM_CDP_ORIGIN", "https://chatglm.cn").strip() or "https://chatglm.cn",
        glm_cdp_breaker_threshold=max(1, parse_int(values.get("GLM_CDP_BREAKER_THRESHOLD"), 3)),
        glm_cdp_breaker_seconds=max(1.0, parse_float(values.get("GLM_CDP_BREAKER_SECONDS"), 600.0)),
        # P2.5 第二批 D2 定案：非游客账号各自专属 BrowserContext（cookie + Authorization 同源一致）；
        # false 退回单 context（浏览器默认身份）旧形态。游客恒走默认 context。
        glm_cdp_account_contexts=parse_bool(values.get("GLM_CDP_ACCOUNT_CONTEXTS"), True),
        # P2.5 第二批 canary A/B 分流（11.4）：默认关闭只做统计记录，显式开启才参与选路
        glm_canary_enabled=parse_bool(values.get("GLM_CANARY_ENABLED"), False),
        glm_canary_every_n=max(1, parse_int(values.get("GLM_CANARY_EVERY_N"), 20)),
        glm_canary_failure_threshold=max(1, parse_int(values.get("GLM_CANARY_FAILURE_THRESHOLD"), 3)),
        glm_canary_cooldown_seconds=max(1.0, parse_float(values.get("GLM_CANARY_COOLDOWN_SECONDS"), 600.0)),
        glm_tool_result_max_chars=max(0, parse_int(values.get("GLM_TOOL_RESULT_MAX_CHARS"), 24000)),
        # P0-4 上下文长度保护（拍板点 2）：默认 0 = 关闭，先观测真实拍平体积分布再定默认值
        glm_context_max_tokens=max(0, parse_int(values.get("GLM_CONTEXT_MAX_TOKENS"), 0)),
        # P0-6 SSE 硬超时看门狗：单条流最长存活时间（对照 chatgpt2api 单流挂 29.5 分钟事故），0 = 关闭
        glm_stream_max_seconds=max(0, parse_int(values.get("GLM_STREAM_MAX_SECONDS"), 600)),
        # P0-7 新账号失败宽限：进入账号池后 N 秒内失败不计入通用熔断（风控不豁免），0 = 关闭
        glm_account_grace_seconds=max(0, parse_int(values.get("GLM_ACCOUNT_GRACE_SECONDS"), 600)),
        # P0-8 全局最小间隔节流：相邻请求的上游到达时刻最小间隔（毫秒），0 = 关闭
        glm_min_request_interval_ms=max(0, parse_int(values.get("GLM_MIN_REQUEST_INTERVAL_MS"), 0)),
        blocked_tool_names=parse_list(values.get("BLOCKED_TOOL_NAMES"), DEFAULT_BLOCKED_TOOL_NAMES),
        exposed_models=exposed_models,  # type: ignore
        model_aliases=model_aliases,
        server_api_keys=parse_list(values.get("SERVER_API_KEYS")),
        admin_key=values.get("ADMIN_KEY", "glm2api-admin").strip() or "glm2api-admin",
        cors_allow_origin=values.get("CORS_ALLOW_ORIGIN", "*").strip() or "*",
    )

    if not (1 <= config.port <= 65535):
        raise ConfigError(f"端口配置超出范围: PORT={config.port}")
    if config.request_timeout <= 0:
        raise ConfigError(f"请求超时必须大于 0: REQUEST_TIMEOUT_SECONDS={config.request_timeout}")
    if config.glm_queue_wait_timeout <= 0:
        raise ConfigError(f"队列等待时间必须大于 0: GLM_QUEUE_WAIT_TIMEOUT_SECONDS={config.glm_queue_wait_timeout}")
    if config.glm_busy_retry_interval < 0:
        raise ConfigError(f"忙碌重试间隔不能小于 0: GLM_BUSY_RETRY_INTERVAL_SECONDS={config.glm_busy_retry_interval}")
    if not config.glm_base_url.startswith(("http://", "https://")):
        raise ConfigError(f"GLM_BASE_URL 必须以 http:// 或 https:// 开头: {config.glm_base_url}")

    token_source = "游客模式" if explicit_guest_mode else (f"token 文件 ({token_file_path})" if token_file_path.exists() else ".env GLM_REFRESH_TOKEN")
    logger.info(
        "配置加载完成 端口=%s 并发=%s 账号数=%s token来源=%s 日志级别=%s",
        config.port,
        config.glm_max_concurrency,
        len(config.glm_refresh_tokens),
        token_source,
        config.log_level,
    )
    logger.debug(
        "配置详情 host=%s api_prefix=%s timeout=%ss 删除会话=%s 暴露模型=%s",
        config.host,
        config.api_prefix,
        config.request_timeout,
        config.glm_delete_conversation,
        len(config.exposed_models),
    )
    return config
