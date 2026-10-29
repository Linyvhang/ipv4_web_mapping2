# l3_plugins/__init__.py
"""L3 插件注册表：按 service_type 动态选择深度探测模块。

新增服务类型时，只需编写一个 BasePlugin 子类并加入 PLUGINS 列表，
无需改动 l3_scan 的调度逻辑。
"""

from .base import (
    BasePlugin,
    PluginError,
    PluginResult,
    ScanTarget,
    SERVICE_PRIORITY,
    STATUS_DONE,
    STATUS_ERROR,
    clip,
    open_socket,
    recv_burst,
    recv_exact,
    uint32_to_ip,
)
from .web_plugin import WebPlugin
from .ssh_plugin import SshPlugin
from .db_plugin import DbPlugin
from .rdp_plugin import RdpPlugin
from .iot_plugin import IotPlugin

# 已注册插件；顺序不影响调度（调度按 service_type + confidence 排序）
PLUGINS = (
    WebPlugin(),
    SshPlugin(),
    DbPlugin(),
    RdpPlugin(),
    IotPlugin(),
)

_REGISTRY = {plugin.service_type: plugin for plugin in PLUGINS}

# 兜底插件：未知类型（telnet/ftp/file/dns/mail/unknown...）走通用 Banner 采集
_FALLBACK = IotPlugin()


def load_plugin(service_type):
    """按 service_type 路由到对应深度扫描插件"""
    key = (service_type or "unknown").strip().lower()
    return _REGISTRY.get(key, _FALLBACK)


def list_plugins():
    """返回全部已注册插件"""
    return list(PLUGINS)


__all__ = [
    "BasePlugin",
    "PluginError",
    "PluginResult",
    "ScanTarget",
    "SERVICE_PRIORITY",
    "STATUS_DONE",
    "STATUS_ERROR",
    "clip",
    "load_plugin",
    "list_plugins",
    "uint32_to_ip",
]
