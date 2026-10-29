# l3_plugins/base.py
"""第三层（L3）插件公共定义。

所有深度探测插件遵循同一契约：

    plugin.scan(ScanTarget) -> PluginResult

- ScanTarget  ：来自 service_instance_l2 的一条服务实例
- PluginResult：写回对应 detail 表的字段集合 + 扫描状态

插件只负责"探测 + 解析"，不直接访问数据库；
入库与状态回写统一由 l3_store / l3_scan 完成，保证调度与存储解耦。
"""

import socket
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

# 服务类型扫描优先级（数字越小越先扫描，高风险/高价值服务优先）
SERVICE_PRIORITY: Dict[str, int] = {"web": 0, "ssh": 1, "db": 2, "rdp": 3}
DEFAULT_PRIORITY = 4

# detail 表 scan_status 语义
STATUS_DONE = 1
STATUS_ERROR = 2


def uint32_to_ip(num: int) -> str:
    """uint32 -> 点分十进制 IP"""
    return f"{(num >> 24) & 0xFF}.{(num >> 16) & 0xFF}.{(num >> 8) & 0xFF}.{num & 0xFF}"


def clip(text, limit: int = 255) -> Optional[str]:
    """压缩空白并截断，用于写入 VARCHAR 字段"""
    if text is None:
        return None
    text = " ".join(str(text).split())
    if not text:
        return None
    return text if len(text) <= limit else text[: limit - 3] + "..."


@dataclass
class ScanTarget:
    """L3 扫描目标：一条 L2 已确认的服务实例"""

    service_instance_id: int
    ip_address: int                    # uint32
    port: int
    transport_protocol: str = "tcp"
    service_type: str = "unknown"
    application_proto: Optional[str] = None
    banner: Optional[str] = None
    confidence: float = 0.0

    @property
    def ip(self) -> str:
        return uint32_to_ip(self.ip_address)

    @property
    def endpoint(self) -> str:
        return f"{self.ip}:{self.port}"

    @property
    def priority(self) -> int:
        return SERVICE_PRIORITY.get((self.service_type or "").lower(), DEFAULT_PRIORITY)


@dataclass
class PluginResult:
    """插件输出：detail 表字段 + 扫描状态"""

    plugin_name: str
    scan_status: int = STATUS_DONE
    fields: Dict[str, object] = field(default_factory=dict)
    error_message: Optional[str] = None


class PluginError(Exception):
    """探测失败（网络不可达、协议不符合预期等），由调度层记录为异常状态"""


class BasePlugin:
    """插件基类"""

    service_type = ""      # 负责的 service_type
    plugin_name = ""       # 插件名，写入 detail.plugin_name
    table = ""             # 结果表名
    detail_fields: Tuple[str, ...] = ()   # 允许写入的 detail 表字段
    timeout = 5.0          # 单次探测超时（秒）

    def scan(self, target: ScanTarget) -> PluginResult:
        raise NotImplementedError


# ===================== 网络辅助函数 =====================

def open_socket(ip: str, port: int, timeout: float = 5.0) -> socket.socket:
    """建立 TCP 连接并设置读写超时"""
    sock = socket.create_connection((ip, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """精确读取 n 字节（用于带长度头的协议，如 MySQL 握手包）"""
    chunks = []
    total = 0
    while total < n:
        try:
            data = sock.recv(n - total)
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
        total += len(data)
    return b"".join(chunks)


def recv_burst(sock: socket.socket, max_bytes: int = 1024, timeout: float = 5.0,
               idle: float = 0.25) -> bytes:
    """读取一段响应：收到数据后短暂空闲即认为本次响应结束。

    相比"一直读到超时"，不会为每个目标额外等待完整超时时间。
    """
    chunks = []
    total = 0
    while total < max_bytes:
        sock.settimeout(idle if chunks else timeout)
        try:
            data = sock.recv(min(4096, max_bytes - total))
        except OSError:  # 超时 / 连接被重置：按"响应结束"处理
            break
        if not data:
            break
        chunks.append(data)
        total += len(data)
    return b"".join(chunks)
