# l3_plugins/db_plugin.py
"""数据库服务深度探测插件。

覆盖 MySQL / MariaDB、PostgreSQL、Redis、MongoDB、Elasticsearch、MSSQL：
    Banner、版本信息、开放能力特征

结果写入 db_service_detail。
"""

import struct
from typing import Dict, Optional

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

from .base import (
    BasePlugin,
    PluginError,
    PluginResult,
    ScanTarget,
    clip,
    open_socket,
    recv_burst,
    recv_exact,
)

urllib3.disable_warnings(InsecureRequestWarning)

USER_AGENT = "IPv4Mapper/2.0 (L3 db-fingerprint)"

# 端口 -> 数据库类型（application_proto 无法判断时兜底）
PORT_DB_TYPE = {
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
    9200: "elasticsearch",
    1433: "mssql",
}

MYSQL_AUTH_PLUGINS = (
    "caching_sha2_password",
    "mysql_native_password",
    "sha256_password",
    "mysql_clear_password",
)


class DbPlugin(BasePlugin):
    service_type = "db"
    plugin_name = "db-fingerprint"
    table = "db_service_detail"
    detail_fields = ("db_type", "version", "banner", "features")
    timeout = 5.0

    def scan(self, target: ScanTarget) -> PluginResult:
        db_type = self._guess_type(target)
        if db_type == "mysql":
            return self._probe_mysql(target)
        if db_type == "postgresql":
            return self._probe_postgres(target)
        if db_type == "redis":
            return self._probe_redis(target)
        if db_type == "mongodb":
            return self._probe_mongodb(target)
        if db_type == "elasticsearch":
            return self._probe_elasticsearch(target)
        if db_type == "mssql":
            return self._probe_mssql(target)
        return self._probe_generic(target)

    # ---------------- 类型判定 ----------------

    def _guess_type(self, target: ScanTarget) -> str:
        app = (target.application_proto or "").lower()
        if "maria" in app:
            return "mysql"
        if "mysql" in app:
            return "mysql"
        if "postgres" in app or "pgsql" in app:
            return "postgresql"
        if "redis" in app:
            return "redis"
        if "mongo" in app:
            return "mongodb"
        if "elastic" in app:
            return "elasticsearch"
        if "mssql" in app or "sqlserver" in app:
            return "mssql"
        return PORT_DB_TYPE.get(target.port, "unknown")

    # ---------------- MySQL / MariaDB ----------------

    def _probe_mysql(self, target: ScanTarget) -> PluginResult:
        with open_socket(target.ip, target.port, self.timeout) as sock:
            header = recv_exact(sock, 4)
            if len(header) < 4:
                raise PluginError("MySQL 握手包不完整")
            packet_len = int.from_bytes(header[:3], "little")
            payload = recv_exact(sock, packet_len)

        if not payload:
            raise PluginError("MySQL 握手包为空")
        if payload[0] == 0xFF:
            raise PluginError("MySQL 返回错误包: " + clip(payload[3:].decode("utf-8", "ignore"), 100))

        nul = payload.find(b"\x00", 1)
        if nul < 0:
            raise PluginError("MySQL 握手包解析失败")
        version = payload[1:nul].decode("utf-8", "ignore").strip() or None
        db_type = "mariadb" if version and "mariadb" in version.lower() else "mysql"

        # 认证插件名位于握手包尾部，直接按已知名称匹配，避免偏移量兼容问题
        tail = payload.decode("utf-8", "ignore")
        auth_plugin = next((name for name in MYSQL_AUTH_PLUGINS if name in tail), None)

        features = {
            "protocol_version": payload[0],
            "auth_plugin": auth_plugin,
        }
        return PluginResult(
            self.plugin_name,
            fields={
                "db_type": db_type,
                "version": clip(version, 64),
                "banner": clip(version, 255),
                "features": features,
            },
        )

    # ---------------- PostgreSQL ----------------

    def _probe_postgres(self, target: ScanTarget) -> PluginResult:
        # PostgreSQL SSLRequest：服务器回复 'S'（支持 SSL）或 'N'（不支持）
        ssl_request = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
        with open_socket(target.ip, target.port, self.timeout) as sock:
            sock.sendall(ssl_request)
            response = recv_burst(sock, max_bytes=32, timeout=self.timeout, idle=0.25)

        if not response:
            raise PluginError("PostgreSQL 无响应")
        first = response[:1]
        if first not in (b"S", b"N"):
            raise PluginError(f"非 PostgreSQL 响应: {response[:16]!r}")

        ssl_supported = first == b"S"
        return PluginResult(
            self.plugin_name,
            fields={
                "db_type": "postgresql",
                "version": None,
                # 未完成认证无法拿到 ParameterStatus，此处仅记录协议特征
                "banner": "SSLRequest accepted" if ssl_supported else "SSLRequest refused",
                "features": {"ssl_request_accepted": ssl_supported},
            },
        )

    # ---------------- Redis ----------------

    def _probe_redis(self, target: ScanTarget) -> PluginResult:
        with open_socket(target.ip, target.port, self.timeout) as sock:
            sock.sendall(b"PING\r\n")
            ping = recv_burst(sock, max_bytes=256, timeout=self.timeout, idle=0.25)

            if not ping:
                raise PluginError("Redis 无响应")
            if b"NOAUTH" in ping:
                return PluginResult(
                    self.plugin_name,
                    fields={
                        "db_type": "redis",
                        "version": None,
                        "banner": clip(ping.decode("utf-8", "ignore"), 255),
                        "features": {"auth_required": True},
                    },
                )
            if b"PONG" not in ping:
                raise PluginError(f"非 Redis 响应: {clip(ping.decode('utf-8', 'ignore'), 80)}")

            sock.sendall(b"INFO server\r\n")
            info = recv_burst(sock, max_bytes=8192, timeout=self.timeout, idle=0.3)

        features: Dict[str, object] = {"ping": "PONG"}
        for line in info.decode("utf-8", "ignore").splitlines():
            if not line or line.startswith("#") or ":" not in line:
                continue
            key, value = line.split(":", 1)
            if key in (
                "redis_version",
                "redis_git_sha1",
                "redis_mode",
                "os",
                "arch_bits",
                "run_id",
                "tcp_port",
                "uptime_in_seconds",
                "io_threads_active",
            ):
                features[key] = value.strip()

        version = features.get("redis_version")
        return PluginResult(
            self.plugin_name,
            fields={
                "db_type": "redis",
                "version": clip(version, 64),
                "banner": clip(f"Redis {version}" if version else "Redis PONG", 255),
                "features": features,
            },
        )

    # ---------------- MongoDB ----------------

    def _probe_mongodb(self, target: ScanTarget) -> PluginResult:
        query = _bson_encode({"isMaster": 1, "helloOk": True})
        body = struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<ii", 0, -1) + query
        message = struct.pack("<iiii", len(body) + 16, 1, 0, 2004) + body

        with open_socket(target.ip, target.port, self.timeout) as sock:
            sock.sendall(message)
            data = recv_burst(sock, max_bytes=8192, timeout=self.timeout, idle=0.3)

        if not data:
            raise PluginError("MongoDB 无响应")
        if len(data) < 16:
            raise PluginError("MongoDB 响应包不完整")

        op_code = struct.unpack_from("<i", data, 12)[0]
        if op_code == 1 and len(data) >= 36:          # OP_REPLY
            doc = _bson_decode(data[36:])
        elif op_code == 2013 and len(data) >= 21:     # OP_MSG
            doc = _bson_decode(data[21:])
        else:
            doc = {}

        if not doc:
            raise PluginError("MongoDB 响应解析失败")

        features: Dict[str, object] = {"probe": "isMaster"}
        for key in (
            "maxWireVersion",
            "minWireVersion",
            "maxBsonObjectSize",
            "maxMessageSizeBytes",
            "readOnly",
            "helloOk",
            "logicalSessionTimeoutMinutes",
        ):
            if key in doc:
                features[key] = doc[key]
        if "ok" in doc:
            features["ok"] = doc["ok"]

        return PluginResult(
            self.plugin_name,
            fields={
                "db_type": "mongodb",
                "version": None,
                "banner": "MongoDB isMaster 响应成功",
                "features": features,
            },
        )

    # ---------------- Elasticsearch ----------------

    def _probe_elasticsearch(self, target: ScanTarget) -> PluginResult:
        data: Optional[dict] = None
        errors = []
        for scheme in ("http", "https"):
            try:
                response = requests.get(
                    f"{scheme}://{target.ip}:{target.port}/",
                    timeout=self.timeout,
                    verify=False,
                    headers={"User-Agent": USER_AGENT},
                )
                data = response.json()
                break
            except Exception as exc:
                errors.append(f"{scheme}: {type(exc).__name__}")

        if not data:
            raise PluginError("Elasticsearch 无有效 JSON 响应: " + "; ".join(errors))

        version_block = data.get("version") or {}
        version = version_block.get("number")
        return PluginResult(
            self.plugin_name,
            fields={
                "db_type": "elasticsearch",
                "version": clip(version, 64),
                "banner": clip(data.get("tagline") or "Elasticsearch", 255),
                "features": {
                    "cluster_name": data.get("cluster_name"),
                    "build_flavor": version_block.get("build_flavor"),
                    "build_type": version_block.get("build_type"),
                },
            },
        )

    # ---------------- MSSQL ----------------

    def _probe_mssql(self, target: ScanTarget) -> PluginResult:
        # TDS PRELOGIN 报文较长且版本差异大，这里仅确认端口可达，
        # 明确记录 detect=port，避免误报版本。
        with open_socket(target.ip, target.port, self.timeout) as sock:
            response = recv_burst(sock, max_bytes=512, timeout=self.timeout, idle=0.25)

        return PluginResult(
            self.plugin_name,
            fields={
                "db_type": "mssql",
                "version": None,
                "banner": clip(response.decode("utf-8", "ignore"), 255) if response else None,
                "features": {"detect": "port", "response_bytes": len(response)},
            },
        )

    # ---------------- 其他 ----------------

    def _probe_generic(self, target: ScanTarget) -> PluginResult:
        with open_socket(target.ip, target.port, self.timeout) as sock:
            sock.sendall(b"\r\n")
            response = recv_burst(sock, max_bytes=1024, timeout=self.timeout, idle=0.25)

        text = response.decode("utf-8", "ignore").strip()
        if not text:
            raise PluginError("未获得数据库 Banner")
        return PluginResult(
            self.plugin_name,
            fields={
                "db_type": "unknown",
                "version": None,
                "banner": clip(text, 255),
                "features": {},
            },
        )


# =============== 最小 BSON 编解码（用于 MongoDB isMaster 探测） ===============

def _bson_encode(doc: Dict[str, object]) -> bytes:
    body = b""
    for key, value in doc.items():
        name = key.encode("utf-8") + b"\x00"
        if isinstance(value, bool):
            body += b"\x08" + name + (b"\x01" if value else b"\x00")
        elif isinstance(value, int):
            body += b"\x10" + name + struct.pack("<i", value)
        elif isinstance(value, str):
            payload = value.encode("utf-8")
            body += b"\x02" + name + struct.pack("<i", len(payload) + 1) + payload + b"\x00"
        else:
            raise TypeError(f"不支持的 BSON 类型: {type(value)}")
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


def _bson_decode(data: bytes) -> Dict[str, object]:
    """解析 BSON 文档（覆盖探测场景中出现的常用类型）"""
    if len(data) < 5:
        return {}
    length = int.from_bytes(data[:4], "little")
    if length < 5 or length > len(data):
        return {}

    pos = 4
    end = length - 1
    result: Dict[str, object] = {}
    while pos < end:
        element_type = data[pos]
        pos += 1
        key_end = data.find(b"\x00", pos)
        if key_end < 0:
            break
        key = data[pos:key_end].decode("utf-8", "ignore")
        pos = key_end + 1

        if element_type == 0x01:  # double
            result[key] = struct.unpack_from("<d", data, pos)[0]
            pos += 8
        elif element_type == 0x02:  # string
            size = int.from_bytes(data[pos:pos + 4], "little")
            pos += 4
            result[key] = data[pos:pos + size - 1].decode("utf-8", "ignore")
            pos += size
        elif element_type in (0x03, 0x04):  # document / array
            size = int.from_bytes(data[pos:pos + 4], "little")
            inner = _bson_decode(data[pos:pos + size])
            result[key] = inner if element_type == 0x03 else list(inner.values())
            pos += size
        elif element_type == 0x05:  # binary
            size = int.from_bytes(data[pos:pos + 4], "little")
            pos += 5 + size
            result[key] = f"<binary {size}B>"
        elif element_type == 0x07:  # ObjectId
            pos += 12
            result[key] = "<ObjectId>"
        elif element_type == 0x08:  # bool
            result[key] = data[pos] != 0
            pos += 1
        elif element_type == 0x09:  # datetime(ms)
            result[key] = struct.unpack_from("<q", data, pos)[0]
            pos += 8
        elif element_type == 0x0A:  # null
            result[key] = None
        elif element_type == 0x10:  # int32
            result[key] = struct.unpack_from("<i", data, pos)[0]
            pos += 4
        elif element_type in (0x11, 0x12):  # timestamp / int64
            result[key] = struct.unpack_from("<q", data, pos)[0]
            pos += 8
        elif element_type == 0x13:  # decimal128
            pos += 16
            result[key] = "<decimal128>"
        else:
            # 未知类型无法安全跳过，终止解析，保留已解析字段
            break
    return result
