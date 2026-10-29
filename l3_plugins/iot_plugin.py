# l3_plugins/iot_plugin.py
"""通用 Banner 采集插件。

承担 L2 中除 web/ssh/db/rdp 之外的服务类型（telnet / ftp / file / iot / unknown）
的深度探测：协议特征、设备型号关键词、原始 Banner。
"""

import re

from .base import BasePlugin, PluginError, PluginResult, ScanTarget, clip, open_socket, recv_burst

# 无被动 Banner 时主动发送 HTTP HEAD 的端口
HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8888, 9000, 9080}

PROTOCOL_MARKERS = (
    (b"HTTP/", "http"),
    (b"SSH-", "ssh"),
    (b"RTSP/", "rtsp"),
    (b"RFB ", "vnc"),
    (b"AMQP", "amqp"),
    (b"+OK", "pop3"),
    (b"* OK", "imap"),
    (b"\xffSMB", "smb"),
    (b"\xfeSMB", "smb"),
    (b"220", "ftp/smtp"),
)

DEVICE_KEYWORDS = {
    "hikvision": "Hikvision",
    "dvrdvs": "Hikvision",
    "dahua": "Dahua",
    "mikrotik": "MikroTik",
    "routeros": "MikroTik RouterOS",
    "tp-link": "TP-LINK",
    "cisco": "Cisco",
    "huawei": "Huawei",
    "h3c": "H3C",
    "zte": "ZTE",
    "siemens": "Siemens",
    "schneider": "Schneider",
    "moxa": "Moxa",
    "rockwell": "Rockwell",
    "axis": "Axis",
    "d-link": "D-Link",
    "netgear": "NETGEAR",
    "epson": "Epson",
    "canon": "Canon",
    "brother": "Brother",
}

NON_PRINTABLE_RE = re.compile(r"[^\x20-\x7e\r\n\t]")


class IotPlugin(BasePlugin):
    service_type = "iot"
    plugin_name = "banner-grab"
    table = "iot_service_detail"
    detail_fields = ("protocol_guess", "device_model", "banner")
    timeout = 4.0

    def scan(self, target: ScanTarget) -> PluginResult:
        application = (target.application_proto or "").lower()

        with open_socket(target.ip, target.port, self.timeout) as sock:
            banner = recv_burst(sock, max_bytes=1024, timeout=self.timeout, idle=0.2)

            # 被动无响应时，对疑似 HTTP 的端口主动发起 HEAD 请求
            if not banner and (target.port in HTTP_PORTS or "http" in application):
                sock.sendall(
                    b"HEAD / HTTP/1.0\r\n"
                    b"Host: " + target.ip.encode() + b"\r\n"
                    b"User-Agent: IPv4Mapper/2.0\r\n\r\n"
                )
                banner = recv_burst(sock, max_bytes=1024, timeout=self.timeout, idle=0.25)

        if not banner:
            raise PluginError("未获得 Banner 响应")

        protocol_guess = next(
            (name for marker, name in PROTOCOL_MARKERS if marker in banner), None
        )
        if protocol_guess is None:
            if target.port == 23:
                protocol_guess = "telnet"
            elif target.port == 21:
                protocol_guess = "ftp"
            else:
                protocol_guess = "unknown"

        text = banner.decode("utf-8", "ignore")
        text = NON_PRINTABLE_RE.sub(".", text)
        lowered = text.lower()
        device_model = next(
            (name for keyword, name in DEVICE_KEYWORDS.items() if keyword in lowered), None
        )

        return PluginResult(
            self.plugin_name,
            fields={
                "protocol_guess": clip(protocol_guess, 32),
                "device_model": clip(device_model, 128),
                "banner": clip(text, 255),
            },
        )
