# l3_plugins/rdp_plugin.py
"""RDP 深度探测插件：协议协商、加密方式、端口开放情况。

通过发送 X.224 Connection Request（携带 RDP 协商请求），
解析服务器返回的 RDP_NEG_RSP 得到协商结果。
"""

import struct
from typing import Optional

from .base import BasePlugin, PluginError, PluginResult, ScanTarget, clip, open_socket, recv_burst

# TPKT + X.224 CR + RDP_NEG_REQ（请求 TLS/CredSSP）
NEGOTIATION_REQUEST = bytes.fromhex("030000130ee000000000000100080003000000")

PROTOCOLS = {
    0: "RDP (standard security)",
    1: "TLS",
    2: "CredSSP (NLA)",
    3: "CredSSP+HYBRID (NLA)",
    4: "RDSTLS",
    5: "CredSSP+HYBRID_EX (NLA)",
}

FAILURE_CODES = {
    1: "SSL_REQUIRED_BY_SERVER",
    2: "SSL_NOT_ALLOWED_BY_SERVER",
    3: "SSL_CERT_NOT_ON_SERVER",
    4: "INCONSISTENT_FLAGS",
    5: "HYBRID_REQUIRED_BY_SERVER",
    6: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
}


class RdpPlugin(BasePlugin):
    service_type = "rdp"
    plugin_name = "rdp-negotiation"
    table = "rdp_service_detail"
    detail_fields = ("banner", "protocol_version", "encryption", "port_open")
    timeout = 4.0

    def scan(self, target: ScanTarget) -> PluginResult:
        with open_socket(target.ip, target.port, self.timeout) as sock:
            sock.sendall(NEGOTIATION_REQUEST)
            response = recv_burst(sock, max_bytes=256, timeout=self.timeout, idle=0.25)

        if not response:
            raise PluginError("RDP 无响应")
        if len(response) < 7 or not response.startswith(b"\x03\x00"):
            raise PluginError(f"非 RDP 响应: {response[:32]!r}")

        # X.224 Connection Confirm 之后紧跟 RDP_NEG_RSP/RSP_FAILURE（起始偏移 11）
        protocol_code: Optional[int] = None
        if len(response) >= 15 and response[11] in (0x02, 0x03):
            neg_type = response[11]
            if neg_type == 0x03:
                code = struct.unpack_from("<I", response, 15)[0] if len(response) >= 19 else 0
                reason = FAILURE_CODES.get(code, f"code={code}")
                raise PluginError(f"RDP 协商失败: {reason}")
            if len(response) >= 19:
                protocol_code = struct.unpack_from("<I", response, 15)[0]

        protocol_version = PROTOCOLS.get(protocol_code, "unknown") if protocol_code is not None else (
            "RDP (legacy, no negotiation)"
        )
        encryption = (
            "CredSSP/NLA"
            if protocol_code in (2, 3, 5)
            else "TLS"
            if protocol_code in (1, 4)
            else "RDP 标准安全 (RC4)"
        )

        return PluginResult(
            self.plugin_name,
            fields={
                "banner": clip(response[:64].hex(), 255),
                "protocol_version": clip(protocol_version, 64),
                "encryption": clip(encryption, 64),
                "port_open": 1,
            },
        )
