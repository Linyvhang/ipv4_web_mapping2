# l3_plugins/ssh_plugin.py
"""SSH 深度探测插件：Banner、协议版本、软件版本、操作系统推测。

说明：认证方式 / 弱口令测试需要完成完整的 SSH 密钥交换，
默认不执行（文档中该能力为"可选"），auth_methods 保留为 NULL，
后续可用 paramiko 扩展。
"""

import re
from typing import Optional

from .base import (
    BasePlugin,
    PluginError,
    PluginResult,
    ScanTarget,
    clip,
    open_socket,
    recv_burst,
)

SSH_BANNER_RE = re.compile(r"SSH-([0-9.]+)-([^\r\n]+)")

OS_KEYWORDS = (
    ("ubuntu", "Ubuntu"),
    ("debian", "Debian"),
    ("centos", "CentOS"),
    ("rocky", "Rocky Linux"),
    ("alma", "AlmaLinux"),
    ("red hat", "RHEL"),
    ("freebsd", "FreeBSD"),
    ("openbsd", "OpenBSD"),
    ("windows", "Windows"),
    ("routeros", "MikroTik RouterOS"),
    ("cisco", "Cisco IOS"),
)


class SshPlugin(BasePlugin):
    service_type = "ssh"
    plugin_name = "ssh-banner"
    table = "ssh_service_detail"
    detail_fields = ("protocol_version", "software", "os_guess", "auth_methods", "banner")
    timeout = 4.0

    def scan(self, target: ScanTarget) -> PluginResult:
        with open_socket(target.ip, target.port, timeout=self.timeout) as sock:
            data = recv_burst(sock, max_bytes=512, timeout=self.timeout, idle=0.2)

        if not data:
            raise PluginError("未收到 SSH Banner")

        text = data.decode("utf-8", "ignore").strip()
        # RFC 4253 允许在 SSH- 行为前存在其他文本行
        ssh_line: Optional[str] = None
        for line in text.splitlines():
            if line.startswith("SSH-"):
                ssh_line = line.strip()
                break
        if ssh_line is None:
            raise PluginError(f"非 SSH 响应: {clip(text, 80)}")

        match = SSH_BANNER_RE.match(ssh_line)
        protocol_version = match.group(1) if match else None
        software = match.group(2).strip() if match else None

        os_guess = None
        haystack = f"{software or ''} {ssh_line}".lower()
        for keyword, name in OS_KEYWORDS:
            if keyword in haystack:
                os_guess = name
                break

        return PluginResult(
            self.plugin_name,
            fields={
                "protocol_version": clip(protocol_version, 32),
                "software": clip(software, 128),
                "os_guess": clip(os_guess, 64),
                "auth_methods": None,
                "banner": clip(ssh_line, 255),
            },
        )
