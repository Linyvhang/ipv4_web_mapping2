# l3_plugins/web_plugin.py
"""Web 深度探测插件。

探测内容（对应《主体思路 2.0》5.2 Web 行）：
    HTTP 状态码、Title、Server Header、X-Powered-By、
    TLS 证书信息、Web 框架 / CMS 指纹

结果写入 web_service_detail。
"""

import html
import re
import socket
import ssl
from typing import Dict, List, Optional

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

from .base import BasePlugin, PluginError, PluginResult, ScanTarget, clip

urllib3.disable_warnings(InsecureRequestWarning)

# 默认按 HTTPS 处理的端口
HTTPS_PORTS = {443, 4443, 8443, 9443}
HTTPS_PROTOCOLS = {"https", "ssl/http", "ssl/https", "ssl/https-alt"}

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 IPv4Mapper/2.0"
)

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I
)

# Server 头指纹
SERVER_RULES = (
    ("cloudflare", "Cloudflare"),
    ("openresty", "OpenResty"),
    ("nginx", "Nginx"),
    ("litespeed", "LiteSpeed"),
    ("apache", "Apache"),
    ("iis", "Microsoft IIS"),
)
# X-Powered-By 指纹
POWERED_BY_RULES = (
    ("php", "PHP"),
    ("asp.net", "ASP.NET"),
    ("express", "Node.js Express"),
    ("servlet", "Java Servlet"),
)
# Cookie 指纹（精确匹配 Cookie 名）
COOKIE_RULES = {
    "phpsessid": "PHP",
    "jsessionid": "Java",
    "asp.net_sessionid": "ASP.NET",
    "laravel_session": "Laravel",
    "ci_session": "CodeIgniter",
    "rememberme": "Apache Shiro",
    "csrftoken": "Django",
    "sessionid": "Django",
}
# 响应正文指纹
BODY_RULES = (
    ("wp-content", "WordPress"),
    ("wp-includes", "WordPress"),
    ("/sites/default/files", "Drupal"),
    ("drupal.settings", "Drupal"),
    ("/media/system/js/", "Joomla"),
    ("thinkphp", "ThinkPHP"),
    ("dedecms", "DedeCMS"),
    ("discuz", "Discuz!"),
    ("__nuxt__", "Nuxt.js"),
    ("_next/static", "Next.js"),
)


class WebPlugin(BasePlugin):
    service_type = "web"
    plugin_name = "http-fingerprint"
    table = "web_service_detail"
    detail_fields = (
        "http_status",
        "title",
        "server_header",
        "x_powered_by",
        "tls_certificate",
        "web_fingerprint",
    )
    timeout = 6.0

    def scan(self, target: ScanTarget) -> PluginResult:
        scheme = self._pick_scheme(target)
        # 优先按判定协议访问，失败时回退到另一种协议
        candidates = [scheme] + [s for s in ("https", "http") if s != scheme]

        response = None
        used_scheme = scheme
        errors: List[str] = []
        for current in candidates:
            try:
                response = requests.get(
                    f"{current}://{target.ip}:{target.port}/",
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                    headers={
                        "User-Agent": USER_AGENT,
                        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                        "Connection": "close",
                    },
                )
                used_scheme = current
                break
            except Exception as exc:  # 连接失败 / TLS 失败 / 超时
                errors.append(f"{current}: {type(exc).__name__}")

        if response is None:
            raise PluginError("HTTP/HTTPS 请求失败: " + "; ".join(errors))

        body, _encoding = self._read_body(response)
        title = self._extract_title(body)
        marks = self._fingerprint(response, body)

        tls_info: Optional[Dict[str, object]] = None
        if used_scheme == "https":
            try:
                tls_info = self._grab_certificate(target.ip, target.port)
            except Exception as exc:
                tls_info = {"error": f"{type(exc).__name__}: {exc}"}

        return PluginResult(
            self.plugin_name,
            fields={
                "http_status": response.status_code,
                "title": clip(title, 255),
                "server_header": clip(response.headers.get("Server"), 255),
                "x_powered_by": clip(response.headers.get("X-Powered-By"), 255),
                "tls_certificate": tls_info,
                "web_fingerprint": {
                    "url": response.url,
                    "scheme": used_scheme,
                    "content_type": clip(response.headers.get("Content-Type"), 120),
                    "fingerprints": marks,
                },
            },
        )

    # ---------------- 内部方法 ----------------

    def _pick_scheme(self, target: ScanTarget) -> str:
        if target.port in HTTPS_PORTS:
            return "https"
        if (target.application_proto or "").lower() in HTTPS_PROTOCOLS:
            return "https"
        if target.banner and "ssl" in target.banner.lower():
            return "https"
        return "http"

    @staticmethod
    def _read_body(response: requests.Response):
        raw = response.content[:262144]
        encoding = response.encoding
        if not encoding or encoding.lower() in ("iso-8859-1", "ascii"):
            encoding = response.apparent_encoding or "utf-8"
        try:
            return raw.decode(encoding, "ignore"), encoding
        except LookupError:
            return raw.decode("utf-8", "ignore"), "utf-8"

    @staticmethod
    def _extract_title(body: str) -> Optional[str]:
        match = TITLE_RE.search(body)
        if not match:
            return None
        return html.unescape(re.sub(r"\s+", " ", match.group(1))).strip()

    def _fingerprint(self, response: requests.Response, body: str) -> List[Dict[str, str]]:
        marks: List[Dict[str, str]] = []
        seen = set()

        def add(name: str, evidence: Optional[str] = None) -> None:
            key = name.lower()
            if key in seen:
                return
            seen.add(key)
            marks.append({"name": name, "evidence": clip(evidence, 120)})

        server = (response.headers.get("Server") or "").lower()
        for keyword, name in SERVER_RULES:
            if keyword in server:
                add(name, response.headers.get("Server"))

        powered_by = (response.headers.get("X-Powered-By") or "").lower()
        for keyword, name in POWERED_BY_RULES:
            if keyword in powered_by:
                add(name, response.headers.get("X-Powered-By"))

        cookie_names = {key.lower() for key in response.cookies.keys()}
        for cookie, name in COOKIE_RULES.items():
            if cookie in cookie_names:
                add(name, f"Cookie: {cookie}")
        if any(key.startswith("wordpress_") for key in cookie_names):
            add("WordPress", "Cookie: wordpress_*")

        lowered_body = body.lower()
        for keyword, name in BODY_RULES:
            if keyword in lowered_body:
                add(name, keyword)

        generator = GENERATOR_RE.search(body)
        if generator:
            add(clip(generator.group(1), 60) or "generator", "meta generator")

        if response.headers.get("X-Application-Context") or "whitelabel error page" in lowered_body:
            add("Spring Boot", "header/error page")

        return marks

    def _grab_certificate(self, ip: str, port: int) -> Dict[str, object]:
        """独立建立 TLS 连接获取服务器证书（requests 的 verify=False 不改动证书校验配置）"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        info: Dict[str, object] = {}
        with socket.create_connection((ip, port), timeout=self.timeout) as raw:
            with context.wrap_socket(raw, server_hostname=ip) as tls:
                info["version"] = tls.version()
                cipher = tls.cipher()
                info["cipher"] = cipher[0] if cipher else None
                der = tls.getpeercert(binary_form=True)

        if not der:
            return info

        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
        except ImportError:
            info["note"] = "未安装 cryptography，仅记录 TLS 版本"
            return info

        cert = x509.load_der_x509_certificate(der)
        common_name = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
        issuer_cn = [a.value for a in cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)]

        dns_names: List[str] = []
        ip_addresses: List[str] = []
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            dns_names = list(san.get_values_for_type(x509.DNSName))[:20]
            ip_addresses = [str(value) for value in san.get_values_for_type(x509.IPAddress)][:20]
        except x509.ExtensionNotFound:
            pass

        not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after

        info.update(
            {
                "subject_cn": common_name[0] if common_name else None,
                "issuer_cn": issuer_cn[0] if issuer_cn else None,
                "dns_names": dns_names,
                "ip_addresses": ip_addresses,
                "not_valid_before": not_before.isoformat() if not_before else None,
                "not_valid_after": not_after.isoformat() if not_after else None,
                "serial_number": str(cert.serial_number),
                "self_signed": cert.subject == cert.issuer,
            }
        )
        return info
