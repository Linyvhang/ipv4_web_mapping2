# scanner.py
"""L1 第一层：masscan 端口探测。

跨平台说明：
    Linux  : 非 root 运行时自动加 `sudo -n`（需配置免密 sudo，否则直接报错而不是卡在密码输入）
    Windows: 直接调用 PATH 中的 masscan.exe（需安装 Npcap）
"""

import asyncio
import json
import os
import shutil
import tempfile

from config import SCAN_PORTS, MASSCAN_RATE

# 临时结果统一放在系统临时目录，兼容 Windows / Linux
OUTPUT_FILE = os.path.join(tempfile.gettempdir(), "masscan_result.json")


def _port_spec(ports) -> str:
    """端口参数既支持 "80,443" 字符串，也支持 [80, 443] 列表"""
    if not ports:
        return ",".join(map(str, SCAN_PORTS))
    if isinstance(ports, str):
        return ports
    return ",".join(map(str, ports))


def _privilege_prefix():
    """Linux 下 masscan 需要 root：优先直接运行，否则 sudo -n（免密）"""
    if os.name == "nt":
        return []
    try:
        if os.geteuid() == 0:
            return []
    except AttributeError:
        return []
    return ["sudo", "-n"]


async def run_masscan(cidr, ports=None, rate=None, output=None):
    """执行 masscan 并返回 JSON 结果文件路径"""
    masscan = shutil.which("masscan")
    if not masscan:
        raise RuntimeError(
            "未找到 masscan：请安装并加入 PATH（Windows 还需安装 Npcap/WinPcap）"
        )

    output = output or OUTPUT_FILE
    if os.path.exists(output):
        os.remove(output)

    cmd = _privilege_prefix() + [
        masscan, cidr,
        "-p", _port_spec(ports),
        "--rate", str(rate or MASSCAN_RATE),
        "-oJ", output,
    ]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        message = (stderr or stdout).decode("utf-8", "ignore").strip()
        raise RuntimeError(f"masscan 执行失败（returncode={proc.returncode}）: {message[:500]}")

    return output


def parse_masscan_result(path):
    """解析 masscan JSON，返回 IP 列表"""
    if not os.path.exists(path):
        raise RuntimeError(f"masscan 结果文件不存在: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return [item["ip"] for item in data if item.get("ip")]
