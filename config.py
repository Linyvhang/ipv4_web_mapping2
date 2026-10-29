# config.py
"""全项目统一配置入口。

三层扫描（L1 masscan / L2 nmap / L3 插件）以及所有建表脚本
都从这里读取数据库与扫描参数，修改密码只需改本文件。
"""

import sys
import io

# 使用 UTF-8 输出（Windows PowerShell 下避免中文乱码）
if sys.stdout.encoding != 'UTF-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# ===================== 数据库配置 =====================
DB_HOST = "localhost"
DB_PORT = 3306
DB_USER = "root"
DB_PASSWORD = "123456"      # ← 本机 MySQL 密码不同时改这里
DB_NAME = "ipv4scan"

# pymysql 连接参数（L2 / L3 / 建表脚本共用）
DB_CONFIG = {
    "host": DB_HOST,
    "port": DB_PORT,
    "user": DB_USER,
    "password": DB_PASSWORD,
    "database": DB_NAME,
    "charset": "utf8mb4",
    "autocommit": False,
}

# ===================== 扫描配置 =====================
SCAN_ROUND = 1              # 当前扫描轮次，对应 active_host.scan_round
SCAN_PORTS = [80, 443]      # L1 masscan 探测端口
MASSCAN_RATE = "100000"     # masscan 发包速率（包/秒）

# L1 结果分批入库大小、令牌桶限速（供 scheduler.py 使用）
BATCH_SIZE = 1024
SCAN_RATE_LIMIT = 1000


# ===================== IP 转换 =====================
def ip_to_uint32(ip: str) -> int:
    parts = ip.split('.')
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])


def uint32_to_ip(num: int) -> str:
    return f"{(num >> 24) & 0xFF}.{(num >> 16) & 0xFF}.{(num >> 8) & 0xFF}.{num & 0xFF}"
