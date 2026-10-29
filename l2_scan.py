import argparse
import ipaddress
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import pymysql

from config import DB_CONFIG, SCAN_ROUND

TARGET = ""

# 分批并发
BATCH_IP_COUNT = 500       # 每批 IP 数量
MAX_WORKERS = 4            # 线程数

# ---- nmap 参数 ----
NMAP_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995,1433,3306,3389,5432,6379,8080,8443,9200,27017"
#NMAP_TIMING = "-T4" #很容易被防火墙放掉
NMAP_EXTRA_ARGS = [
    "-Pn",
    "-sV",
    "-sT",
    "--version-light",
    "--max-retries", "1",
    "--host-timeout", "5s",
]

# ---- 路径 ----
WORK_DIR = "l2_workspace"
IP_LIST_FILE = os.path.join(WORK_DIR, "l2_targets.txt")
NMAP_XML_PATTERN = os.path.join(WORK_DIR, "l2_result_{batch_id}.xml")
NMAP_TXT_PATTERN = os.path.join(WORK_DIR, "l2_result_{batch_id}.txt")

# 入库批次
DB_BATCH_SIZE = 500

# 端口映射
PORT_SERVICE_MAP = {
    21:    "ftp",
    22:    "ssh",
    23:    "telnet",
    25:    "mail",
    53:    "dns",
    80:    "web",
    110:   "mail",
    143:   "mail",
    443:   "web",
    465:   "mail",
    587:   "mail",
    993:   "mail",
    995:   "mail",
    3306:  "db",
    3389:  "rdp",
    5432:  "db",
    6379:  "db",
    8080:  "web",
    8443:  "web",
    9200:  "db",
    27017: "db",
}

SERVICE_NAME_MAP = {
    "http":            "web",
    "https":           "web",
    "ssl/http":        "web",
    "http-proxy":      "web",
    "http-alt":        "web",
    "ssh":             "ssh",
    "telnet":          "telnet",
    "ftp":             "ftp",
    "smtp":            "mail",
    "pop3":            "mail",
    "imap":            "mail",
    "dns":             "dns",
    "domain":          "dns",
    "mysql":           "db",
    "mariadb":         "db",
    "postgresql":      "db",
    "postgres":        "db",
    "redis":           "db",
    "mongodb":         "db",
    "elasticsearch":   "db",
    "rdp":             "rdp",
    "ms-wbt-server":   "rdp",
    "smb":             "file",
    "netbios":         "file",
    "netbios-ssn":     "file",
    "microsoft-ds":    "file",
}

#将提取到的长整型ip转换成三点划分四位ip
def ip_int_to_str(ip_int: int) -> str:
    return ipaddress.IPv4Address(ip_int).exploded

def ip_str_to_int(ip_str: str) -> int:
    return int(ipaddress.IPv4Address(ip_str))

def classify_service(port: int, service_name: str) -> str:
    if service_name:
        s = service_name.lower()
        for kw, stype in SERVICE_NAME_MAP.items():
            if kw in s:
                return stype
    return PORT_SERVICE_MAP.get(port, "unknown")

def extract_banner(service_elem) -> str:
    if service_elem is None:
        return ""
    product   = service_elem.get("product", "") or ""
    version   = service_elem.get("version", "") or ""
    extrainfo = service_elem.get("extrainfo", "") or ""
    parts = [p for p in [product, version, extrainfo] if p]
    banner = " ".join(parts).strip()
    if len(banner) > 255:
        banner = banner[:252] + "..."
    return banner

def calc_confidence(service_elem, port_open: bool) -> float:
    if not port_open:
        return 0.0
    if service_elem is None:
        return 0.5
    name    = service_elem.get("name", "") or ""
    product = service_elem.get("product", "") or ""
    if name and product:
        return 0.9
    elif name:
        return 0.7
    else:
        return 0.5

# XML完整性修复
# 防止中断xml报错
def fix_incomplete_nmap_xml(xml_path: str) -> str:
    """检查 nmap XML 是否完整，不完整则自动补齐结束标签"""
    if not os.path.exists(xml_path):
        return xml_path

    with open(xml_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read().strip()

    if content.endswith("</nmaprun>"):
        return xml_path

    print(f"XML 不完整，正在自动修复: {os.path.basename(xml_path)}")

    # 方法1：lxml recover
    try:
        from lxml import etree
        parser = etree.XMLParser(recover=True, encoding="utf-8")
        tree = etree.parse(xml_path, parser=parser)
        if tree.getroot() is not None:
            fixed_path = xml_path + ".fixed.xml"
            tree.write(fixed_path, xml_declaration=True, encoding="utf-8",
                       standalone=False)
            print(f" xml recover 修复成功")
            return fixed_path
    except ImportError:
        pass
    except Exception as e:
        print(f"    [~] lxml recover 失败 ({e})，尝试手动补标签")

    # 方法2：手动补标签
    tags_needed = []
    if content.count("<port ") > content.count("</port>"):
        tags_needed.append("</port>")
    if content.count("<ports>") > content.count("</ports>"):
        tags_needed.append("</ports>")
    if content.count("<host>") > content.count("</host>"):
        tags_needed.append("</host>")
    for tag in tags_needed:
        content += f"\n{tag}"
    if "</runstats>" not in content:
        content += "\n</runstats>"
    if not content.endswith("</nmaprun>"):
        content += "\n</nmaprun>\n"

    fixed_path = xml_path + ".fixed.xml"
    with open(fixed_path, "w", encoding="utf-8") as f:
        f.write(content)

    try:
        ET.parse(fixed_path)
        print(f"手动补标签修复成功")
    except ET.ParseError as e:
        print(f"手动修复后仍无法解析: {e}")

    return fixed_path

# 从 active_host 表读取存活 IP

def build_host_map_from_db(scan_round: int) -> dict:
    """从 active_host 表读取存活 IP"""
    conn = pymysql.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, ip_address FROM active_host WHERE scan_round = %s ORDER BY ip_address",
        (scan_round,)
    )
    mapping = {}
    for row in cursor.fetchall():
        host_id, ip_int = row
        mapping[ip_int] = host_id
    cursor.close()
    conn.close()
    print(f" 从 active_host 读取到 {len(mapping)} 个存活主机 (scan_round={scan_round})")
    return mapping

def build_host_map_from_target(target_str: str) -> dict:
    """从 TARGET 配置解析 IP → host_map"""
    mapping = {}
    targets = [t.strip() for t in target_str.split(",") if t.strip()]
    for t in targets:
        if "/" in t:
            net = ipaddress.ip_network(t, strict=False)
            for ip in net.hosts():
                mapping[int(ip)] = 0
        else:
            mapping[int(ipaddress.IPv4Address(t))] = 0
    print(f"从 TARGET 配置解析到 {len(mapping)} 个 IP")
    return mapping

def write_ip_list(host_map: dict, filepath: str):
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        for ip_int in host_map:
            f.write(ip_int_to_str(ip_int) + "\n")
    print(f"IP 列表已写入: {filepath} ({len(host_map)} 行)")

# 单批次处理

def process_batch(batch_id: int, ip_list_file: str, host_map: dict,
                  conn_pool_lock: threading.Lock) -> dict:
    """处理一个批次：nmap 扫描 → 解析 XML → 立即入库"""
    xml_path = NMAP_XML_PATTERN.format(batch_id=batch_id)
    txt_path = NMAP_TXT_PATTERN.format(batch_id=batch_id)
    stats = {
        "batch_id": batch_id, "ips": 0, "scanned": False,
        "records": 0, "inserted": 0, "elapsed": 0.0, "error": None,
    }

    try:
        with open(ip_list_file, "r") as f:
            stats["ips"] = sum(1 for _ in f)
    except Exception:
        pass

    start = time.time()
    print(f"  [Batch {batch_id}] 开始处理 ({stats['ips']} 个 IP)")

    try:
        scan_ok = run_nmap_batch(ip_list_file, xml_path, txt_path, batch_id)
        if not scan_ok:
            stats["error"] = "nmap 扫描失败"
            stats["elapsed"] = time.time() - start
            print(f"  [Batch {batch_id}] nmap 失败 (耗时 {stats['elapsed']:.1f}s)")
            return stats
        stats["scanned"] = True

        fixed_xml = fix_incomplete_nmap_xml(xml_path)
        records = parse_nmap_xml(fixed_xml, host_map)

        if not records:
            stats["elapsed"] = time.time() - start
            print(f"  [Batch {batch_id}] 无开放端口记录 (耗时 {stats['elapsed']:.1f}s)")
            return stats

        stats["records"] = len(records)
        inserted = upsert_service_instances_threadsafe(records, conn_pool_lock)
        stats["inserted"] = inserted
        stats["elapsed"] = time.time() - start
        print(f"  [Batch {batch_id}] 已入库 {inserted}/{len(records)} 条 (耗时 {stats['elapsed']:.1f}s)")

    except Exception as e:
        stats["error"] = str(e)
        stats["elapsed"] = time.time() - start
        print(f"  [Batch {batch_id}] 异常: {e} (耗时 {stats['elapsed']:.1f}s)")

    return stats

def run_nmap_batch(ip_list_file: str, xml_output: str, txt_output: str, batch_id: int) -> bool:
    """单批次 nmap 扫描"""
    nmap = shutil.which("nmap")
    if not nmap:
        print(f"  [Batch {batch_id}] [!] 未找到 nmap，请先安装并加入 PATH")
        return False

    cmd = [
        nmap,
        "-iL", ip_list_file,
        "-p", NMAP_PORTS,
        "-oX", xml_output,
        "-oN", txt_output,
        #NMAP_TIMING,
        *NMAP_EXTRA_ARGS,
    ]

    print(f"  [Batch {batch_id}] → nmap -iL ... -p {NMAP_PORTS} ...")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"  [Batch {batch_id}] [!] nmap returncode={result.returncode}")
        if result.stderr:
            print(f"  [Batch {batch_id}] [!] stderr: {result.stderr[:200]}")
        return os.path.exists(xml_output)

    return True


# 数据库连接池（不设上限，池容量由 init_db_pool 的 pool_size 决定）
_db_pool = queue.Queue()
_db_lock = threading.Lock()
_db_initialized = False

def init_db_pool(pool_size: int):
    global _db_initialized, MAX_WORKERS
    MAX_WORKERS = pool_size
    with _db_lock:
        if _db_initialized:
            return
        for i in range(pool_size):
            conn = pymysql.connect(**DB_CONFIG)
            _db_pool.put(conn)
        _db_initialized = True
        print(f"数据库连接池初始化完成 (size={pool_size})")

def close_db_pool():
    global _db_initialized
    with _db_lock:
        while not _db_pool.empty():
            conn = _db_pool.get()
            try:
                conn.close()
            except Exception:
                pass
        _db_initialized = False
        print("数据库连接池已关闭")

def upsert_service_instances_threadsafe(records: list, lock: threading.Lock) -> int:
    """从连接池取连接，批量 UPSERT，线程安全"""
    conn = _db_pool.get()
    try:
        sql = """
            INSERT INTO service_instance_l2
                (active_host_id, ip_address, port, transport_protocol,
                 service_type, application_proto, banner, confidence,
                 scan_status, scan_time, created_at, updated_at)
            VALUES
                (%(active_host_id)s, %(ip_address)s, %(port)s, %(transport_protocol)s,
                 %(service_type)s, %(application_proto)s, %(banner)s, %(confidence)s,
                 1, NOW(), NOW(), NOW())
            ON DUPLICATE KEY UPDATE
                service_type       = VALUES(service_type),
                application_proto  = VALUES(application_proto),
                banner             = VALUES(banner),
                confidence         = VALUES(confidence),
                scan_status        = 1,
                scan_time          = NOW(),
                updated_at         = NOW()
        """
        total = len(records)
        inserted = 0
        cursor = conn.cursor()
        try:
            for i in range(0, total, DB_BATCH_SIZE):
                batch = records[i:i + DB_BATCH_SIZE]
                with lock:
                    cursor.executemany(sql, batch)
                    conn.commit()
                inserted += len(batch)
        except Exception as e:
            conn.rollback()
            print(f"批次写入异常: {e}")
            raise
        finally:
            cursor.close()
        return inserted
    finally:
        _db_pool.put(conn)

# XML 解析
def parse_nmap_xml(xml_path: str, host_map: dict) -> list:
    """解析 nmap XML，提取所有开放端口的服务信息"""
    if not os.path.exists(xml_path):
        return []

    tree = ET.parse(xml_path)
    root = tree.getroot()
    results = []

    for host_elem in root.iter("host"):
        addr_elem = host_elem.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            addr_elem = host_elem.find("address")
        if addr_elem is None:
            continue

        ip_str = addr_elem.get("addr")
        try:
            ip_int = ip_str_to_int(ip_str)
        except ValueError:
            continue

        if ip_int not in host_map:
            continue

        active_host_id = host_map[ip_int]
        ports_elem = host_elem.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            port_id   = int(port_elem.get("portid"))
            proto     = port_elem.get("protocol", "tcp").lower()
            service_elem = port_elem.find("service")

            service_name = ""
            app_proto    = ""
            if service_elem is not None:
                service_name = service_elem.get("name", "") or ""
                app_proto   = service_name

            banner     = extract_banner(service_elem)
            svc_type   = classify_service(port_id, service_name)
            confidence = calc_confidence(service_elem, port_open=True)

            record = {
                "active_host_id":    active_host_id,
                "ip_address":        ip_int,
                "port":              port_id,
                "transport_protocol": proto,
                "service_type":      svc_type,
                "application_proto":  app_proto[:16] if app_proto else None,
                "banner":            banner if banner else None,
                "confidence":        confidence,
            }
            results.append(record)
    return results

# IP 分批

def split_ip_list(host_map: dict, batch_size: int) -> list:
    """将 host_map 拆分为多个批次文件，返回 [(batch_id, filepath, chunk), ...]"""
    os.makedirs(WORK_DIR, exist_ok=True)
    batches = []
    ip_list = list(host_map.keys())
    batch_id = 0

    for i in range(0, len(ip_list), batch_size):
        chunk = ip_list[i:i + batch_size]
        filepath = os.path.join(WORK_DIR, f"l2_targets_batch_{batch_id}.txt")
        with open(filepath, "w", encoding="utf-8") as f:
            for ip_int in chunk:
                f.write(ip_int_to_str(ip_int) + "\n")
        batches.append((batch_id, filepath, chunk))
        batch_id += 1

    print(f"IP 列表已拆分为 {len(batches)} 个批次 (每批 ≤ {batch_size})")
    return batches

def print_summary(all_stats: list):
    total_ips      = sum(s["ips"] for s in all_stats)
    total_records  = sum(s["records"] for s in all_stats)
    total_inserted = sum(s["inserted"] for s in all_stats)
    errors         = [s for s in all_stats if s["error"]]
    print(f"  总批次数:    {len(all_stats)}")
    print(f"  总 IP 数:    {total_ips}")
    print(f"  总记录数:    {total_records}")
    print(f"  总入库数:    {total_inserted}")
    if errors:
        print(f"  异常批次:    {len(errors)}")
        for e in errors:
            print(f"    - Batch {e['batch_id']}: {e['error']}")

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="L2 第二层：nmap 通用服务识别")
    parser.add_argument("--round", type=int, default=None, help="扫描轮次，对应 active_host.scan_round")
    parser.add_argument("--target", default=None, help="直接指定目标（IP 或 CIDR，逗号分隔），不走 active_host")
    parser.add_argument("--batch-size", type=int, default=None, help="每批 IP 数，默认 500")
    parser.add_argument("--workers", type=int, default=None, help="并发批次数，默认 4")
    parser.add_argument("--ports", default=None, help="nmap 端口列表，默认使用内置常见端口集")
    return parser.parse_args(argv)


def main(argv=None):
    global TARGET, SCAN_ROUND, BATCH_IP_COUNT, MAX_WORKERS, NMAP_PORTS
    args = parse_args(argv)
    if args.round is not None:
        SCAN_ROUND = args.round
    if args.target is not None:
        TARGET = args.target
    if args.batch_size is not None:
        BATCH_IP_COUNT = max(1, args.batch_size)
    if args.workers is not None:
        MAX_WORKERS = max(1, args.workers)
    if args.ports:
        NMAP_PORTS = args.ports

    print("  L2 第二层扫描")
    print(f"  时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  批次大小: {BATCH_IP_COUNT} IP/批")
    print(f"  并发数:   {MAX_WORKERS} 批次并行")
    if TARGET:
        print(f"  扫描目标:  {TARGET}")
    else:
        print(f"  扫描目标:  active_host (scan_round={SCAN_ROUND})")

    # ---- Step 1: 确定扫描目标 ----
    print("确定扫描目标")
    try:
        if TARGET:
            host_map = build_host_map_from_target(TARGET)
        else:
            host_map = build_host_map_from_db(SCAN_ROUND)
    except Exception as exc:
        print(f"[×] 无法获取扫描目标: {exc}")
        print("    请检查 config.py 中的数据库配置，或使用 --target 直接指定目标")
        return 1

    if not host_map:
        print("没有可用的扫描目标，请检查 TARGET 配置或 active_host 表")
        return 1

    write_ip_list(host_map, IP_LIST_FILE)
    print()

    print("拆分 IP 为多个批次")
    batches = split_ip_list(host_map, BATCH_IP_COUNT)
    print()

    # ---- 初始化连接池 ----
    try:
        init_db_pool(MAX_WORKERS)
    except Exception as exc:
        print(f"[×] 数据库连接失败: {exc}")
        print("    请检查 config.py 中的 DB_PASSWORD / 数据库服务是否运行")
        return 1

    print(f"并发执行 {len(batches)} 个批次（workers={MAX_WORKERS}）")
    print()

    write_lock = threading.Lock()
    all_stats = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        for batch_id, ip_file, ip_chunk in batches:
            future = executor.submit(
                process_batch, batch_id, ip_file, host_map, write_lock
            )
            futures[future] = batch_id

        for future in as_completed(futures):
            bid = futures[future]
            try:
                stats = future.result()
                all_stats.append(stats)
            except Exception as e:
                all_stats.append({
                    "batch_id": bid, "ips": 0, "scanned": False,
                    "records": 0, "inserted": 0, "elapsed": 0, "error": str(e)
                })
                print(f"  [Batch {bid}] ✗ 未捕获异常: {e}")

    print_summary(all_stats)

    # ---- 清理 ----
    close_db_pool()
    return 0

# 入口

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n用户中断 (Ctrl+C)")
        print("已完成的批次数据已入库，未完成的批次将被跳过")
        print("重新运行脚本可继续处理剩余 IP")
        try:
            close_db_pool()
        except Exception:
            pass
        sys.exit(1)
