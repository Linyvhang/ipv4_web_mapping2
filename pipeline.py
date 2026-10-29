#!/usr/bin/env python3
"""pipeline.py —— 三层 IPv4 资产扫描统一入口。

用法:
    python pipeline.py init                 # 初始化数据库与全部表（L1 + L2 + L3）
    python pipeline.py status               # 查看当前各表数据量、待扫描任务
    python pipeline.py l1 --cidr 1.0.0.0/9  # 第一层：masscan 发现存活主机
    python pipeline.py l2                   # 第二层：nmap 识别服务
    python pipeline.py l3                   # 第三层：插件式深度探测
    python pipeline.py all                  # 依次执行 init -> l1 -> l2 -> l3
"""

import argparse
import shutil
import sys

import pymysql

import config

DETAIL_TABLES = (
    "web_service_detail",
    "ssh_service_detail",
    "db_service_detail",
    "rdp_service_detail",
    "iot_service_detail",
)


# ===================== 数据库辅助 =====================

def existing_tables(cursor):
    cursor.execute("SHOW TABLES")
    return {row[0] for row in cursor.fetchall()}


def count(cursor, sql, params=()):
    try:
        cursor.execute(sql, params)
        return cursor.fetchone()[0]
    except Exception:
        return None


def column_exists(cursor, table, column):
    cursor.execute(
        """SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND COLUMN_NAME = %s""",
        (table, column),
    )
    return cursor.fetchone()[0] > 0


# ===================== 各阶段命令 =====================

def cmd_init():
    try:
        from init_database import init_database
        from init_service_instance import create_table
        from init_l3_tables import init_l3_tables
    except ImportError as exc:
        print(f"[×] 缺少依赖或模块: {exc}")
        print("    依赖安装: pip install pymysql aiomysql mysql-connector-python requests cryptography")
        return 1

    if not init_database():
        return 1
    if not create_table(auto_confirm=True):
        return 1
    if not init_l3_tables():
        return 1

    print("\n[✓] 三层数据库初始化完成")
    return 0


def cmd_status():
    try:
        conn = pymysql.connect(**config.DB_CONFIG)
    except Exception as exc:
        print(f"[×] 数据库连接失败: {exc}")
        print("    请检查 MySQL 是否运行，并修改 config.py 中的 DB_PASSWORD")
        return 1

    try:
        with conn.cursor() as cursor:
            tables = existing_tables(cursor)

            print("=" * 66)
            print(f"  数据库: {config.DB_NAME} @ {config.DB_HOST}:{config.DB_PORT}")
            print(f"  当前轮次: {config.SCAN_ROUND}")
            print("=" * 66)

            print("\n[基础表]")
            for table in ("ipv4_subnet_l1", "active_host", "service_instance_l2"):
                if table in tables:
                    print(f"  {table:<22} {count(cursor, f'SELECT COUNT(*) FROM {table}')} 条")
                else:
                    print(f"  {table:<22} 未创建")

            if "service_instance_l2" in tables:
                print("\n[L2 服务实例状态]  0=未完成 1=完成 2=异常")
                cursor.execute("SELECT scan_status, COUNT(*) FROM service_instance_l2 "
                               "GROUP BY scan_status ORDER BY scan_status")
                for status, rows in cursor.fetchall():
                    print(f"  scan_status={status}  {rows} 条")

                if column_exists(cursor, "service_instance_l2", "l3_scan_status"):
                    print("\n[L3 深度扫描状态]  0=待扫描 1=完成 2=异常")
                    cursor.execute("SELECT l3_scan_status, COUNT(*) FROM service_instance_l2 "
                                   "GROUP BY l3_scan_status ORDER BY l3_scan_status")
                    for status, rows in cursor.fetchall():
                        print(f"  l3_scan_status={status}  {rows} 条")

                    print("\n[待 L3 扫描的服务类型]")
                    cursor.execute(
                        """SELECT service_type, COUNT(*) FROM service_instance_l2
                           WHERE scan_status = 1 AND l3_scan_status = 0
                           GROUP BY service_type ORDER BY COUNT(*) DESC"""
                    )
                    pending = cursor.fetchall()
                    if pending:
                        for service_type, rows in pending:
                            print(f"  {(service_type or 'unknown'):<10} {rows} 条")
                    else:
                        print("  无（所有已完成 L2 的服务都已处理或尚未产生）")
                else:
                    print("\n[!] service_instance_l2 缺少 l3_scan_status 字段，请运行: python pipeline.py init")

            print("\n[L3 结果表]")
            for table in DETAIL_TABLES:
                if table in tables:
                    print(f"  {table:<22} {count(cursor, f'SELECT COUNT(*) FROM {table}')} 条")
                else:
                    print(f"  {table:<22} 未创建")

            print("=" * 66)
    finally:
        conn.close()
    return 0


def cmd_l1(args):
    if not shutil.which("masscan"):
        print("[×] 未找到 masscan，请安装并加入 PATH（Windows 还需要 Npcap）")
        return 1

    from run_l1_scan import main as l1_main

    return l1_main([
        "--cidr", args.cidr,
        "--round", str(args.round if args.round is not None else config.SCAN_ROUND),
        "--rate", str(args.rate),
    ])


def cmd_l2(args):
    if not shutil.which("nmap"):
        print("[×] 未找到 nmap，请安装并加入 PATH")
        return 1

    from l2_scan import main as l2_main

    argv = ["--round", str(args.round if args.round is not None else config.SCAN_ROUND)]
    if args.workers:
        argv += ["--workers", str(args.workers)]
    if args.batch_size:
        argv += ["--batch-size", str(args.batch_size)]
    if args.target:
        argv += ["--target", args.target]
    return l2_main(argv)


def cmd_l3(args):
    from l3_scan import main as l3_main

    argv = []
    if args.limit:
        argv += ["--limit", str(args.limit)]
    if args.types:
        argv += ["--types", args.types]
    if args.workers:
        argv += ["--workers", str(args.workers)]
    if args.round is not None:
        argv += ["--round", str(args.round)]
    return l3_main(argv)


def cmd_all(args):
    steps = []
    if not args.skip_init:
        steps.append(("初始化", cmd_init, ()))
    steps.append(("L1 masscan", cmd_l1, (args,)))
    steps.append(("L2 nmap", cmd_l2, (args,)))
    steps.append(("L3 深度探测", cmd_l3, (args,)))

    for index, (name, func, func_args) in enumerate(steps, 1):
        print(f"\n{'#' * 66}\n#  [{index}/{len(steps)}] {name}\n{'#' * 66}")
        code = func(*func_args)
        if code != 0:
            print(f"\n[×] {name} 失败（退出码 {code}），后续阶段已中止")
            return code

    print("\n[✓] 三阶段流水线全部完成")
    return 0


# ===================== 入口 =====================

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="三层 IPv4 资产扫描统一入口（L1 masscan -> L2 nmap -> L3 插件）"
    )
    parser.add_argument("stage", choices=["init", "status", "l1", "l2", "l3", "all"],
                        help="要执行的阶段")
    parser.add_argument("--cidr", default="1.0.0.0/9", help="L1 扫描网段，默认 1.0.0.0/9")
    parser.add_argument("--round", type=int, default=None,
                        help=f"扫描轮次，默认 {config.SCAN_ROUND}")
    parser.add_argument("--rate", default=config.MASSCAN_RATE, help="L1 masscan 速率（包/秒）")
    parser.add_argument("--workers", type=int, default=None, help="L2 批次并发数 / L3 线程数")
    parser.add_argument("--batch-size", type=int, default=None, help="L2 每批 IP 数")
    parser.add_argument("--target", default="", help="L2 直接指定目标，跳过 active_host")
    parser.add_argument("--limit", type=int, default=0, help="L3 最多扫描条数（0=不限）")
    parser.add_argument("--types", default="", help="L3 仅扫描的服务类型，如 web,ssh,db")
    parser.add_argument("--skip-init", action="store_true", help="all 模式下跳过初始化")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.stage == "init":
        return cmd_init()
    if args.stage == "status":
        return cmd_status()
    if args.stage == "l1":
        return cmd_l1(args)
    if args.stage == "l2":
        return cmd_l2(args)
    if args.stage == "l3":
        return cmd_l3(args)
    return cmd_all(args)


if __name__ == "__main__":
    sys.exit(main())
