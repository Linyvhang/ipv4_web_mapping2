#!/usr/bin/env python3
"""
l3_scan.py
第三层调度入口：基于 service_instance_l2 的插件式服务深度探测。

流程（对应《主体思路 2.0》5.3 扫描调度策略）：
    1. 从 service_instance_l2 读取 scan_status=1 且 l3_scan_status=0 的服务实例
    2. 按 service_type 路由到对应插件（web/ssh/db/rdp，其余类型走通用 Banner 插件）
    3. 按"服务类型优先级 + 置信度"排序，多线程并发执行
    4. 结果写入各 service_type 对应的 detail 表，并回写 l3_scan_status

用法：
    python init_l3_tables.py                  # 首次运行前建表
    python l3_scan.py                         # 扫描全部待处理服务
    python l3_scan.py --types web,ssh         # 只扫描指定服务类型
    python l3_scan.py --limit 50 --workers 8  # 小批量试跑
    python l3_scan.py --round 1               # 只扫描第 1 轮 L1 发现的活跃主机
"""

import argparse
import io
import json
import os
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import l3_store
from l3_plugins import list_plugins, load_plugin
from l3_plugins.base import STATUS_DONE, STATUS_ERROR, PluginResult

WORK_DIR = "l3_workspace"
SUMMARY_FILE = os.path.join(WORK_DIR, "l3_summary.json")

# 每个线程独立数据库连接（pymysql 连接非线程安全）
_local = threading.local()
_connections = []
_conn_lock = threading.Lock()


def get_connection():
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = l3_store.connect()
        _local.conn = conn
        with _conn_lock:
            _connections.append(conn)
    return conn


def close_connections():
    with _conn_lock:
        for conn in _connections:
            try:
                conn.close()
            except Exception:
                pass
        _connections.clear()


def scan_one(target) -> dict:
    """处理单个服务实例：插件探测 -> detail 入库 -> 回写调度状态"""
    plugin = load_plugin(target.service_type)
    start = time.time()

    try:
        result = plugin.scan(target)
    except Exception as exc:  # 插件内部异常统一转为异常状态
        result = PluginResult(
            plugin.plugin_name,
            STATUS_ERROR,
            {},
            f"{type(exc).__name__}: {exc}",
        )

    elapsed = time.time() - start
    stored = True
    conn = get_connection()
    try:
        l3_store.save_result(conn, target, plugin, result)
        conn.commit()
    except Exception as exc:
        stored = False
        conn.rollback()
        error = f"入库失败: {type(exc).__name__}: {exc}"
        try:
            l3_store.mark_failed(conn, target.service_instance_id)
            conn.commit()
        except Exception as mark_exc:
            conn.rollback()
            error += f"; 状态回写失败: {mark_exc}"
        result.error_message = error[:255]

    return {
        "type": (target.service_type or "unknown").lower(),
        "endpoint": target.endpoint,
        "plugin": plugin.plugin_name,
        "status": result.scan_status,
        "stored": stored,
        "elapsed": elapsed,
        "error": result.error_message,
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="第三层：插件式服务深度探测")
    parser.add_argument("--limit", type=int, default=0, help="最多扫描 N 条服务实例（0=不限）")
    parser.add_argument("--types", type=str, default="", help="仅扫描指定 service_type，逗号分隔，例如 web,ssh,db")
    parser.add_argument("--workers", type=int, default=8, help="并发线程数（默认 8）")
    parser.add_argument("--round", dest="scan_round", type=int, default=None, help="仅扫描指定 L1 轮次")
    return parser.parse_args(argv)


def progress_line(index: int, total: int, stats: dict) -> str:
    if stats["status"] == STATUS_DONE:
        state = "完成"
    else:
        state = "异常"
    if not stats["stored"]:
        state += "/入库失败"
    detail = f"  {stats['error'][:100]}" if stats["error"] else ""
    return (
        f"[{index:>5}/{total}] {stats['type']:<7} {stats['endpoint']:<22} "
        f"{stats['plugin']:<16} {state:<10} {stats['elapsed']:.2f}s{detail}"
    )


def summarize(results, elapsed):
    by_type = {}
    by_plugin = {}
    failed = []

    for item in results:
        type_stats = by_type.setdefault(item["type"], {"total": 0, "done": 0, "error": 0, "store_failed": 0})
        type_stats["total"] += 1
        type_stats["done" if item["status"] == STATUS_DONE else "error"] += 1
        if not item["stored"]:
            type_stats["store_failed"] += 1

        plugin_stats = by_plugin.setdefault(item["plugin"], {"total": 0, "done": 0, "error": 0})
        plugin_stats["total"] += 1
        plugin_stats["done" if item["status"] == STATUS_DONE else "error"] += 1

        if item["error"] and len(failed) < 50:
            failed.append({k: item[k] for k in ("type", "endpoint", "plugin", "error")})

    return {
        "total": len(results),
        "done": sum(1 for r in results if r["status"] == STATUS_DONE),
        "error": sum(1 for r in results if r["status"] != STATUS_DONE),
        "store_failed": sum(1 for r in results if not r["stored"]),
        "elapsed_seconds": round(elapsed, 2),
        "by_type": by_type,
        "by_plugin": by_plugin,
        "failed_samples": failed,
    }


def print_summary(summary):
    print("\n" + "=" * 72)
    print("  第三层扫描完成")
    print("=" * 72)
    print(f"  服务实例: {summary['total']}   完成: {summary['done']}   "
          f"异常: {summary['error']}   入库失败: {summary['store_failed']}")
    print(f"  总耗时:   {summary['elapsed_seconds']}s")
    print("\n  按服务类型：")
    for service_type, stats in sorted(summary["by_type"].items(), key=lambda x: -x[1]["total"]):
        print(f"    {service_type:<10} 共 {stats['total']:>5}  完成 {stats['done']:>5}  "
              f"异常 {stats['error']:>5}  入库失败 {stats['store_failed']:>3}")
    print("\n  按插件：")
    for plugin_name, stats in sorted(summary["by_plugin"].items(), key=lambda x: -x[1]["total"]):
        print(f"    {plugin_name:<18} 共 {stats['total']:>5}  完成 {stats['done']:>5}  异常 {stats['error']:>5}")
    print(f"\n  调度摘要: {SUMMARY_FILE}")
    print("=" * 72)


def save_summary(summary, args):
    os.makedirs(WORK_DIR, exist_ok=True)
    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "scan_round": args.scan_round,
        "types_filter": args.types or "all",
        "workers": args.workers,
        **summary,
    }
    with open(SUMMARY_FILE, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)


def main(argv=None):
    args = parse_args(argv)
    service_types = [t.strip() for t in args.types.split(",") if t.strip()] or None
    limit = args.limit or None

    print("  L3 第三层扫描（插件式服务深度探测）")
    print(f"  时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("  插件路由: " + ", ".join(f"{p.service_type}→{p.plugin_name}" for p in list_plugins())
          + ", 其他→banner-grab")

    try:
        pending = l3_store.fetch_pending(
            limit=limit, service_types=service_types, scan_round=args.scan_round
        )
    except l3_store.L3StoreError as exc:
        print(f"[×] {exc}")
        return 1

    if not pending:
        print("\n[i] 没有待第三层扫描的服务实例。")
        print("    请确认: 1) 已执行 init_l3_tables.py 建表/补字段")
        print("             2) service_instance_l2 中存在 scan_status=1 的服务")
        return 0

    distribution = Counter((t.service_type or "unknown").lower() for t in pending)
    print(f"\n  待扫描服务实例: {len(pending)}")
    print("  类型分布: " + ", ".join(f"{name}={count}" for name, count in distribution.items()))
    print()

    total = len(pending)
    results = []
    started = time.time()

    executor = ThreadPoolExecutor(max_workers=max(1, args.workers))
    try:
        futures = [executor.submit(scan_one, target) for target in pending]
        for index, future in enumerate(as_completed(futures), 1):
            try:
                stats = future.result()
            except Exception as exc:  # 理论上 scan_one 已兜底
                stats = {
                    "type": "unknown", "endpoint": "-", "plugin": "-",
                    "status": 2, "stored": False, "elapsed": 0.0,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            results.append(stats)
            print(progress_line(index, total, stats))
    except KeyboardInterrupt:
        print("\n[!] 用户中断，正在取消未开始的任务...")
        executor.shutdown(wait=False, cancel_futures=True)
        return 130
    finally:
        executor.shutdown(wait=True)
        close_connections()

    elapsed = time.time() - started
    summary = summarize(results, elapsed)
    print_summary(summary)
    save_summary(summary, args)
    return 0


if __name__ == "__main__":
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.exit(main())
