# run_l1_scan.py
"""L1 第一层扫描：masscan 全网段端口探测 -> active_host / ipv4_subnet_l1。

独立运行:
    python run_l1_scan.py --cidr 1.0.0.0/9 --round 1
统一入口:
    python pipeline.py l1 --cidr 1.0.0.0/9
"""

import argparse
import asyncio
import ipaddress
import signal

from aggregator import L1Aggregator
from config import MASSCAN_RATE, SCAN_PORTS, SCAN_ROUND
from db import db
from scanner import parse_masscan_result, run_masscan


def handle_sigpipe(signum, frame):
    pass


if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, handle_sigpipe)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="L1 第一层：masscan 存活主机发现")
    parser.add_argument("--cidr", default="1.0.0.0/9", help="扫描网段，默认 1.0.0.0/9")
    parser.add_argument("--round", type=int, default=SCAN_ROUND, help="扫描轮次（写入 scan_round）")
    parser.add_argument("--ports", default="", help="探测端口，逗号分隔，默认取 config.SCAN_PORTS")
    parser.add_argument("--rate", default=MASSCAN_RATE, help="masscan 发包速率（包/秒）")
    parser.add_argument("--batch-size", type=int, default=1024, help="入库分批大小")
    return parser.parse_args(argv)


async def run_scan(cidr, scan_round, ports, rate, batch_size):
    network = ipaddress.IPv4Network(cidr, strict=False)

    await db.connect()
    print(f"[INFO] 开始 Masscan 扫描: {cidr}（端口 {ports or ','.join(map(str, SCAN_PORTS))}，"
          f"速率 {rate}，轮次 {scan_round}）")

    json_file = await run_masscan(cidr, ports=ports or None, rate=rate)
    ips = sorted(set(parse_masscan_result(json_file)))
    print(f"[INFO] Masscan 发现存活 IP: {len(ips)}")

    aggregator = L1Aggregator(
        cidr=cidr,
        total_ip_count=network.num_addresses,
        db_manager=db,
        scan_round=scan_round,
    )

    for index in range(0, len(ips), batch_size):
        await aggregator.merge_batch(ips[index:index + batch_size])

    aggregator.finalize()
    await db.save_l1_result(aggregator.summary())
    await db.close()

    print(f"[INFO] L1 完成：{cidr} 存活 {len(ips)} 个，已写入 active_host / ipv4_subnet_l1")


def main(argv=None):
    args = parse_args(argv)
    try:
        asyncio.run(run_scan(
            cidr=args.cidr,
            scan_round=args.round,
            ports=args.ports,
            rate=args.rate,
            batch_size=args.batch_size,
        ))
        return 0
    except KeyboardInterrupt:
        print("\n[INFO] 扫描中断")
        return 130
    except Exception as exc:
        print(f"[×] L1 扫描失败: {exc}")
        print("    请检查 config.py 数据库配置，以及 masscan 是否安装并加入 PATH")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
