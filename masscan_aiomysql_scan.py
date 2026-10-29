#!/usr/bin/env python3
"""兼容旧入口：原本独立的 masscan 扫描脚本。

为避免两套 L1 实现（旧脚本写死 /tmp、sudo、1.0.0.0/9），
此处直接转发到统一实现 run_l1_scan.py，参数与 pipeline.py l1 一致。

用法:
    python masscan_aiomysql_scan.py --cidr 1.0.0.0/9 --round 1
"""

import sys

from run_l1_scan import main

if __name__ == "__main__":
    sys.exit(main())
