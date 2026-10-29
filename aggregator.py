# aggregator.py
"""L1 结果聚合：去重、分批写入 active_host、汇总 ipv4_subnet_l1。"""

import asyncio
import time
from datetime import datetime

from config import SCAN_ROUND


class L1Aggregator:
    def __init__(self, cidr, total_ip_count, db_manager, flush_interval=9999999,
                 scan_round=SCAN_ROUND):
        self.cidr = cidr
        self.total_ip_count = total_ip_count
        self.reachable_ips = set()
        self.db = db_manager
        self.flush_interval = flush_interval
        self.scan_round = scan_round

        self.scanned_ips = 0
        self._last_flush = 0
        self._start_ts = time.time()
        self._lock = asyncio.Lock()
        self.start_time = datetime.utcnow()
        self.end_time = None

    async def merge_batch(self, ip_list):
        async with self._lock:
            self.scanned_ips += len(ip_list)
            new_ips = set(ip_list) - self.reachable_ips
            if not new_ips:
                return
            self.reachable_ips.update(new_ips)

            await self.db.bulk_save_active_hosts(list(new_ips), scan_round=self.scan_round)

            if len(self.reachable_ips) - self._last_flush >= self.flush_interval:
                await self.db.save_l1_result(self.summary())
                self._last_flush = len(self.reachable_ips)

    def finalize(self):
        if self.end_time is None:
            self.end_time = datetime.utcnow()

    def summary(self):
        return {
            "cidr": self.cidr,
            "total_ip": self.total_ip_count,
            "reachable_ip_count": len(self.reachable_ips),
            "scan_start": self.start_time,
            "scan_end": self.end_time or datetime.utcnow(),
            "scan_round": self.scan_round,
        }
