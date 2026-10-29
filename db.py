# db.py
import aiomysql
from datetime import datetime
from config import (
    DB_HOST, DB_PORT, DB_USER, DB_PASSWORD,
    DB_NAME, ip_to_uint32, uint32_to_ip, SCAN_ROUND
)


class DatabaseManager:
    def __init__(self):
        self.pool = None

    async def connect(self):
        if self.pool is None:
            self.pool = await aiomysql.create_pool(
                host=DB_HOST, port=DB_PORT,
                user=DB_USER, password=DB_PASSWORD,
                db=DB_NAME, autocommit=False,
                maxsize=20, charset="utf8mb4"
            )
            print(f"✅ 已连接到数据库: {DB_NAME}")

    async def close(self):
        if self.pool:
            self.pool.close()
            await self.pool.wait_closed()
            print("✅ 数据库连接池已关闭")

    # ================= ipv4_subnet_l1 =================
    async def save_l1_result(self, summary):
        await self.connect()
        cidr = summary["cidr"]
        ip_part, prefix_part = cidr.split("/")

        network_address = ip_to_uint32(ip_part)
        prefix_len = int(prefix_part)
        scan_round = summary.get("scan_round", SCAN_ROUND)
        last_scan_time = summary.get("scan_end") or datetime.utcnow()
        scanner_node = summary.get("scanner_node", "masscan")

        async with self.pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cur:
                try:
                    await cur.execute(
                        "SELECT id FROM ipv4_subnet_l1 WHERE network_address=%s AND scan_round=%s",
                        (network_address, scan_round)
                    )
                    row = await cur.fetchone()

                    if row:
                        await cur.execute(
                            """UPDATE ipv4_subnet_l1
                               SET scan_status=2, alive_host_count=%s,
                                   last_scan_time=%s, scanner_node=%s,
                                   updated_at=CURRENT_TIMESTAMP
                               WHERE id=%s""",
                            (summary["reachable_ip_count"], last_scan_time, scanner_node, row["id"])
                        )
                    else:
                        await cur.execute(
                            """INSERT INTO ipv4_subnet_l1
                               (network_address, prefix_len, scan_status, scan_round,
                                alive_host_count, last_scan_time, scanner_node)
                               VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                            (network_address, prefix_len, 2, scan_round,
                             summary["reachable_ip_count"], last_scan_time, scanner_node)
                        )
                    await conn.commit()
                    print(f"✅ 子网扫描结果已保存: {cidr}")
                except Exception as e:
                    await conn.rollback()
                    print(f"❌ 保存 ipv4_subnet_l1 失败: {e}")
                    raise

    # ================= active_host =================
    async def bulk_save_active_hosts(self, ip_list, alive_type=1, scan_round=1, scanner_node="masscan"):
        if not ip_list:
            return
        await self.connect()
        now = datetime.utcnow()
        values = [(ip_to_uint32(ip), alive_type, now, now, scan_round, scanner_node) for ip in ip_list]

        async with self.pool.acquire() as conn:
            async with conn.cursor() as cur:
                try:
                    await cur.executemany(
                        """INSERT INTO active_host
                           (ip_address, alive_type, first_seen, last_seen, scan_round, scanner_node)
                           VALUES (%s,%s,%s,%s,%s,%s) AS new
                           ON DUPLICATE KEY UPDATE
                           last_seen=new.last_seen, updated_at=CURRENT_TIMESTAMP""",
                        values
                    )
                    await conn.commit()
                    print(f"✅ active_host 写入 {len(ip_list)} 条")
                except Exception as e:
                    await conn.rollback()
                    print(f"❌ active_host 写入失败: {e}")
                    raise


db = DatabaseManager()