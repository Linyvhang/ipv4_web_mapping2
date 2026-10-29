#!/usr/bin/env python3
"""
init_service_instance.py
根据《主体思路2.0》文档 4.3 节 ServiceInstance 表结构示例，
在数据库 ipv4scan 中创建第二层通用服务发现结果表。

表名: service_instance_l2
功能: 记录在存活主机上发现的各类网络服务实例

用法:
    python init_service_instance.py            # 建表（active_host 缺失时会询问）
    python init_service_instance.py --yes      # 自动确认（供 pipeline.py 调用）
    python init_service_instance.py --drop     # 删除后重建
"""

import argparse
import sys

import pymysql

from config import DB_CONFIG


# ---- 建表 SQL（严格对应文档 4.3 表结构示例 + 4.4 约束索引） ----
CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS service_instance_l2 (
    id               BIGINT       NOT NULL AUTO_INCREMENT COMMENT '服务实例唯一标识',
    active_host_id   BIGINT       NOT NULL                COMMENT '外键，关联 ActiveHost 表的主机 ID',
    ip_address       INT UNSIGNED NOT NULL                COMMENT '冗余存储 IP，便于查询统计和审计',
    port             INT          NOT NULL                COMMENT '服务监听端口号',
    transport_protocol VARCHAR(4) NOT NULL DEFAULT 'tcp' COMMENT 'TCP / UDP',
    service_type     VARCHAR(32)  NOT NULL                COMMENT '服务类型抽象标签 (web/ssh/db/rdp/unknown)',
    application_proto VARCHAR(16) NULL                    COMMENT '初步判定的应用层协议 (http/mysql 等)',
    banner           VARCHAR(255) NULL                    COMMENT '服务响应 Banner 或协议特征，用于辅助确认',
    confidence       FLOAT        DEFAULT 0               COMMENT '服务识别置信度 (0~1)，用于判断识别可靠性',
    scan_status      TINYINT      NOT NULL DEFAULT 0      COMMENT '扫描状态: 0=未完成, 1=完成, 2=异常',
    scan_time        DATETIME     NOT NULL                COMMENT '最近一次扫描时间，便于增量或周期扫描',
    created_at       DATETIME     NOT NULL                COMMENT '记录创建时间',
    updated_at       DATETIME     NOT NULL                COMMENT '最近更新时间',

    PRIMARY KEY (id),

    -- 约束与索引（对应文档 4.5 设计要点）
    UNIQUE KEY uniq_host_port (active_host_id, port, transport_protocol) COMMENT '同一主机同端口同协议只记录一条',
    KEY idx_service_type (service_type)                                  COMMENT '快速按服务类型查询',
    KEY idx_ip_port      (ip_address, port)                              COMMENT '快速按 IP/端口组合查询',
    KEY idx_scan_time    (scan_time)                                     COMMENT '支持历史扫描比对',

    -- 外键关联（对应文档 4.5 第 2 点：所有服务实例均可追溯到 ActiveHost）
    CONSTRAINT fk_service_active_host
        FOREIGN KEY (active_host_id)
        REFERENCES active_host (id)
        ON DELETE CASCADE

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='第二层扫描结果表：基于 ActiveHost 的通用服务发现';
"""


def create_table(auto_confirm=False):
    conn = None
    try:
        # 1. 连接数据库
        print(f"[*] 正在连接数据库 {DB_CONFIG['database']} @ {DB_CONFIG['host']}:{DB_CONFIG['port']} ...")
        conn = pymysql.connect(**DB_CONFIG)
        cursor = conn.cursor()
        print("[✓] 数据库连接成功")

        # 2. 确认 active_host 表存在（外键依赖）
        cursor.execute("SHOW TABLES LIKE 'active_host'")
        if not cursor.fetchone():
            print("[!] 警告: active_host 表不存在！")
            print("    外键约束需要引用该表，请先执行第一层建表脚本。")
            print("    你可以选择继续创建（无外键），或先创建 active_host 表。")
            if not auto_confirm:
                choice = input("    是否继续创建（跳过外键）? [y/N]: ").strip().lower()
                if choice != 'y':
                    print("[×] 已取消")
                    return False
            # 去掉外键子句后建表
            _create_without_fk(cursor)
        else:
            print("[✓] active_host 表已存在，开始创建 service_instance_l2 ...")
            cursor.execute(CREATE_TABLE_SQL)
            print("[✓] service_instance_l2 表创建成功！")

        # 3. 验证表结构
        _verify_table(cursor)

        conn.commit()
        return True

    except pymysql.err.ProgrammingError as e:
        print(f"[!] SQL 错误: {e}")
        return False
    except pymysql.err.OperationalError as e:
        print(f"[!] 数据库连接失败: {e}")
        print("    请检查：1) MySQL 是否运行  2) 账号密码是否正确  3) 数据库 ipv4scan 是否存在")
        return False
    except Exception as e:
        print(f"[!] 未知错误: {e}")
        return False
    finally:
        if conn:
            conn.close()
            print("[*] 数据库连接已关闭")


def _create_without_fk(cursor):
    """跳过外键约束创建表（用于 active_host 尚未创建时）"""
    sql = CREATE_TABLE_SQL.replace(
        "CONSTRAINT fk_service_active_host\n        FOREIGN KEY (active_host_id)\n        REFERENCES active_host (id)\n        ON DELETE CASCADE\n",
        "-- 外键已跳过（active_host 表不存在时）\n"
    )
    cursor.execute(sql)
    print("[✓] service_instance_l2 表已创建（无外键约束）")


def _verify_table(cursor):
    """验证建表结果，打印表结构"""
    print("\n" + "=" * 70)
    print("  表结构验证")
    print("=" * 70)

    # 字段信息
    cursor.execute("DESCRIBE service_instance_l2")
    rows = cursor.fetchall()
    print(f"\n{'字段名':<22} {'类型':<20} {'允许空':<8} {'键':<6} {'默认':<10}")
    print("-" * 70)
    for r in rows:
        field, type_, null, key, default, _ = r
        null_str = "YES" if null == "YES" else "NO"
        default_str = str(default) if default else "NULL"
        print(f"{field:<22} {type_:<20} {null_str:<8} {key:<6} {default_str:<10}")

    # 索引信息
    cursor.execute("SHOW INDEX FROM service_instance_l2")
    idx_rows = cursor.fetchall()
    idx_names = set()
    for r in idx_rows:
        idx_names.add(r[2])
    print(f"\n索引列表: {', '.join(sorted(idx_names))}")

    # 外键信息
    cursor.execute("""
        SELECT CONSTRAINT_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME
        FROM information_schema.KEY_COLUMN_USAGE
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'service_instance_l2'
          AND REFERENCED_TABLE_NAME IS NOT NULL
    """)
    fk_rows = cursor.fetchall()
    if fk_rows:
        for fk in fk_rows:
            print(f"外键: {fk[0]} → {fk[1]}.{fk[2]}")
    else:
        print("外键: 无（active_host 表不存在时跳过）")

    print("=" * 70)


def drop_table():
    """删除表（用于重建）"""
    conn = pymysql.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS service_instance_l2")
    conn.commit()
    conn.close()
    print("[✓] service_instance_l2 表已删除")


def main(argv=None):
    parser = argparse.ArgumentParser(description="创建第二层 service_instance_l2 表")
    parser.add_argument("--drop", action="store_true", help="先删除旧表再重建")
    parser.add_argument("--yes", action="store_true", help="active_host 缺失时自动跳过外键，不再交互")
    args = parser.parse_args(argv)

    if args.drop:
        drop_table()
        print("[✓] 旧表已删除，准备重建...")

    return 0 if create_table(auto_confirm=args.yes) else 1


if __name__ == "__main__":
    sys.exit(main())
