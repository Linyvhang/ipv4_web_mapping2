#!/usr/bin/env python3
"""
init_l3_tables.py
第三层（L3）数据库初始化脚本，对应《主体思路 2.0》第 5 节。

创建：
    web_service_detail   Web 深度扫描结果（文档 5.4 表结构）
    ssh_service_detail   SSH 深度扫描结果
    db_service_detail    数据库服务深度扫描结果
    rdp_service_detail   RDP 深度扫描结果
    iot_service_detail   通用 Banner / IoT 深度扫描结果

并在 service_instance_l2 上补充 L3 调度字段：
    l3_scan_status  0=待扫描 1=完成 2=异常
    l3_scan_time    最近一次 L3 扫描时间

说明：
文档 5.3 用 ServiceInstance.scan_status 表示 L3 进度（1=待扫描、2=完成），
但 4.4 中 scan_status 已表示 L2 状态（0=未完成、1=完成、2=异常），两者冲突。
这里保留 L2 语义，新增独立的 l3_scan_status 字段，避免覆盖 L2 结果。

用法：
    python init_l3_tables.py          # 建表 / 补字段
    python init_l3_tables.py --drop   # 删除全部 L3 结果表后重建
    python pipeline.py init           # 统一初始化（L1 + L2 + L3）

也作为函数被 pipeline.py 调用：init_l3_tables(drop=False)
"""

import argparse
import sys

import pymysql

from config import DB_CONFIG

COMMON_TAIL = """
    scan_status    TINYINT      NOT NULL DEFAULT 0 COMMENT '扫描状态：0=未完成，1=完成，2=异常',
    error_message  VARCHAR(255) NULL                COMMENT '异常信息（正常时为空）',
    scan_time      DATETIME     NOT NULL             COMMENT '扫描时间',
    created_at     DATETIME     NOT NULL             COMMENT '记录创建时间',
    updated_at     DATETIME     NOT NULL             COMMENT '最近更新时间',
    PRIMARY KEY (id),
    UNIQUE KEY uniq_instance_port (service_instance_id, port),
    KEY idx_ip_port (ip_address, port),
    KEY idx_plugin (plugin_name),
"""

DETAIL_TABLES = {
    "web_service_detail": f"""
CREATE TABLE IF NOT EXISTS web_service_detail (
    id                  BIGINT       NOT NULL AUTO_INCREMENT COMMENT 'Web 深度扫描记录主键',
    service_instance_id BIGINT       NOT NULL COMMENT '关联第二层 service_instance_l2.id',
    ip_address          INT UNSIGNED NOT NULL COMMENT '冗余存储 IP 地址',
    port                INT          NOT NULL COMMENT 'Web 服务端口',
    transport_protocol  VARCHAR(4)   NOT NULL DEFAULT 'tcp' COMMENT '传输层协议 TCP/UDP',
    plugin_name         VARCHAR(64)  NOT NULL COMMENT '执行扫描的插件名称',
    http_status         SMALLINT     NULL COMMENT 'HTTP 状态码，如 200/404/500',
    title               VARCHAR(255) NULL COMMENT '网页 Title',
    server_header       VARCHAR(255) NULL COMMENT 'HTTP Server Header',
    x_powered_by        VARCHAR(255) NULL COMMENT 'X-Powered-By Header',
    tls_certificate     JSON         NULL COMMENT 'TLS 证书信息（CN、SAN、有效期等）',
    web_fingerprint     JSON         NULL COMMENT 'Web 框架或 CMS 指纹信息',
{COMMON_TAIL}
    CONSTRAINT fk_web_l3_instance
        FOREIGN KEY (service_instance_id) REFERENCES service_instance_l2 (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='第三层 Web 深度扫描结果表'
""",
    "ssh_service_detail": f"""
CREATE TABLE IF NOT EXISTS ssh_service_detail (
    id                  BIGINT       NOT NULL AUTO_INCREMENT COMMENT 'SSH 深度扫描记录主键',
    service_instance_id BIGINT       NOT NULL COMMENT '关联第二层 service_instance_l2.id',
    ip_address          INT UNSIGNED NOT NULL COMMENT '冗余存储 IP 地址',
    port                INT          NOT NULL COMMENT 'SSH 服务端口',
    transport_protocol  VARCHAR(4)   NOT NULL DEFAULT 'tcp',
    plugin_name         VARCHAR(64)  NOT NULL,
    protocol_version    VARCHAR(32)  NULL COMMENT 'SSH 协议版本，如 2.0',
    software            VARCHAR(128) NULL COMMENT '服务端软件及版本，如 OpenSSH_8.9',
    os_guess            VARCHAR(64)  NULL COMMENT '由 Banner 推测的操作系统',
    auth_methods        JSON         NULL COMMENT '支持的认证方式（需完整 KEX，默认不探测）',
    banner              VARCHAR(255) NULL COMMENT 'SSH Banner 原文',
{COMMON_TAIL}
    CONSTRAINT fk_ssh_l3_instance
        FOREIGN KEY (service_instance_id) REFERENCES service_instance_l2 (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='第三层 SSH 深度扫描结果表'
""",
    "db_service_detail": f"""
CREATE TABLE IF NOT EXISTS db_service_detail (
    id                  BIGINT       NOT NULL AUTO_INCREMENT COMMENT '数据库深度扫描记录主键',
    service_instance_id BIGINT       NOT NULL COMMENT '关联第二层 service_instance_l2.id',
    ip_address          INT UNSIGNED NOT NULL COMMENT '冗余存储 IP 地址',
    port                INT          NOT NULL COMMENT '数据库服务端口',
    transport_protocol  VARCHAR(4)   NOT NULL DEFAULT 'tcp',
    plugin_name         VARCHAR(64)  NOT NULL,
    db_type             VARCHAR(32)  NULL COMMENT '数据库类型：mysql/mariadb/postgresql/redis/mongodb/elasticsearch/mssql',
    version             VARCHAR(64)  NULL COMMENT '版本信息',
    banner              VARCHAR(255) NULL COMMENT 'Banner / 协议响应特征',
    features            JSON         NULL COMMENT '协议与开放能力特征',
{COMMON_TAIL}
    CONSTRAINT fk_db_l3_instance
        FOREIGN KEY (service_instance_id) REFERENCES service_instance_l2 (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='第三层数据库服务深度扫描结果表'
""",
    "rdp_service_detail": f"""
CREATE TABLE IF NOT EXISTS rdp_service_detail (
    id                  BIGINT       NOT NULL AUTO_INCREMENT COMMENT 'RDP 深度扫描记录主键',
    service_instance_id BIGINT       NOT NULL COMMENT '关联第二层 service_instance_l2.id',
    ip_address          INT UNSIGNED NOT NULL COMMENT '冗余存储 IP 地址',
    port                INT          NOT NULL COMMENT 'RDP 服务端口',
    transport_protocol  VARCHAR(4)   NOT NULL DEFAULT 'tcp',
    plugin_name         VARCHAR(64)  NOT NULL,
    banner              VARCHAR(255) NULL COMMENT 'X.224 响应报文（十六进制）',
    protocol_version    VARCHAR(64)  NULL COMMENT '协商结果：TLS / CredSSP (NLA) / RDP 标准安全',
    encryption          VARCHAR(64)  NULL COMMENT '加密方式',
    port_open           TINYINT      NOT NULL DEFAULT 1 COMMENT '端口开放情况：1=开放',
{COMMON_TAIL}
    CONSTRAINT fk_rdp_l3_instance
        FOREIGN KEY (service_instance_id) REFERENCES service_instance_l2 (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='第三层 RDP 深度扫描结果表'
""",
    "iot_service_detail": f"""
CREATE TABLE IF NOT EXISTS iot_service_detail (
    id                  BIGINT       NOT NULL AUTO_INCREMENT COMMENT 'Banner 采集记录主键',
    service_instance_id BIGINT       NOT NULL COMMENT '关联第二层 service_instance_l2.id',
    ip_address          INT UNSIGNED NOT NULL COMMENT '冗余存储 IP 地址',
    port                INT          NOT NULL COMMENT '服务端口',
    transport_protocol  VARCHAR(4)   NOT NULL DEFAULT 'tcp',
    plugin_name         VARCHAR(64)  NOT NULL,
    protocol_guess      VARCHAR(32)  NULL COMMENT '协议推测：telnet/ftp/smb/http/...',
    device_model        VARCHAR(128) NULL COMMENT '由 Banner 推测的设备型号',
    banner              VARCHAR(255) NULL COMMENT '原始 Banner',
{COMMON_TAIL}
    CONSTRAINT fk_iot_l3_instance
        FOREIGN KEY (service_instance_id) REFERENCES service_instance_l2 (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='第三层通用 Banner / IoT 深度扫描结果表'
""",
}

L3_COLUMNS = (
    ("l3_scan_status", "TINYINT NOT NULL DEFAULT 0 COMMENT '第三层扫描状态：0=待扫描，1=完成，2=异常'"),
    ("l3_scan_time", "DATETIME NULL COMMENT '第三层最近一次扫描时间'"),
)


def column_exists(cursor, table: str, column: str) -> bool:
    cursor.execute(
        """SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND COLUMN_NAME = %s""",
        (table, column),
    )
    return cursor.fetchone()[0] > 0


def table_exists(cursor, table: str) -> bool:
    cursor.execute("SHOW TABLES LIKE %s", (table,))
    return cursor.fetchone() is not None


def drop_tables(cursor):
    for table in reversed(list(DETAIL_TABLES)):
        cursor.execute(f"DROP TABLE IF EXISTS {table}")
        print(f"[✓] 已删除 {table}")


def create_tables(cursor):
    if not table_exists(cursor, "service_instance_l2"):
        print("[×] 未找到 service_instance_l2，请先执行 init_service_instance.py 完成第二层建表")
        return False

    for table, sql in DETAIL_TABLES.items():
        cursor.execute(sql)
        print(f"[✓] {table} 已创建/已存在")

    # 为第二层表补充 L3 调度字段
    for name, definition in L3_COLUMNS:
        if column_exists(cursor, "service_instance_l2", name):
            print(f"[=] service_instance_l2.{name} 已存在，跳过")
            continue
        cursor.execute(f"ALTER TABLE service_instance_l2 ADD COLUMN {name} {definition}")
        print(f"[+] service_instance_l2.{name} 已添加")
    return True


def verify(cursor):
    print("\n" + "=" * 72)
    print("  L3 表结构验证")
    print("=" * 72)
    for table in DETAIL_TABLES:
        cursor.execute(f"DESCRIBE {table}")
        rows = cursor.fetchall()
        print(f"\n[{table}] 共 {len(rows)} 个字段")
        print("  " + ", ".join(row[0] for row in rows))

    cursor.execute(
        """SELECT COLUMN_NAME, COLUMN_TYPE, COLUMN_DEFAULT
           FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'service_instance_l2'
             AND COLUMN_NAME IN ('scan_status', 'l3_scan_status', 'l3_scan_time')
           ORDER BY ORDINAL_POSITION"""
    )
    print("\n[service_instance_l2] 调度字段：")
    for name, column_type, default in cursor.fetchall():
        print(f"  {name:<16} {column_type:<12} default={default}")
    print("=" * 72)


def init_l3_tables(drop=False):
    """创建 L3 全部结果表并补充调度字段，成功返回 True"""
    conn = None
    try:
        print(f"[*] 连接数据库 {DB_CONFIG['database']} @ {DB_CONFIG['host']}:{DB_CONFIG['port']} ...")
        conn = pymysql.connect(**DB_CONFIG)
        cursor = conn.cursor()
        print("[✓] 数据库连接成功")

        if drop:
            drop_tables(cursor)

        if not create_tables(cursor):
            return False

        conn.commit()
        verify(cursor)

        cursor.close()
        print("\n[✓] 第三层数据库初始化完成")
        return True
    except pymysql.err.OperationalError as exc:
        print(f"[×] 数据库连接/执行失败: {exc}")
        print("    请检查 MySQL 是否运行，以及 config.py 中的账号密码是否正确")
        return False
    except pymysql.err.ProgrammingError as exc:
        print(f"[×] SQL 错误: {exc}")
        return False
    finally:
        if conn:
            conn.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="初始化第三层 L3 结果表")
    parser.add_argument("--drop", action="store_true", help="删除全部 L3 结果表后重建")
    args = parser.parse_args(argv)
    return 0 if init_l3_tables(drop=args.drop) else 1


if __name__ == "__main__":
    sys.exit(main())
