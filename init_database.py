#数据库初始化(如没有创建项目所需数据库表可运行)


import mysql.connector
from config import DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME

def create_database_if_not_exists():
    """如果数据库不存在，则创建"""
    try:
        # 连接到MySQL（不指定数据库）
        connection = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD
        )
        
        cursor = connection.cursor()
        
        # 创建数据库（如果不存在）
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        print(f"数据库 {DB_NAME} 已创建或已存在")
        
        cursor.close()
        connection.close()
        return True
        
    except Exception as e:
        print(f"创建数据库失败: {e}")
        return False

def init_database():
    """创建项目所需的数据库表"""
    try:
        # 先确保数据库存在
        create_database_if_not_exists()
        
        # 连接到MySQL（指定数据库）
        connection = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        
        cursor = connection.cursor()
        print(f"已连接到数据库: {DB_NAME}")
        
        # 创建ipv4_subnet_l1表
        print("创建ipv4_subnet_l1表...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ipv4_subnet_l1 (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                network_address INT UNSIGNED NOT NULL,
                prefix_len TINYINT NOT NULL DEFAULT 9,
                scan_status TINYINT NOT NULL DEFAULT 0,
                scan_round INT NOT NULL DEFAULT 1,
                alive_host_count INT DEFAULT 0,
                last_scan_time DATETIME NULL,
                next_scan_time DATETIME NULL,
                scanner_node VARCHAR(64) NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        """)
        
        # 创建active_host表
        print("创建active_host表...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS active_host (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                ip_address INT UNSIGNED NOT NULL,
                alive_type TINYINT NOT NULL,
                first_seen DATETIME NOT NULL,
                last_seen DATETIME NOT NULL,
                scan_round INT NOT NULL,
                scanner_node VARCHAR(64) NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_ip_round (ip_address, scan_round),
                KEY idx_ip (ip_address)
            )
        """)
        
        connection.commit()
        print("数据库表创建成功！")
        
        # 显示表结构
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()
        print(f"数据库中的表：")
        for table in tables:
            print(f"{table[0]}")
        
        cursor.close()
        connection.close()
        print("数据库初始化完成！")
        
    except Exception as e:
        print(f"数据库初始化失败: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("=== 项目数据库初始化 ===")
    print(f"数据库: {DB_NAME} @ {DB_HOST}:{DB_PORT}")
    print(f"用户: {DB_USER}")
    print("-" * 35)
    
    init_database()