import sqlite3

def create_db():
    conn = sqlite3.connect('network_data.db')
    cursor = conn.cursor()
    
    # 创建 ProtocolUsage 表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ProtocolUsage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        protocol TEXT,
        count INTEGER
    )
    ''')

    # 创建 IPStats 表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS IPStats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT,
        type TEXT,
        count INTEGER
    )
    ''')

    # 创建 TCPFlags 表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS TCPFlags (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        flag TEXT,
        count INTEGER
    )
    ''')

    # 创建 LayerSequence 表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS LayerSequence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sequence TEXT,
        count INTEGER
    )
    ''')

    conn.commit()
    conn.close()

create_db()
