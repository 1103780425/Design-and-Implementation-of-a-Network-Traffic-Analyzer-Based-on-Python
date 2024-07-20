import sqlite3
import wmi

def update_or_insert(cursor, table, column_name, value, count, type=None):
    try:
        if type:
            cursor.execute(f"SELECT id, count FROM {table} WHERE {column_name} = ? AND type = ?", (value, type))
        else:
            cursor.execute(f"SELECT id, count FROM {table} WHERE {column_name} = ?", (value,))
        row = cursor.fetchone()
        if row:
            new_count = row[1] + count
            cursor.execute(f"UPDATE {table} SET count = ? WHERE id = ?", (new_count, row[0]))
        else:
            if type:
                cursor.execute(f"INSERT INTO {table} ({column_name}, type, count) VALUES (?, ?, ?)", (value, type, count))
            else:
                cursor.execute(f"INSERT INTO {table} ({column_name}, count) VALUES (?, ?)", (value, count))
    except Exception as e:
        print(f"Error updating or inserting into {table}: {e}")

def main():
    conn = sqlite3.connect('network_data.db')
    cursor = conn.cursor()
    
    # Test with dummy data
    update_or_insert(cursor, "ProtocolUsage", 'protocol', "HTTP", 10)
    conn.commit()
    conn.close()

if __name__ == "__main__":
    main()
