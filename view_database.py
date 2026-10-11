import sqlite3


connection = sqlite3.connect("USBGuardian.db")

cursor = connection.cursor()


cursor.execute(
    "SELECT * FROM scan_history"
)


rows = cursor.fetchall()


for row in rows:
    print(row)


connection.close()