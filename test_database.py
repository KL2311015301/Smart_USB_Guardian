from database.database import create_database, save_scan


create_database()


save_scan(
    "Test USB",
    "D:\\",
    "D:\\USBGuardian_Test",
    "SAFE",
    0
)


print("Database test complete")