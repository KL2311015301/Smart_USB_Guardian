import sqlite3


DATABASE_NAME = "USBGuardian.db"


def view_history():

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()


    cursor.execute("""
        SELECT
            id,
            device_name,
            drive_letter,
            result,
            threats,
            scan_time

        FROM scan_history
    """)


    records = cursor.fetchall()


    print()
    print("================================")
    print("       USB GUARDIAN HISTORY")
    print("================================")
    print()


    if not records:

        print("No scan history found.")

    else:

        print(
            f"{'ID':<5}"
            f"{'DEVICE':<30}"
            f"{'RESULT':<15}"
        )

        print("-" * 50)


        for record in records:

            print(
                f"{record[0]:<5}"
                f"{record[1]:<30}"
                f"{record[3]:<15}"
            )


        print()
        print(f"Total scans: {len(records)}")


    connection.close()



if __name__ == "__main__":

    view_history()