from database.database import create_database
from core.guardian import start_monitoring


def main():

    create_database()

    print("================================")
    print("        USB GUARDIAN")
    print("================================")
    print()

    print("Protection Status: ACTIVE")
    print()

    start_monitoring()


if __name__ == "__main__":
    main()