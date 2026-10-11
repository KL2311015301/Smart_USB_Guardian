import sqlite3
import json
from datetime import datetime
from pathlib import Path


APP_DATA_DIR = Path.home() / "USBGuardian"
APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_NAME = APP_DATA_DIR / "USBGuardian.db"


def create_database():

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        device_name TEXT,

        drive_letter TEXT,

        scan_path TEXT,

        result TEXT,

        threats INTEGER,

        scan_time TEXT,

        scan_duration REAL,

        detected_files TEXT,

        sha256 TEXT,

        threat_ids TEXT,

        remediation_status TEXT,

        detection_engine TEXT,

        yara_rules TEXT
    )
    """)

    # -------------------------------------------------
    # Database migration for existing installations
    # -------------------------------------------------

    cursor.execute("""
        PRAGMA table_info(scan_history)
    """)

    columns = {
        row[1]
        for row in cursor.fetchall()
    }

    if "detected_files" not in columns:

        cursor.execute("""
            ALTER TABLE scan_history
            ADD COLUMN detected_files TEXT
        """)

    if "sha256" not in columns:

        cursor.execute("""
            ALTER TABLE scan_history
            ADD COLUMN sha256 TEXT
        """)

    if "threat_ids" not in columns:

        cursor.execute("""
            ALTER TABLE scan_history
            ADD COLUMN threat_ids TEXT
        """)
        
    if "remediation_status" not in columns:

        cursor.execute("""
            ALTER TABLE scan_history
            ADD COLUMN remediation_status TEXT
        """)
    
    if "detection_engine" not in columns:

        cursor.execute("""
            ALTER TABLE scan_history
            ADD COLUMN detection_engine TEXT
        """)

    if "yara_rules" not in columns:

        cursor.execute("""
            ALTER TABLE scan_history
            ADD COLUMN yara_rules TEXT
        """)
    
    
    connection.commit()
    connection.close()


def save_scan(
        device_name,
        drive_letter,
        scan_path,
        result,
        threats,
        scan_duration,
        detected_files=None,
        sha256=None,
        threat_ids=None,
        remediation_status="NONE",
        detection_engine=None,
        yara_rules=None
):

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    # Store lists as JSON.
    if detected_files is None:
        detected_files = []

    if threat_ids is None:
        threat_ids = []
    
    if yara_rules is None:
        yara_rules = []

    cursor.execute("""
    INSERT INTO scan_history
    (
        device_name,
        drive_letter,
        scan_path,
        result,
        threats,
        scan_time,
        scan_duration,
        detected_files,
        sha256,
        threat_ids,
        remediation_status,
        detection_engine,
        yara_rules
    )

    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

    """,
    (
        device_name,
        drive_letter,
        scan_path,
        result,
        threats,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        scan_duration,
        json.dumps(detected_files),
        sha256,
        json.dumps(threat_ids),
        remediation_status,
        detection_engine,
        json.dumps(yara_rules)
    ))

    connection.commit()
    connection.close()


def get_scan_history():

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            scan_time,
            device_name,
            drive_letter,
            result,
            threats,
            scan_duration,
            detected_files,
            sha256,
            threat_ids,
            remediation_status,
            detection_engine,
            yara_rules

        FROM scan_history

        ORDER BY id DESC
    """)

    records = cursor.fetchall()

    connection.close()

    return records