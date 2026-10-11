import json
import subprocess
from pathlib import Path
import re
from datetime import datetime


DEFENDER_PLATFORM_PATH = Path(
    r"C:\ProgramData\Microsoft\Windows Defender\Platform"
)


def find_defender():
    """
    Find the newest Microsoft Defender MpCmdRun.exe.
    """

    if not DEFENDER_PLATFORM_PATH.exists():
        return None

    defender_versions = []

    for folder in DEFENDER_PLATFORM_PATH.iterdir():

        if folder.is_dir():

            executable = folder / "MpCmdRun.exe"

            if executable.exists():
                defender_versions.append(executable)

    if not defender_versions:
        return None

    defender_versions.sort(reverse=True)

    return defender_versions[0]


def get_defender_detections():

    """
    Retrieve recent Microsoft Defender detection records.

    Returns a list containing:
        - threat_id
        - detection_time
        - resources
        - action_success
    """

    command = [
        "powershell.exe",
        "-NoProfile",
        "-Command",
        """
        Get-MpThreatDetection |
        Select-Object ThreatID,
                      InitialDetectionTime,
                      Resources,
                      ActionSuccess |
        ConvertTo-Json -Compress
        """
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        if result.returncode != 0:

            return []

        output = result.stdout.strip()

        if not output:
            return []

        data = json.loads(output)

        # PowerShell returns an object instead of a list
        # when there is only one detection.
        if isinstance(data, dict):
            data = [data]

        return data

    except Exception as e:

        print("Could not retrieve Defender detections:", e)

        return []


def extract_detected_files(detections):

    """
    Extract actual detected file paths from Defender Resources.
    """

    detected_files = []

    for detection in detections:

        resources = detection.get("Resources", [])

        if isinstance(resources, str):
            resources = [resources]

        for resource in resources:

            resource = str(resource)

            # We want the actual file resource.
            if not resource.lower().startswith("file:"):
                continue

            resource = resource[5:]

            # Defender may append:
            # ->(UTF-16LE)
            if "->(" in resource:
                resource = resource.split("->(", 1)[0]

            # Defender prefixes the path with "_"
            resource = resource.lstrip("_")

            if resource not in detected_files:
                detected_files.append(resource)

    return detected_files


def scan_path(path):

    defender = find_defender()

    if defender is None:

        return {
            "status": "ERROR",
            "message": "Microsoft Defender not found."
        }

    command = [
        str(defender),
        "-Scan",
        "-ScanType",
        "3",
        "-File",
        str(path)
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        print("RETURN CODE:", result.returncode)

        print("STDOUT:")
        print(result.stdout)

        print("STDERR:")
        print(result.stderr)

        output = result.stdout.strip()

        if "found no threats" in output.lower():

            return {
                "status": "SAFE",
                "path": str(path),
                "threats": 0,
                "raw_output": output
            }

        if "found" in output.lower() and "threat" in output.lower():


            return {
                "status": "THREAT_DETECTED",
                "path": str(path),
                "threats": 1,
                "raw_output": output
            }

        return {
            "status": "ERROR",
            "path": str(path),
            "message": "Unable to determine Defender scan result.",
            "raw_output": output
        }

    except Exception as e:

        return {
            "status": "ERROR",
            "message": str(e)
        }
        
        
def get_new_defender_detections(before, after):
    """
    Return Defender detections that were not present
    before the current scan.
    """

    before_keys = set()

    for detection in before:

        key = (
            detection.get("ThreatID"),
            detection.get("InitialDetectionTime"),
            tuple(
                detection.get("Resources", [])
            )
            if isinstance(
                detection.get("Resources", []),
                list
            )
            else detection.get("Resources")
        )

        before_keys.add(key)

    new_detections = []

    for detection in after:

        key = (
            detection.get("ThreatID"),
            detection.get("InitialDetectionTime"),
            tuple(
                detection.get("Resources", [])
            )
            if isinstance(
                detection.get("Resources", []),
                list
            )
            else detection.get("Resources")
        )

        if key not in before_keys:
            new_detections.append(detection)

    return new_detections


def get_drive_detections_since(
    detections,
    drive_letter,
    since_time
):
    """
    Return Defender detections that:
    1. belong to the specified USB drive, and
    2. occurred on or after the USB connection time.
    """

    matching_detections = []

    drive_prefix = f"{drive_letter}:\\".lower()

    for detection in detections:

        detection_time_raw = detection.get(
            "InitialDetectionTime"
        )

        if not detection_time_raw:
            continue

        # PowerShell JSON date format:
        # /Date(1791178897760)/
        match = re.search(
            r"/Date\((\d+)\)/",
            str(detection_time_raw)
        )

        if not match:
            continue

        milliseconds = int(
            match.group(1)
        )

        detection_time = datetime.fromtimestamp(
            milliseconds / 1000
        )

        # Ignore Defender detections that happened
        # before this USB was connected.
        if detection_time < since_time:
            continue

        resources = detection.get(
            "Resources",
            []
        )

        if isinstance(resources, str):
            resources = [resources]

        belongs_to_drive = False

        for resource in resources:

            resource_normalized = (
                str(resource)
                .lower()
                .replace("file:_", "")
                .replace("containerfile:_", "")
            )

            if drive_prefix in resource_normalized:

                belongs_to_drive = True
                break

        if belongs_to_drive:

            matching_detections.append(
                detection
            )

    return matching_detections