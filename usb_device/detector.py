import subprocess
import json


def get_usb_drives():
    """
    Detect storage devices connected through USB
    and return their drive information.
    """

    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        """
        Get-Disk |
        Where-Object {$_.BusType -eq 'USB'} |
        ForEach-Object {
            $diskNumber = $_.Number
            $diskName = $_.FriendlyName
            $diskSize = $_.Size

            Get-Partition -DiskNumber $diskNumber |
            Where-Object {$_.DriveLetter} |
            ForEach-Object {
                [PSCustomObject]@{
                    DiskNumber = $diskNumber
                    DriveLetter = $_.DriveLetter
                    DiskName = $diskName
                    Size = $diskSize
                }
            }
        } |
        ConvertTo-Json
        """
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        creationflags=subprocess.CREATE_NO_WINDOW
    )

    output = result.stdout.strip()

    if not output:
        return []

    try:
        data = json.loads(output)

        # If only one USB drive is detected,
        # PowerShell may return a dictionary instead of a list.
        if isinstance(data, dict):
            data = [data]

        return data

    except json.JSONDecodeError:
        return []


def format_size(size):
    """Convert bytes into a human-readable size."""

    if size >= 1_000_000_000_000:
        return f"{size / 1_000_000_000_000:.2f} TB"

    if size >= 1_000_000_000:
        return f"{size / 1_000_000_000:.2f} GB"

    if size >= 1_000_000:
        return f"{size / 1_000_000:.2f} MB"

    return f"{size:,} bytes"


def display_usb_drives():
    """Display detected USB devices."""

    drives = get_usb_drives()

    print("================================")
    print("        USB GUARDIAN")
    print("================================")
    print()

    if not drives:
        print("No USB storage devices detected.")
        print()
        print("Status: Waiting for USB device.")
        return

    for drive in drives:
        print("USB DEVICE DETECTED")
        print()
        print(f"Drive       : {drive['DriveLetter']}:\\")
        print(f"Connection  : USB")
        print(f"Capacity    : {format_size(drive['Size'])}")
        print()

        if drive["DiskName"]:
            print(f"Device      : {drive['DiskName']}")
            print()

        print("Status      : Ready for scanning")
        print("--------------------------------")


if __name__ == "__main__":
    display_usb_drives()