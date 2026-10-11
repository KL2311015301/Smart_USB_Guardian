import time

from usb_device.detector import get_usb_drives
from core.scan_manager import scan_usb
from config.config_manager import load_settings


def start_monitoring():

    print("Monitoring USB devices...")
    print("Waiting for USB connection...")
    print()


    previous_drives = set()


    try:

        while True:

            drives = get_usb_drives()

            current_drives = set()


            for drive in drives:

                drive_letter = drive["DriveLetter"]

                current_drives.add(drive_letter)


                if drive_letter not in previous_drives:

                    # Mark as detected immediately
                    previous_drives.add(drive_letter)

                    settings = load_settings()


                    if settings["auto_scan"]:

                        result = scan_usb(drive)

                        print()
                        print("================================")
                        print("SCAN SUMMARY")
                        print("================================")
                        print()

                        print("Device:")
                        print(result["device"])

                        print()

                        print("Drive:")
                        print(result["drive"])

                        print()

                        print("Scan Path:")
                        print(result["scan_path"])

                        print()

                        print("Result:")
                        print(result["status"])

                        print()

                        print("Threats Found:")
                        print(result.get("threats", 0))

                        if "duration" in result:

                            print()

                            print("Scan Duration:")
                            print(f"{result['duration']} seconds")


                    else:

                        print()
                        print("================================")
                        print("USB DETECTED")
                        print("================================")
                        print()

                        print("Device:")
                        print(drive["DiskName"])

                        print()

                        print("Drive:")
                        print(f"{drive['DriveLetter']}:\\")
    
                        print()

                        print("Automatic scanning disabled.")
                        print("Waiting for manual scan.")



            previous_drives = current_drives


            time.sleep(3)


    except KeyboardInterrupt:

        print()
        print("================================")
        print("USB GUARDIAN STOPPED")
        print("================================")
        print()

        print("Monitoring terminated safely.")
