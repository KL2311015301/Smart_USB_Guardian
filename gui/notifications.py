from PySide6.QtWidgets import QSystemTrayIcon


def show_scan_notification(tray_icon, result, enabled=True):

    if not enabled:
        return

    if tray_icon is None:
        return

    status = result.get("status", "ERROR")
    drive = result.get("drive", "Unknown")
    threats = result.get("threats", 0)

    if status == "SAFE":

        tray_icon.showMessage(
            "USB Guardian",
            f"Scan completed successfully.\n"
            f"No threats were detected on {drive}",
            QSystemTrayIcon.Information,
            5000
        )

    elif status == "UNSAFE":

        tray_icon.showMessage(
            "USB Guardian - Threat Detected",
            f"{threats} threat(s) detected on {drive}\n"
            f"Open USB Guardian for details.",
            QSystemTrayIcon.Warning,
            7000
        )

    else:

        tray_icon.showMessage(
            "USB Guardian - Scan Error",
            "The USB scan could not be completed.",
            QSystemTrayIcon.Critical,
            5000
        )
