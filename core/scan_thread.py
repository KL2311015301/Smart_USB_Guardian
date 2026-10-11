from PySide6.QtCore import QThread, Signal

from core.scan_manager import scan_usb


class ScanThread(QThread):

    scan_finished = Signal(dict)

    def __init__(self, drive, usb_connected_time):
        super().__init__()

        self.drive = drive
        self.usb_connected_time = usb_connected_time


    def run(self):

        print("Scan thread started")

        result = scan_usb(
            self.drive,
            self.usb_connected_time
        )

        print("Scan result:", result)

        self.scan_finished.emit(
            result
        )
