import time

from PySide6.QtCore import QThread, Signal

from usb_device.detector import get_usb_drives


class USBMonitor(QThread):

    usb_detected = Signal(dict)
    usb_removed = Signal()


    def __init__(self):

        super().__init__()

        self.running = True
        self.previous_drives = set()



    def run(self):

        while self.running and not self.isInterruptionRequested():

            drives = get_usb_drives()

            current_drives = set()


            for drive in drives:

                drive_letter = drive["DriveLetter"]

                current_drives.add(
                    drive_letter
                )


                # New USB detected

                if drive_letter not in self.previous_drives:

                    self.usb_detected.emit(
                        drive
                    )


            # Detect removal

            if len(self.previous_drives) > 0:

                if len(current_drives) == 0:

                    self.usb_removed.emit()



            self.previous_drives = current_drives


            self.msleep(3000)



    def stop(self):

        self.running = False
        self.requestInterruption()
        
        if self.isRunning():
            self.wait()
