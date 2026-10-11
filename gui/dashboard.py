from datetime import datetime
from PySide6.QtCore import QTimer, Signal, Qt
from core.usb_monitor import USBMonitor
from core.scan_thread import ScanThread
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QGroupBox,
    QProgressBar,
    QScrollArea
)

from usb_device.detector import get_usb_drives
from config.config_manager import load_settings



class Dashboard(QWidget):
    
    scan_completed_signal = Signal(dict)

    def __init__(self):
        super().__init__()
        
        self.setObjectName("dashboardPage")

        self.setStyleSheet(
            """
            QWidget#dashboardPage {
                background-color: #F5F7F6;
            }

            QLabel#dashboardTitle {
                color: #173B2B;
                font-size: 30px;
                font-weight: 800;
            }

            QLabel#dashboardSubtitle {
                color: #6B7771;
                font-size: 13px;
            }

            QGroupBox {
                background-color: white;
                border: 1px solid #DDE5E1;
                border-radius: 12px;
                margin-top: 14px;
                padding: 18px;
                font-size: 13px;
                font-weight: 700;
                color: #173B2B;
            }

            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                left: 16px;
                padding: 0px 6px;
                background-color: #F5F7F6;
            }

            QPushButton {
                min-height: 38px;
                border-radius: 8px;
                font-size: 13px;
                font-weight: 700;
            }

            QProgressBar {
                border: 1px solid #D8E1DD;
                border-radius: 6px;
                background-color: #EDF2F0;
                min-height: 12px;
            }

            QProgressBar::chunk {
                background-color: #0B6B45;
                border-radius: 6px;
            }
            """
        )
        
        # Main layout for the Dashboard page
        main_layout = QVBoxLayout(self)

        # Scroll area prevents large scan results from
        # forcing the application beyond the screen height.
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)

        content_widget = QWidget()

        layout = QVBoxLayout(content_widget)


        title = QLabel(
            "USB Guardian Dashboard"
        )

        title = QLabel(
            "USB Guardian Dashboard"
        )

        title.setObjectName(
            "dashboardTitle"
        )

        subtitle = QLabel(
            "USB Security & Removable Drive Protection"
        )

        subtitle.setObjectName(
            "dashboardSubtitle"
        )


        layout.addWidget(title)
        layout.addWidget(subtitle)

        layout.addSpacing(15)



        # =========================
        # PROTECTION STATUS
        # =========================

        protection = QGroupBox(
            "Protection Status"
        )

        protection.setMaximumHeight(115)

        protection_layout = QHBoxLayout(
            protection
        )


        protection_text_layout = QVBoxLayout()


        protection_title = QLabel(
            "USB Guardian is protecting this computer"
        )

        protection_title.setStyleSheet(
            """
            color: #173B2B;
            font-size: 15px;
            font-weight: 700;
            """
        )


        protection_description = QLabel(
            "Automatic monitoring of connected USB storage devices is enabled."
        )

        protection_description.setStyleSheet(
            """
            color: #6B7771;
            font-size: 12px;
            font-weight: normal;
            """
        )


        protection_text_layout.addWidget(
            protection_title
        )

        protection_text_layout.addWidget(
            protection_description
        )


        self.status = QLabel(
            "●  ACTIVE"
        )

        self.status.setStyleSheet(
            """
            color: #087A4B;
            background-color: #E8F6EF;

            border: 1px solid #B9E5D0;
            border-radius: 14px;

            padding: 7px 14px;

            font-size: 12px;
            font-weight: 800;
            """
        )


        protection_layout.addLayout(
            protection_text_layout
        )

        protection_layout.addStretch()

        protection_layout.addWidget(
            self.status
        )


        layout.addWidget(
            protection
        )


        # =========================
        # USB + LAST SCAN CARDS
        # =========================

        cards_layout = QHBoxLayout()

        cards_layout.setSpacing(16)


        # -------------------------
        # CONNECTED USB CARD
        # -------------------------

        usb_box = QGroupBox(
            "Connected USB"
        )

        usb_box.setObjectName(
            "usbCard"
        )

        usb_layout = QVBoxLayout(
            usb_box
        )

        usb_layout.setContentsMargins(
            22, 25, 22, 22
        )


        usb_heading = QLabel(
            "Removable Storage Device"
        )

        usb_heading.setStyleSheet(
            """
            color: #173B2B;
            font-size: 16px;
            font-weight: 700;
            """
        )


        usb_description = QLabel(
            "USB storage currently monitored by USB Guardian"
        )

        usb_description.setStyleSheet(
            """
            color: #6B7771;
            font-size: 12px;
            """
        )


        self.usb_status_badge = QLabel(
            "● CHECKING"
        )

        self.usb_status_badge.setStyleSheet(
            """
            color: #8A6A00;
            background-color: #FFF4CC;
            border: 1px solid #F2D36B;
            border-radius: 12px;
            padding: 5px 10px;
            font-size: 11px;
            font-weight: 800;
            """
        )

        self.usb_status_badge.setMaximumWidth(
            110
        )


        self.usb_device_name = QLabel(
            "Checking USB devices..."
        )

        self.usb_device_name.setStyleSheet(
            """
            color: #173B2B;
            font-size: 18px;
            font-weight: 800;
            """
        )

        self.usb_device_name.setWordWrap(
            True
        )


        self.usb_info = QLabel(
            "Drive: -\nConnection: USB"
        )

        self.usb_info.setStyleSheet(
            """
            color: #4F5E57;
            font-size: 13px;
            line-height: 1.5;
            """
        )


        usb_layout.addWidget(
            usb_heading
        )

        usb_layout.addWidget(
            usb_description
        )

        usb_layout.addSpacing(
            12
        )

        usb_layout.addWidget(
            self.usb_status_badge
        )

        usb_layout.addSpacing(
            10
        )

        usb_layout.addWidget(
            self.usb_device_name
        )

        usb_layout.addWidget(
            self.usb_info
        )

        usb_layout.addStretch()


        # -------------------------
        # LAST SCAN CARD
        # -------------------------

        scan_box = QGroupBox(
            "Last Security Scan"
        )

        scan_box.setObjectName(
            "scanCard"
        )

        scan_layout = QVBoxLayout(
            scan_box
        )

        scan_layout.setContentsMargins(
            22, 25, 22, 22
        )


        scan_heading = QLabel(
            "Security Assessment"
        )

        scan_heading.setStyleSheet(
            """
            color: #173B2B;
            font-size: 16px;
            font-weight: 700;
            """
        )


        # Large visual scan-status badge
        self.scan_status_badge = QLabel(
            "NO SCAN YET"
        )

        self.scan_status_badge.setAlignment(
            Qt.AlignCenter
        )

        self.scan_status_badge.setStyleSheet(
            """
            color: #6B7771;
            background-color: #F2F4F3;
            border: 1px solid #DDE5E1;
            border-radius: 10px;
            padding: 10px 14px;
            font-size: 14px;
            font-weight: 800;
            """
        )


        # Short explanation below the badge
        self.scan_summary = QLabel(
            "Run a USB security scan to view the assessment."
        )

        self.scan_summary.setWordWrap(True)

        self.scan_summary.setStyleSheet(
            """
            color: #6B7771;
            font-size: 12px;
            """
        )


        # Detailed technical scan information
        self.scan_result = QLabel(
            "Detection Engine: -\n"
            "Files Scanned: -\n"
            "Scan Errors: -\n"
            "Duration: -"
        )

        self.scan_result.setObjectName(
            "scanResult"
        )

        self.scan_result.setWordWrap(
            True
        )

        self.scan_result.setStyleSheet(
            """
            color: #34483F;
            font-size: 13px;
            """
        )


        scan_layout.addWidget(
            scan_heading
        )

        scan_layout.addSpacing(
            10
        )

        scan_layout.addWidget(
            self.scan_status_badge
        )

        scan_layout.addWidget(
            self.scan_summary
        )

        scan_layout.addSpacing(
            10
        )

        scan_layout.addWidget(
            self.scan_result
        )

        self.scan_progress = QProgressBar()

        # Defender does not provide an exact percentage,
        # so USB Guardian uses an indeterminate progress bar.
        self.scan_progress.setRange(
            0,
            0
        )

        self.scan_progress.hide()

        scan_layout.addWidget(
            self.scan_progress
        )

        scan_layout.addStretch()


        # -------------------------
        # ADD BOTH CARDS
        # -------------------------

        cards_layout.addWidget(
            usb_box,
            1
        )

        cards_layout.addWidget(
            scan_box,
            1
        )


        layout.addLayout(
            cards_layout
        )
        
        self.scan_button = QPushButton(
            "Scan USB"
        )

        self.ignore_button = QPushButton(
            "Ignore"
        )


        self.scan_button.clicked.connect(
            self.manual_scan
        )


        self.ignore_button.clicked.connect(
            self.ignore_usb
        )


        self.scan_button.hide()
        self.ignore_button.hide()


        layout.addWidget(
            self.scan_button
        )


        layout.addWidget(
            self.ignore_button
        )

        layout.addStretch()

        scroll_area.setWidget(
            content_widget
        )

        main_layout.addWidget(
            scroll_area
        )
        
        self.monitor = USBMonitor()

        self.monitor.usb_detected.connect(
            self.usb_connected
        )

        self.monitor.usb_removed.connect(
            self.usb_disconnected
        )

        self.monitor.start()
        
        # Check USB when dashboard loads
        self.update_usb_status()
        
    def usb_connected(self, drive):
        
        self.current_drive = drive
        self.usb_connected_time = datetime.now()

        print(
            "USB CONNECTION TIME:",
            self.usb_connected_time
        )
        
        settings = load_settings()
        
        if settings.get("auto_scan", False):
            
            self.scan_button.hide()
            self.ignore_button.hide()
            
            self.start_auto_scan()
            
        else:
            
            self.scan_button.show()
            self.ignore_button.show()
            
        

        self.usb_status_badge.setText(
            "● CONNECTED"
        )

        self.usb_status_badge.setStyleSheet(
            """
            color: #087A4B;
            background-color: #E8F6EF;
            border: 1px solid #B9E5D0;
            border-radius: 12px;
            padding: 5px 10px;
            font-size: 11px;
            font-weight: 800;
            """
        )

        self.usb_device_name.setText(
            drive["DiskName"]
        )

        self.usb_info.setText(
            f"Drive: {drive['DriveLetter']}:\\\n"
            f"Connection: USB Storage\n"
            f"Monitoring: Active"
        )
        
    def start_auto_scan(self):

        QTimer.singleShot(
            3000,
            self.manual_scan
        )


    def usb_disconnected(self):

        self.usb_info.setText(
            "No USB device connected"
        )
        

        self.scan_button.hide()
        self.ignore_button.hide()
        
        self.scan_result.setText(
            "No scan performed"
        )

        if hasattr(self, "current_drive"):
            del self.current_drive
            
        if hasattr(self, "usb_connected_time"):
            del self.usb_connected_time

    def manual_scan(self):
        
        if hasattr(self, "scan_thread"):
            
            if self.scan_thread is not None:
                
                if self.scan_thread.isRunning():
                
                    return  # Prevent starting a new scan if one is already running

        if not hasattr(self, "current_drive"):
            return
        
        print("Starting scan:", self.current_drive)

        drives = get_usb_drives()

        if not drives:
            self.usb_info.setText(
                "USB device removed."
            )

            self.scan_button.hide()
            return

        self.usb_info.setText(
        """
        Scanning USB device...

        Please wait.
        """
        )
        
        self.usb_status_badge.setText(
            "● SCANNING"
        )

        self.usb_status_badge.setStyleSheet(
            """
            color: #8A6500;
            background-color: #FFF4CC;
            border: 1px solid #F2D36B;
            border-radius: 12px;
            padding: 5px 10px;
            font-size: 11px;
            font-weight: 800;
            """
        )
        
        self.scan_status_badge.setText(
            "● SCANNING"
        )

        self.scan_status_badge.setStyleSheet(
            """
            color: #8A6500;
            background-color: #FFF4CC;
            border: 1px solid #F2D36B;
            border-radius: 10px;
            padding: 10px 14px;
            font-size: 14px;
            font-weight: 800;
            """
        )

        self.scan_summary.setText(
            "USB Guardian is checking this device for security threats."
        )

        self.scan_result.setText(
    """
        Microsoft Defender and YARA analysis are currently running.

        Results will appear when the scan is complete.
        """
        )

        self.scan_progress.show()

        self.scan_button.setText(
            "Scan Again"
        )

        self.scan_button.hide()
        self.ignore_button.hide()


        self.scan_thread = ScanThread(
            self.current_drive,
            self.usb_connected_time
        )


        self.scan_thread.scan_finished.connect(
            self.scan_completed
        )


        self.scan_thread.start()
        
    def scan_completed(self, result):
        
        self.scan_progress.hide()

        if result is None:

            self.scan_result.setText(
                "Scan failed: No result returned"
            )

            self.scan_button.setText("Scan USB")
            self.scan_button.show()

            return
        
        # YARA scan statistics
        files_discovered = result.get(
            "files_discovered",
            0
        )

        files_scanned = result.get(
            "files_scanned",
            0
        )

        scan_errors = result.get(
            "scan_errors",
            0
        )

        if result["status"] == "ERROR":

            self.scan_status_badge.setText(
                "● SCAN ERROR"
            )

            self.scan_status_badge.setStyleSheet(
                """
                color: #A12A2A;
                background-color: #FDECEC;
                border: 1px solid #F2B8B8;
                border-radius: 10px;
                padding: 10px 14px;
                font-size: 14px;
                font-weight: 800;
                """
            )

            self.scan_summary.setText(
                "USB Guardian could not complete the security scan."
            )
            
            self.scan_result.setText(
                f"""
    Scan Error:

    {result.get('message', 'Unknown error')}
    """
            )

            self.scan_button.setText("Scan USB")
            self.scan_button.show()

            return


        if result["status"] == "UNSAFE":
            
            self.scan_status_badge.setText(
                "● THREAT DETECTED"
            )

            self.scan_status_badge.setStyleSheet(
                """
                color: #A12A2A;
                background-color: #FDECEC;
                border: 1px solid #F2B8B8;
                border-radius: 10px;
                padding: 10px 14px;
                font-size: 14px;
                font-weight: 800;
                """
            )

            self.scan_summary.setText(
                f"USB Guardian detected "
                f"{result.get('threats', 0)} threat(s) on this device."
            )

            detected_files = result.get(
                "detected_files",
                []
            )

            threat_ids = result.get(
                "threat_ids",
                []
            )

            sha256 = result.get(
                "sha256"
            )
            
            remediation_status = result.get(
                "remediation_status",
                "NONE"
            )
            
            detection_engine = result.get(
                "detection_engine",
                "Unknown"
            )

            yara_rules = result.get(
                "yara_rules",
                []
            )
            
            if remediation_status == "REMEDIATED_BY_DEFENDER":

                remediation_text = (
                    "Remediated by Microsoft Defender"
                )

            elif remediation_status == "QUARANTINED_BY_USB_GUARDIAN":

                remediation_text = (
                    "Quarantined by USB Guardian"
                )

            elif remediation_status == "QUARANTINE_FAILED":

                remediation_text = (
                    "Quarantine failed"
                )

            else:

                remediation_text = (
                    "No remediation information available"
                )


            if detected_files:

                detected_files_text = "\n".join(
                    detected_files
                )

            else:

                detected_files_text = (
                    "Threat detected, but file details "
                    "were unavailable."
                )


            if threat_ids:

                threat_ids_text = ", ".join(
                    str(threat_id)
                    for threat_id in threat_ids
                )

            else:

                threat_ids_text = "Unavailable"

            if yara_rules:

                yara_rules_text = ", ".join(
                    str(rule)
                    for rule in yara_rules
                )

            else:

                yara_rules_text = "None"

            if sha256:

                sha256_text = sha256

            else:

                sha256_text = (
                    "Unavailable - file may have been "
                    "blocked or remediated by antivirus."
                )


            self.scan_result.setText(
                f"""
        Result:              UNSAFE
        Threats:             {result.get('threats', 0)}
        Detection Engine:    {detection_engine}
        YARA Rule:           {yara_rules_text}

        Detected File:       {detected_files_text}
        Threat ID:           {threat_ids_text}
        SHA-256:             {sha256_text}

        Remediation:         {remediation_text}
        Files Scanned:       {files_scanned} / {files_discovered}
        Scan Errors:         {scan_errors}
        Duration:            {result.get('duration', 0)} seconds
        """
            )

        else:

            self.scan_status_badge.setText(
                "● SAFE"
            )

            self.scan_status_badge.setStyleSheet(
                """
                color: #087A4B;
                background-color: #E8F6EF;
                border: 1px solid #B9E5D0;
                border-radius: 10px;
                padding: 10px 14px;
                font-size: 14px;
                font-weight: 800;
                """
            )

            self.scan_summary.setText(
                "No threats were detected on this USB device."
            )

            self.scan_result.setText(
                f"""
        Result:              {result['status']}
        Threats:             {result.get('threats', 0)}
        Detection Engine:    {result.get('detection_engine', 'Unknown')}

        Files Scanned:       {files_scanned} / {files_discovered}
        Scan Errors:         {scan_errors}
        Duration:            {result.get('duration', 0)} seconds
        """
            )


        self.usb_status_badge.setText(
            "● SCAN COMPLETE"
        )

        self.usb_status_badge.setStyleSheet(
            """
            color: #087A4B;
            background-color: #E8F6EF;
            border: 1px solid #B9E5D0;
            border-radius: 12px;
            padding: 5px 10px;
            font-size: 11px;
            font-weight: 800;
            """
        )

        self.usb_device_name.setText(
            result.get(
                "device",
                "Unknown USB Device"
            )
        )

        self.usb_info.setText(
            f"Drive: {result.get('drive', 'Unknown')}\n"
            f"Connection: USB Storage\n"
            f"Security Status: {result['status']}"
        )


        # Allow rescanning
        self.scan_button.setText("Scan Again")
        self.scan_button.show()


        self.scan_completed_signal.emit(result)



    def ignore_usb(self):

        self.scan_result.setText(
            "Scan skipped by user."
        )

        self.scan_button.setText(
            "Scan USB"
        )

        self.scan_button.show()
        self.ignore_button.hide()

        
    def update_usb_status(self):

        drives = get_usb_drives()


        if not drives:

            self.usb_info.setText(
                "No USB device detected"
            )

            return


        drive = drives[0]


        self.usb_info.setText(
            f"""
    Device:
    {drive['DiskName']}

    Drive:
    {drive['DriveLetter']}:

    Connection:
    USB
    """
        )
        
    def closeEvent(self, event):

        if hasattr(self, "monitor"):

            self.monitor.stop()

        event.accept()
