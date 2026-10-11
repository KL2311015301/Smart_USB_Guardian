from config.config_manager import save_settings, load_settings

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QGroupBox,
    QRadioButton,
    QCheckBox,
    QPushButton
)


class SettingsView(QWidget):

    def __init__(self):

        super().__init__()

        layout = QVBoxLayout()


        title = QLabel(
            "Settings"
        )

        title.setStyleSheet(
            """
            font-size:28px;
            font-weight:bold;
            """
        )

        layout.addWidget(title)



        # Scan mode

        scan_group = QGroupBox(
            "Scan Mode"
        )

        scan_layout = QVBoxLayout()


        self.test_scan = QRadioButton(
            "Test Folder Mode"
        )

        self.full_scan = QRadioButton(
            "Full USB Scan"
        )


        scan_layout.addWidget(
            self.test_scan
        )

        scan_layout.addWidget(
            self.full_scan
        )


        scan_group.setLayout(
            scan_layout
        )

        layout.addWidget(
            scan_group
        )



        # Protection

        protection_group = QGroupBox(
            "Protection"
        )

        protection_layout = QVBoxLayout()


        self.auto_scan = QCheckBox(
            "Enable automatic USB scanning"
        )


        self.notifications = QCheckBox(
            "Enable notifications"
        )


        protection_layout.addWidget(
            self.auto_scan
        )

        protection_layout.addWidget(
            self.notifications
        )


        protection_group.setLayout(
            protection_layout
        )

        layout.addWidget(
            protection_group
        )



        # Engine

        engine = QLabel(
            "Antivirus Engine:\nMicrosoft Defender"
        )

        layout.addWidget(
            engine
        )



        save_button = QPushButton(
            "Save Settings"
        )


        save_button.clicked.connect(
            self.save
        )


        layout.addWidget(
            save_button
        )


        layout.addStretch()


        self.setLayout(
            layout
        )


        # Load saved values AFTER widgets exist
        self.load_settings()



    def load_settings(self):

        settings = load_settings()


        if settings.get("scan_mode") == "test":

            self.test_scan.setChecked(True)

        else:

            self.full_scan.setChecked(True)



        self.auto_scan.setChecked(
            settings.get("auto_scan", False)
        )


        self.notifications.setChecked(
            settings.get("notifications", True)
        )



    def save(self):

        settings = load_settings()


        settings["scan_mode"] = (
            "test"
            if self.test_scan.isChecked()
            else "full"
        )


        settings["auto_scan"] = (
            self.auto_scan.isChecked()
        )


        settings["notifications"] = (
            self.notifications.isChecked()
        )


        save_settings(
            settings
        )
