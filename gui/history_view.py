import json
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import QHeaderView
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QDialog,
    QFormLayout,
    QDialogButtonBox,
    QPushButton,
    QMessageBox,
    QFrame
)
from PySide6.QtCore import Qt
from database.database import get_scan_history
from reports.report_generator import generate_pdf_scan_report

class HistoryView(QWidget):

    def __init__(self):

        super().__init__()


        # =========================
        # MAIN PAGE LAYOUT
        # =========================

        layout = QVBoxLayout()

        layout.setContentsMargins(
            30,
            20,
            30,
            25
        )

        layout.setSpacing(16)


        # =========================
        # PAGE HEADER
        # =========================

        title = QLabel(
            "Scan History"
        )

        title.setStyleSheet(
            """
            font-size: 28px;
            font-weight: bold;
            color: #073B2C;
            """
        )

        subtitle = QLabel(
            "Review previous USB security scans and detection results"
        )

        subtitle.setStyleSheet(
            """
            font-size: 13px;
            color: #6B7C75;
            """
        )

        layout.addWidget(title)
        layout.addWidget(subtitle)


        # =========================
        # HISTORY SECTION HEADER
        # =========================

        section_layout = QHBoxLayout()

        section_title = QLabel(
            "Security Scan Records"
        )

        section_title.setStyleSheet(
            """
            font-size: 17px;
            font-weight: bold;
            color: #073B2C;
            """
        )

        section_hint = QLabel(
            "Double-click a record to view full details"
        )

        section_hint.setAlignment(
            Qt.AlignRight | Qt.AlignVCenter
        )

        section_hint.setStyleSheet(
            """
            font-size: 12px;
            color: #74827C;
            """
        )

        section_layout.addWidget(
            section_title
        )

        section_layout.addStretch()

        section_layout.addWidget(
            section_hint
        )

        layout.addLayout(
            section_layout
        )


        self.table = QTableWidget()


        self.table.setColumnCount(12)


        self.table.setHorizontalHeaderLabels(
            [
                "Time",
                "Device",
                "Drive",
                "Result",
                "Threats",
                "Duration",
                "Detected File",
                "SHA-256",
                "Threat ID",
                "Remediation",
                "Detection Engine",
                "YARA Rule"
            ]
        )

        # Allow columns to use practical widths instead of
        # squeezing all 12 columns into the window.
        header = self.table.horizontalHeader()

        header.setSectionResizeMode(
            QHeaderView.Interactive
        )
        
        self.table.setAlternatingRowColors(True)

        self.table.setSelectionBehavior(
            QTableWidget.SelectRows
        )

        self.table.setSelectionMode(
            QTableWidget.SingleSelection
        )

        self.table.setShowGrid(False)

        self.table.verticalHeader().setVisible(
            False
        )

        self.table.verticalHeader().setDefaultSectionSize(
            42
        )

        self.table.setStyleSheet(
            """
            QTableWidget {
                background-color: white;
                alternate-background-color: #F7FAF8;
                border: 1px solid #D6E0DB;
                border-radius: 10px;
                color: #173C30;
                font-size: 12px;
                selection-background-color: #FFF0B8;
                selection-color: #073B2C;
            }

            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #E8EEEB;
            }

            QHeaderView::section {
                background-color: #0B6546;
                color: white;
                border: none;
                padding: 10px 8px;
                font-weight: bold;
                font-size: 12px;
            }

            QTableCornerButton::section {
                background-color: #0B6546;
                border: none;
            }

            QScrollBar:horizontal {
                height: 12px;
            }

            QScrollBar:vertical {
                width: 12px;
            }
            """
        )

        # Set useful default widths for each column.
        self.table.setColumnWidth(0, 150)   # Time
        self.table.setColumnWidth(1, 180)   # Device
        self.table.setColumnWidth(2, 70)    # Drive
        self.table.setColumnWidth(3, 90)    # Result
        self.table.setColumnWidth(4, 80)    # Threats
        self.table.setColumnWidth(5, 90)    # Duration
        self.table.setColumnWidth(6, 260)   # Detected File
        self.table.setColumnWidth(7, 300)   # SHA-256
        self.table.setColumnWidth(8, 110)   # Threat ID
        self.table.setColumnWidth(9, 220)   # Remediation
        self.table.setColumnWidth(10, 190)  # Detection Engine
        self.table.setColumnWidth(11, 220)  # YARA Rule

        self.table.cellDoubleClicked.connect(
            self.show_scan_details
        )

        layout.addWidget(
            self.table
        )


        self.setLayout(
            layout
        )


        self.load_history()


    def refresh_history(self):

        self.load_history()


    def load_history(self):

        records = get_scan_history()


        self.table.setRowCount(
            len(records)
        )


        for row, record in enumerate(records):

            values = list(record)

            # Format detected files
            try:
                detected_files = json.loads(
                    values[6]
                ) if values[6] else []

                values[6] = ", ".join(
                    detected_files
                ) if detected_files else "-"
            except (json.JSONDecodeError, TypeError):
                values[6] = "-"


            # Format SHA-256
            if not values[7]:
                values[7] = "-"


            # Format threat IDs
            try:
                threat_ids = json.loads(
                    values[8]
                ) if values[8] else []

                values[8] = ", ".join(
                    str(threat_id)
                    for threat_id in threat_ids
                ) if threat_ids else "-"
            except (json.JSONDecodeError, TypeError):
                values[8] = "-"


            # Format remediation status for display
            remediation_map = {
                "NONE": "None",
                "QUARANTINED_BY_USB_GUARDIAN": "Quarantined by USB Guardian",
                "REMEDIATED_BY_DEFENDER": "Remediated by Microsoft Defender",
                "QUARANTINE_FAILED": "Quarantine Failed"
            }

            if values[9]:
                values[9] = remediation_map.get(
                    values[9],
                    values[9]
                )
            else:
                values[9] = "-"
            
            # Format detection engine
            if not values[10]:
                values[10] = "-"


            # Format YARA rules
            try:
                yara_rules = json.loads(
                    values[11]
                ) if values[11] else []

                values[11] = ", ".join(
                    str(rule)
                    for rule in yara_rules
                ) if yara_rules else "-"

            except (json.JSONDecodeError, TypeError):
                values[11] = "-"
            
            # Format duration
            values[5] = f"{values[5]} s"


            for column, value in enumerate(values):

                item = QTableWidgetItem(
                    str(value)
                )

                # Highlight the scan result column.
                if column == 3:

                    result = str(value).upper()

                    font = QFont()
                    font.setBold(True)
                    item.setFont(font)

                    if result == "SAFE":

                        item.setForeground(
                            QColor("#087A52")
                        )

                        item.setBackground(
                            QColor("#EAF8F1")
                        )

                    elif result == "UNSAFE":

                        item.setForeground(
                            QColor("#B42318")
                        )

                        item.setBackground(
                            QColor("#FDECEC")
                        )

                self.table.setItem(
                    row,
                    column,
                    item
                )
                
                
    def show_scan_details(self, row, column):

        dialog = QDialog(self)

        dialog.setWindowTitle(
            "USB Guardian - Scan Details"
        )

        dialog.resize(
            760,
            620
        )

        dialog.setStyleSheet(
            """
            QDialog {
                background-color: #F5F7F6;
            }

            QLabel {
                color: #173C30;
            }

            QPushButton {
                min-height: 38px;
                border-radius: 8px;
                font-weight: bold;
            }
            """
        )


        # =========================
        # MAIN LAYOUT
        # =========================

        layout = QVBoxLayout(dialog)

        layout.setContentsMargins(
            28,
            24,
            28,
            24
        )

        layout.setSpacing(16)


        # =========================
        # HEADER
        # =========================

        title = QLabel(
            "Security Scan Details"
        )

        title.setStyleSheet(
            """
            font-size: 24px;
            font-weight: bold;
            color: #073B2C;
            """
        )

        subtitle = QLabel(
            "Detailed information from the selected USB security scan"
        )

        subtitle.setStyleSheet(
            """
            font-size: 12px;
            color: #6B7C75;
            """
        )

        layout.addWidget(title)
        layout.addWidget(subtitle)


        # =========================
        # RESULT STATUS
        # =========================

        result_item = self.table.item(
            row,
            3
        )

        result = (
            result_item.text().upper()
            if result_item
            else "UNKNOWN"
        )

        status_label = QLabel()

        status_label.setAlignment(
            Qt.AlignCenter
        )

        status_label.setMinimumHeight(
            44
        )

        if result == "SAFE":

            status_label.setText(
                "● SAFE"
            )

            status_label.setStyleSheet(
                """
                QLabel {
                    background-color: #EAF8F1;
                    color: #087A52;
                    border: 1px solid #A8DFC8;
                    border-radius: 9px;
                    font-size: 14px;
                    font-weight: bold;
                }
                """
            )

        elif result == "UNSAFE":

            status_label.setText(
                "● THREAT DETECTED"
            )

            status_label.setStyleSheet(
                """
                QLabel {
                    background-color: #FDECEC;
                    color: #B42318;
                    border: 1px solid #F3AAA5;
                    border-radius: 9px;
                    font-size: 14px;
                    font-weight: bold;
                }
                """
            )

        else:

            status_label.setText(
                "● UNKNOWN"
            )

        layout.addWidget(
            status_label
        )


        # =========================
        # DETAILS CARD
        # =========================

        details_card = QFrame()

        details_card.setStyleSheet(
            """
            QFrame {
                background-color: white;
                border: 1px solid #D6E0DB;
                border-radius: 10px;
            }

            QLabel {
                border: none;
                background: transparent;
            }
            """
        )

        card_layout = QVBoxLayout(
            details_card
        )

        card_layout.setContentsMargins(
            22,
            20,
            22,
            20
        )

        card_title = QLabel(
            "Scan Information"
        )

        card_title.setStyleSheet(
            """
            font-size: 16px;
            font-weight: bold;
            color: #073B2C;
            """
        )

        card_layout.addWidget(
            card_title
        )


        form = QFormLayout()

        form.setHorizontalSpacing(
            30
        )

        form.setVerticalSpacing(
            10
        )

        field_names = [
            "Time",
            "Device",
            "Drive",
            "Result",
            "Threats",
            "Duration",
            "Detected File",
            "SHA-256",
            "Threat ID",
            "Remediation",
            "Detection Engine",
            "YARA Rule"
        ]


        for column_index, field_name in enumerate(
            field_names
        ):

            item = self.table.item(
                row,
                column_index
            )

            value = (
                item.text()
                if item
                else "-"
            )


            field_label = QLabel(
                f"{field_name}:"
            )

            field_label.setStyleSheet(
                """
                font-weight: bold;
                color: #36584C;
                """
            )


            value_label = QLabel(
                value
            )

            value_label.setWordWrap(
                True
            )

            value_label.setTextInteractionFlags(
                Qt.TextSelectableByMouse
            )


            form.addRow(
                field_label,
                value_label
            )


        card_layout.addLayout(
            form
        )

        layout.addWidget(
            details_card
        )


        # =========================
        # ACTION BUTTONS
        # =========================

        button_layout = QHBoxLayout()

        generate_button = QPushButton(
            "Generate PDF Report"
        )

        generate_button.setCursor(
            Qt.PointingHandCursor
        )

        generate_button.setStyleSheet(
            """
            QPushButton {
                background-color: #F8C63D;
                color: #173C30;
                border: none;
                padding: 8px 18px;
            }

            QPushButton:hover {
                background-color: #FFD65C;
            }

            QPushButton:pressed {
                background-color: #E8B52F;
            }
            """
        )

        generate_button.clicked.connect(
            lambda: self.generate_report_for_row(
                row
            )
        )


        close_button = QPushButton(
            "Close"
        )

        close_button.setCursor(
            Qt.PointingHandCursor
        )

        close_button.setStyleSheet(
            """
            QPushButton {
                background-color: white;
                color: #0B6546;
                border: 1px solid #0B6546;
                padding: 8px 18px;
            }

            QPushButton:hover {
                background-color: #EAF8F1;
            }
            """
        )

        close_button.clicked.connect(
            dialog.reject
        )


        button_layout.addWidget(
            generate_button
        )

        button_layout.addWidget(
            close_button
        )

        layout.addLayout(
            button_layout
        )


        dialog.exec()
        
    def generate_report_for_row(self, row):

        def get_value(column):

            item = self.table.item(
                row,
                column
            )

            return (
                item.text()
                if item
                else "-"
            )

        scan_data = {
            "time": get_value(0),
            "device": get_value(1),
            "drive": get_value(2),
            "result": get_value(3),
            "threats": get_value(4),
            "duration": get_value(5),
            "detected_file": get_value(6),
            "sha256": get_value(7),
            "threat_id": get_value(8),
            "remediation": get_value(9),
            "detection_engine": get_value(10),
            "yara_rule": get_value(11)
        }

        try:

            report_path = generate_pdf_scan_report(
                scan_data
            )

            QMessageBox.information(
                self,
                "Report Generated",
                (
                    "USB Guardian PDF security report "
                    "generated successfully.\n\n"
                    f"Saved to:\n{report_path}"
                )
            )

        except Exception as error:

            QMessageBox.critical(
                self,
                "Report Generation Failed",
                (
                    "USB Guardian could not generate "
                    "the security report.\n\n"
                    f"Error:\n{error}"
                )
            )
