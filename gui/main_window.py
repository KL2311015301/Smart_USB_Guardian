from PySide6.QtCore import Qt

from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QHBoxLayout,
    QVBoxLayout,
    QPushButton,
    QStackedWidget,
    QLabel,
    QSystemTrayIcon,
    QStyle
)

from gui.dashboard import Dashboard
from gui.history_view import HistoryView
from gui.settings_view import SettingsView
from gui.notifications import show_scan_notification
from config.config_manager import load_settings


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("USB Guardian")
        self.resize(1000, 600)
        
        # =========================
        # SYSTEM TRAY
        # =========================

        self.tray_icon = QSystemTrayIcon(self)

        self.tray_icon.setIcon(
            self.style().standardIcon(
                QStyle.SP_ComputerIcon
            )
        )

        self.tray_icon.setToolTip(
            "USB Guardian"
        )

        self.tray_icon.show()

        main_widget = QWidget()
        self.setCentralWidget(main_widget)

        main_layout = QHBoxLayout()
        main_widget.setLayout(main_layout)


        # =========================
        # LEFT SIDEBAR
        # =========================

        sidebar_widget = QWidget()
        sidebar_widget.setObjectName("sidebar")
        sidebar_widget.setFixedWidth(240)

        sidebar = QVBoxLayout(sidebar_widget)

        sidebar.setContentsMargins(
            20,
            30,
            20,
            25
        )

        sidebar.setSpacing(12)


        # =========================
        # BRANDING
        # =========================

        title = QLabel(
            "USB\nGUARDIAN"
        )

        title.setObjectName(
            "sidebarTitle"
        )

        title.setAlignment(
            Qt.AlignCenter
        )


        subtitle = QLabel(
            "USB SECURITY SYSTEM"
        )

        subtitle.setObjectName(
            "sidebarSubtitle"
        )

        subtitle.setAlignment(
            Qt.AlignCenter
        )


        sidebar.addWidget(title)
        sidebar.addWidget(subtitle)

        sidebar.addSpacing(30)


        # =========================
        # NAVIGATION BUTTONS
        # =========================

        self.dashboard_button = QPushButton(
            "  Dashboard"
        )

        self.history_button = QPushButton(
            "  Scan History"
        )

        self.settings_button = QPushButton(
            "  Settings"
        )


        self.dashboard_button.setObjectName(
            "navButton"
        )

        self.history_button.setObjectName(
            "navButton"
        )

        self.settings_button.setObjectName(
            "navButton"
        )


        self.dashboard_button.setCheckable(True)
        self.history_button.setCheckable(True)
        self.settings_button.setCheckable(True)


        self.dashboard_button.setChecked(
            True
        )


        sidebar.addWidget(
            self.dashboard_button
        )

        sidebar.addWidget(
            self.history_button
        )

        sidebar.addWidget(
            self.settings_button
        )


        sidebar.addStretch()


        # =========================
        # PROTECTION INDICATOR
        # =========================

        protection_label = QLabel(
            "●  PROTECTION ACTIVE"
        )

        protection_label.setObjectName(
            "protectionLabel"
        )

        protection_label.setAlignment(
            Qt.AlignCenter
        )

        sidebar.addWidget(
            protection_label
        )


        main_layout.addWidget(
            sidebar_widget
        )


        # =========================
        # SIDEBAR STYLE
        # =========================

        sidebar_widget.setStyleSheet(
            """
            QWidget#sidebar {
                background-color: #0B5D3B;
                border-radius: 0px;
            }

            QLabel#sidebarTitle {
                color: white;
                font-size: 27px;
                font-weight: 800;
                letter-spacing: 2px;
            }

            QLabel#sidebarSubtitle {
                color: #F4C542;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 1px;
            }

            QPushButton#navButton {
                background-color: transparent;
                color: white;

                border: none;
                border-radius: 8px;

                padding: 13px 15px;

                text-align: left;

                font-size: 14px;
                font-weight: 600;
            }

            QPushButton#navButton:hover {
                background-color: #167A50;
            }

            QPushButton#navButton:checked {
                background-color: #F4C542;
                color: #16382A;
                font-weight: 700;
            }

            QLabel#protectionLabel {
                color: #F4C542;

                background-color: #08472E;

                border: 1px solid #277A57;
                border-radius: 8px;

                padding: 11px;

                font-size: 11px;
                font-weight: 700;
            }
            """
        )

        # =========================
        # CONTENT AREA
        # =========================

        self.pages = QStackedWidget()


        self.dashboard = Dashboard()
        self.history = HistoryView()
        self.dashboard.scan_completed_signal.connect(
            lambda result: self.history.refresh_history()
        )
        self.dashboard.scan_completed_signal.connect(
            self.handle_scan_notification
        )
        self.settings = SettingsView()


        self.pages.addWidget(
            self.dashboard
        )

        self.pages.addWidget(
            self.history
        )

        self.pages.addWidget(
            self.settings
        )


        main_layout.addWidget(
            self.pages
        )



        # Button navigation

        self.dashboard_button.clicked.connect(
            lambda: (
                self.pages.setCurrentWidget(
                    self.dashboard
                ),
                self.set_active_navigation(
                    self.dashboard_button
                )
            )
        )


        self.history_button.clicked.connect(
            self.open_history
        )


        self.settings_button.clicked.connect(
            lambda: (
                self.pages.setCurrentWidget(
                    self.settings
                ),
                self.set_active_navigation(
                    self.settings_button
                )
            )
        )
    
    
    def handle_scan_notification(self, result):

        settings = load_settings()

        notifications_enabled = settings.get(
            "notifications",
            True
        )

        show_scan_notification(
            self.tray_icon,
            result,
            notifications_enabled
        )
    
        
    def closeEvent(self, event):

        if hasattr(self, "dashboard"):

            if hasattr(self.dashboard, "monitor"):

                self.dashboard.monitor.stop()


        event.accept()
        
    def set_active_navigation(self, active_button):

        buttons = [
            self.dashboard_button,
            self.history_button,
            self.settings_button
        ]

        for button in buttons:

            button.setChecked(
                button is active_button
            )
    
    def open_history(self):

        self.history.refresh_history()

        self.pages.setCurrentWidget(
            self.history
        )

        self.set_active_navigation(
            self.history_button
        )
