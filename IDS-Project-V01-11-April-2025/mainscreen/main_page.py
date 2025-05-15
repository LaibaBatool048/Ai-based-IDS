from PyQt5 import QtWidgets, uic, QtGui
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QMainWindow, QApplication, QPushButton, QMessageBox, QListView
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtMultimedia import QSoundEffect
from PyQt5.QtCore import QUrl
from PyQt5 import QtCore  
import sys
import json
import os
from monitoring_controller import MonitoringController
import images
import resources
from graph import LiveGraph
from PyQt5.QtCore import QObject, pyqtSignal, QThread

CONFIG_FILE = "config.txt"

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi("mainscreen/frontpage.ui", self)
        
        # Load settings
        self.current_font_size, self.current_sensitivity, self.popup_enabled, self.sound_enabled = self.load_settings()

        #Initialize monitoring controller
        self.monitoring_controller = MonitoringController(self)
        self.monitoring_controller.alert_triggered.connect(self.handle_alert)
        self.monitoring_controller.status_updated.connect(self.update_status)
        
        # **🔹 Apply UI Setup**
        self.apply_font_size(self.load_font_size())
        self.setup_ui()

    def setup_ui(self):
        #Setup UI elements and navigation.
        self.stackedWidget.setCurrentIndex(0)
        self.icon_text_widget.hide()
        self.menu_btn.setChecked(True)
        
        self.connect_navigation()
        self.setup_dynamic_pages()
        self.setup_monitoring_button()
        self.setup_graph()
    
    
    def connect_navigation(self):
        self.home.clicked.connect(lambda: self.show_page(0))
        self.home_icon.clicked.connect(lambda: self.show_page(0))
        self.dashboard.clicked.connect(lambda: self.show_page(2))
        self.monitoring_bar.clicked.connect(lambda: self.show_page(2))
        self.dashboard_icon.clicked.connect(lambda: self.show_page(2))
        self.Notifications.clicked.connect(lambda: self.show_page(3))
        self.notification_bar.clicked.connect(lambda: self.show_page(3))
        self.notification_icon.clicked.connect(lambda: self.show_page(3))
        self.Reports.clicked.connect(lambda: self.show_page(4))
        self.reports_bar.clicked.connect(lambda: self.show_page(4))
        self.reports_icon.clicked.connect(lambda: self.show_page(4))
        self.Setting.clicked.connect(lambda: self.show_page(1))
        self.setting_bar.clicked.connect(lambda: self.show_page(1))
        self.setting_icon.clicked.connect(lambda: self.show_page(1))
    
    def setup_monitoring_button(self):
        self.btnMonitor = self.findChild(QPushButton, 'btnMonitor')
        if self.btnMonitor:
            self.btnMonitor.clicked.connect(self.toggle_monitoring)
            self.update_button_state()
    
    def toggle_monitoring(self):
        if self.monitoring_controller.is_running:
            self.monitoring_controller.stop_monitoring()
            
        else:
            self.monitoring_controller.start_monitoring()

        self.update_button_state()


    def update_button_state(self):
        if hasattr(self, 'btnMonitor') and self.btnMonitor:
            self.btnMonitor.setChecked(self.monitoring_controller.is_running)
            self.btnMonitor.setText(
                "Stop Monitoring" if self.monitoring_controller.is_running 
                else "Start Monitoring"
            )
        
    
    def handle_alert(self, attack_type, preventions):
        
        print(f"Main thread: {QThread.currentThread() == QApplication.instance().thread()}")  # Debug

        print(f"Handle alert called! Attack: {attack_type}")  # Debug
        print(f"Current settings - popup: {self.popup_enabled}, sound: {self.sound_enabled}")  # Debug

        # Reload settings to get current values
        self.current_font_size, self.current_sensitivity, self.popup_enabled, self.sound_enabled = self.load_settings()
        # Play alert sound
        sound = QSoundEffect()
        sound.setSource(QUrl.fromLocalFile("alert.wav"))  # Path to your sound file
        sound.setLoopCount(1)  # Play once
        sound.setVolume(1.0)  # Maximum volume
        if self.sound_enabled==True:
            sound.play()
        
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("🚨 IDS Alert")
        prevention_text = "\n".join(f"• {p[0]}" for p in preventions) if preventions else "No prevention available"
        msg.setText(f"⚠️ Attack Detected: {attack_type}\n\n💡 Prevention Measures:\n{prevention_text}")
        if self.popup_enabled== True:
            msg.exec_()
        self.update_status(f"ALERT: {attack_type} detected")
    
    def update_status(self, message):
        status_list = self.findChild(QtWidgets.QListView, "listView_2")
    
        if status_list:
            # Ensure model exists, or create one
            model = status_list.model()
            if model is None:
                model = QStandardItemModel(status_list)
                status_list.setModel(model)

            # Create a new list item with multi-line text
            item = QStandardItem(message)
            item.setEditable(False)  # Make it read-only
            model.appendRow(item)  # Add to the list

            # Auto-scroll to the latest entry
            status_list.scrollToBottom()
    
    def setup_dynamic_pages(self):
        from notifications import NotificationCenter  # Import Notification Page
        from report import ReportsPage  # Import Reports Page
        from setting import SettingsPage

        # Create instances
        self.notification_page = NotificationCenter()
        self.reports_page = ReportsPage()
        self.setting_page = SettingsPage()

        # Add them to stackedWidget
        self.stackedWidget.addWidget(self.notification_page)
        self.stackedWidget.addWidget(self.reports_page)
        self.stackedWidget.addWidget(self.setting_page)

        # Connect Notification button
        self.Notifications.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.notification_page))
        self.notification_bar.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.notification_page))
        self.notification_icon.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.notification_page))

        # Connect Reports button
        self.Reports.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.reports_page))
        self.reports_bar.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.reports_page))
        self.reports_icon.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.reports_page))


        # Connect Setting button
        self.Setting.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.setting_page))
        self.setting_bar.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.setting_page))
        self.setting_icon.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.setting_page))

    def setup_graph(self):
        graph_container = self.findChild(QWidget, "graph_widget")
        if graph_container:
        # Clear existing layout
            if graph_container.layout():
                QWidget().setLayout(graph_container.layout())
        
            self.live_graph = LiveGraph(self)
            layout = QVBoxLayout()
            layout.setContentsMargins(0, 0, 0, 0)  # Reduce margins
            layout.addWidget(self.live_graph)
            graph_container.setLayout(layout)
        
        # Use queued connection for thread safety
            self.monitoring_controller.data_updated.connect(
                self.live_graph.update_graph,
                QtCore.Qt.QueuedConnection
            )

            print("Graph connection established:", self.live_graph is not None)  # Debug

    
    def apply_font_size(self, font_size):
        font_sizes = {"Small": 11, "Medium": 12, "Large": 13}
        font = QtGui.QFont()
        font.setPointSize(font_sizes.get(font_size, 14))
        self.setFont(font)
        for widget in self.findChildren(QWidget):
            widget.setFont(font)
    
    def load_font_size(self):
        if not os.path.exists(CONFIG_FILE):
            return "Medium"
        try:
            with open(CONFIG_FILE, "r") as file:
                settings = json.load(file)
                return settings.get("font_size", "Medium")
        except (json.JSONDecodeError, FileNotFoundError):
            return "Medium"
    
    def load_settings(self):
        """Load settings from config.txt or set defaults if missing"""
        if not os.path.exists(CONFIG_FILE):
            self.save_settings()  # Create config file if it doesn’t exist
            return "Medium", "Medium", True, True  # Default values

        try:
            with open(CONFIG_FILE, "r") as file:
                    settings = json.load(file)
                    return (
                        settings.get("font_size", "Medium"),
                        settings.get("sensitivity", "Medium"),
                        bool(settings.get("popup_notifications", True)),
                        bool(settings.get("sound_alerts", True))
                    )
        except (json.JSONDecodeError, FileNotFoundError):
            return "Medium", "Medium", True, True
        
    def save_settings(self):

        # Get current values from UI
        font_size = self.font_size_combo.currentText()
        sensitivity = self.sensitivity_combo.currentText()
        popup_enabled = self.popup_toggle.isChecked()
        sound_enabled = self.sound_toggle.isChecked()
        
        # Update main window settings
        self.main_window.current_font_size = font_size
        self.main_window.current_sensitivity = sensitivity
        self.main_window.popup_enabled = popup_enabled
        self.main_window.sound_enabled = sound_enabled

        """Save all settings to config.txt"""
        settings = {
                "font_size": self.current_font_size,
                "sensitivity": self.current_sensitivity,
                "popup_notifications": self.popup_toggle.isChecked(),
                "sound_alerts": self.sound_toggle.isChecked()
                }
        try:
            with open(CONFIG_FILE, "w") as file:
                json.dump(settings, file)
        except Exception as e:
            print(f"Error saving settings: {e}")

    def show_page(self, index):
        self.stackedWidget.setCurrentIndex(index)

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    window.showMaximized()
    sys.exit(app.exec_())