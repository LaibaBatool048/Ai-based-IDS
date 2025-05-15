from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, 
    QHBoxLayout, QFrame, QScrollArea
)
from PyQt5.QtGui import QPixmap, QIcon
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QSizePolicy
import sys
import sqlite3
import os  # Added for checking file existence

class NotificationPage(QWidget):
    """ Notification Widget containing icon, title, message, and close button """
    def __init__(self, title="Notification Title", message="This is a sample message", icon_path="notification_icon.png"):
        super().__init__()

        self.setStyleSheet("""
            background-color: rgb(205, 226, 244); 
            border-radius: 8px; 
            padding: 10px; 
            border: 1px solid #ddd;
        """)

        layout = QHBoxLayout()

        # Icon
        self.icon = QLabel()
        if os.path.exists(icon_path):  # ✅ Fix: Check if file exists
            pixmap = QPixmap(icon_path).scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        else:
            pixmap = QPixmap()  # Use an empty pixmap to avoid null errors

        self.icon.setPixmap(pixmap)
        layout.addWidget(self.icon)

        # Text
        text_layout = QVBoxLayout()
        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("font-weight: bold; font-size: 14px; color: black;")
        
        self.message_label = QLabel(message)
        self.message_label.setStyleSheet("font-size: 12px; color: gray;")

        text_layout.addWidget(self.title_label)
        text_layout.addWidget(self.message_label)
        layout.addLayout(text_layout)

        # Close Button
        self.close_button = QPushButton("X")
        self.close_button.setFixedSize(24, 24)
        self.close_button.setStyleSheet("""
            background-color: red; 
            color: white; 
            font-weight: bold;
            border: none;
            border-radius: 12px;
        """)
        self.close_button.clicked.connect(self.close)
        layout.addWidget(self.close_button)

        self.setLayout(layout)

class NotificationCenter(QWidget):
    """ Notification Center UI - Displays Attack Alerts in a Single Layout """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Notifications")
        self.setGeometry(100, 100, 600, 500)  # Slightly larger for better readability
        self.setStyleSheet("background-color: #f8f8f8; padding: 10px;")

        self.main_layout = QVBoxLayout()  # ✅ Single layout for all notifications

        # **Header**
        header_layout = QHBoxLayout()
        self.header_label = QLabel("Attack Notifications")
        self.header_label.setStyleSheet("font-size: 20px; font-weight: bold; color: black;")
        header_layout.addWidget(self.header_label)
        self.main_layout.addLayout(header_layout)

        # **Scroll Area for Notifications**
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)

        self.notification_frame = QWidget()
        self.notification_layout = QVBoxLayout()
        self.notification_frame.setLayout(self.notification_layout)

        self.scroll_area.setWidget(self.notification_frame)
        self.main_layout.addWidget(self.scroll_area)

        self.setLayout(self.main_layout)

        # **Load attack notifications**
        self.load_notifications()

    def load_notifications(self):
        """ Load attack notifications from the database and display them """
        conn = sqlite3.connect("IDS.db")
        cursor = conn.cursor()

        # **Retrieve detected attacks with timestamp & key features**
        cursor.execute("SELECT timestamp, prediction, src_bytes, dst_bytes, service FROM detected_attacks ORDER BY timestamp DESC")
        attack_logs = cursor.fetchall()

        

        for log in attack_logs:
            timestamp, attack_type, src_bytes, dst_bytes, service = log
            self.add_notification(attack_type, timestamp, src_bytes, dst_bytes, service)

        conn.close()

    def add_notification(self, attack_type, timestamp, src_bytes, dst_bytes, service):
        """ Add a new attack notification with key details """
       

        notif_text = f"<b>{attack_type}</b><br>" \
                     f"<span style='font-size: 14px;'>🕒 <b>Time:</b> {timestamp}</span><br>" \
                     f"<span style='font-size: 14px;'>📡 <b>Service:</b> {service}</span><br>" \
                     f"<span style='font-size: 14px;'>📥 <b>Src Bytes:</b> {src_bytes} | 📤 <b>Dst Bytes:</b> {dst_bytes}</span>"

        notif_label = QLabel(notif_text)
        notif_label.setStyleSheet(
            "background-color: white; padding: 15px; border: 1px solid #ccc; border-radius: 8px; "
            "font-size: 16px; color: black;"
        )
        notif_label.setWordWrap(True)
        notif_label.setTextFormat(Qt.RichText)  # ✅ Allows HTML formatting for bold text

        self.notification_layout.addWidget(notif_label)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NotificationCenter()
    window.show()
    sys.exit(app.exec_())
