from PyQt5 import QtWidgets, QtGui, QtCore
import sqlite3
import os

class SignUpWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("AI Based Intrusion Detection System - Sign Up")

        # Get screen size and set the window size accordingly
        screen = QtWidgets.QDesktopWidget().screenGeometry()
        self.setGeometry(0, 0, screen.width(), screen.height())

        # Background Image
        self.background_label = QtWidgets.QLabel(self)
        self.background_label.setPixmap(QtGui.QPixmap("mainscreen/background_su.jpg"))  # Replace with your image
        self.background_label.setScaledContents(True)

        opacity_effect = QtWidgets.QGraphicsOpacityEffect()
        opacity_effect.setOpacity(0.5)  # Transparency Level
        self.background_label.setGraphicsEffect(opacity_effect)

        # Main Header
        self.main_label = QtWidgets.QLabel("AI Based Intrusion Detection System", self)
        self.main_label.setFont(QtGui.QFont("Arial", 30, QtGui.QFont.Bold))
        self.main_label.setStyleSheet("color: #073965; border-bottom: 2px solid black; padding-top: 100px;")
        self.main_label.setAlignment(QtCore.Qt.AlignCenter)

        # Sign Up Container
        self.container = QtWidgets.QFrame(self)

        # Username
        self.username = QtWidgets.QLineEdit(self.container)
        self.username.setPlaceholderText("USERNAME")
        self.username.setStyleSheet("background: white; border-radius: 5px; padding: 5px;")

        # Password
        self.password = QtWidgets.QLineEdit(self.container)
        self.password.setPlaceholderText("PASSWORD")
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password.setStyleSheet("background: white; border-radius: 5px; padding: 5px;")

        # Confirm Password
        self.confirm_password = QtWidgets.QLineEdit(self.container)
        self.confirm_password.setPlaceholderText("CONFIRM PASSWORD")
        self.confirm_password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.confirm_password.setStyleSheet("background: white; border-radius: 5px; padding: 5px;")

        # Sign Up Button
        self.signup_button = QtWidgets.QPushButton("SIGN UP", self.container)
        self.signup_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.signup_button.setStyleSheet("""
            QPushButton {
                background: navy;
                color: white;
                border-radius: 8px;
                border: 2px solid #002266;
                font-size: 18px;
                font-weight: bold;
                padding: 10px;
                transition: all 0.3s ease-in-out;
            }
            QPushButton:hover {
                background: #5353c6;
                border: 2px solid #0033aa;
            }
            QPushButton:pressed {
                background: linear-gradient(to bottom, #0044cc, #002299);
                border: 2px solid #001166;
            }
        """)
        self.signup_button.clicked.connect(self.create_account)

        # Already have an account
        self.already_account = QtWidgets.QLabel("<a href='#'>Already have an account? Login</a>", self.container)
        self.already_account.setStyleSheet("color: blue; font-size: 13px; border-radius: 25px;padding: 5px;")
        self.already_account.setAlignment(QtCore.Qt.AlignCenter)
        self.already_account.setTextFormat(QtCore.Qt.RichText)
        self.already_account.setTextInteractionFlags(QtCore.Qt.TextBrowserInteraction)
        self.already_account.linkActivated.connect(self.redirect_to_login)

        self.resizeUI()

    def resizeUI(self):
        width, height = self.width(), self.height()

        # Background Full-Screen
        self.background_label.setGeometry(0, 0, width, height)

        # Main Header at the Top
        self.main_label.setGeometry(int(width * 0.2), int(height * 0.1), int(width * 0.6), 200)

        # Centering Sign Up Container
        container_width, container_height = int(width * 0.3), int(height * 0.5)
        self.container.setGeometry(int((width - container_width) / 2), int(height * 0.3), container_width, container_height)

        # Adjust Child Widgets inside Container
        padding_x, padding_y = 30, 20
        input_width, input_height = container_width - 2 * padding_x, 40
        button_width, button_height = input_width, 50

        self.username.setGeometry(padding_x, 50, input_width, input_height)
        self.password.setGeometry(padding_x, 110, input_width, input_height)
        self.confirm_password.setGeometry(padding_x, 170, input_width, input_height)
        self.signup_button.setGeometry(padding_x, 230, button_width, button_height)
        self.already_account.setGeometry(padding_x, 290, button_width, button_height)

    def resizeEvent(self, event):
        self.resizeUI()

    def check_username_exists(self, username):
        conn = sqlite3.connect("IDS.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user WHERE name = ?", (username,))
        result = cursor.fetchone()
        conn.close()
        return result is not None

    def create_account(self):
        username = self.username.text()
        password = self.password.text()
        confirm_password = self.confirm_password.text()

        if password != confirm_password:
            QtWidgets.QMessageBox.warning(self, "Error", "Passwords do not match!")
            return
        if password == "" or username=="" or confirm_password=="":
            QtWidgets.QMessageBox.warning(self, "Error", "Fill all the fields")
            return
        

        if self.check_username_exists(username):
            QtWidgets.QMessageBox.warning(self, "Error", "Username already exists!")
            return

        conn = sqlite3.connect("IDS.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO user (name, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()

        QtWidgets.QMessageBox.information(self, "Success", "Account created successfully!")
        self.redirect_to_login()

    def redirect_to_login(self):
        window.close()
        os.system("python mainscreen/login_page.py")

if __name__ == "__main__":
    app = QtWidgets.QApplication([])
    window = SignUpWindow()
    window.showMaximized()
    app.exec_()
