from PyQt5 import QtWidgets, QtGui, QtCore
import sqlite3
import os
import session

class LoginWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("AI Based Intrusion Detection System")

        # Get screen size and set the window size accordingly
        screen = QtWidgets.QDesktopWidget().screenGeometry()
        self.setGeometry(0, 0, screen.width(), screen.height())

        # Background Image
        self.background_label = QtWidgets.QLabel(self)
        self.background_label.setPixmap(QtGui.QPixmap("mainscreen/background.jpg"))  # Replace with your image
        self.background_label.setScaledContents(True)

        opacity_effect = QtWidgets.QGraphicsOpacityEffect()
        opacity_effect.setOpacity(0.5)  # Transparency Level
        self.background_label.setGraphicsEffect(opacity_effect)

        # Main Header
        self.main_label = QtWidgets.QLabel("AI Based Intrusion Detection System", self)
        self.main_label.setFont(QtGui.QFont("Arial", 30, QtGui.QFont.Bold))
        self.main_label.setStyleSheet("color: #073965; border-bottom: 2px solid black; padding-top: 100px;")
        self.main_label.setAlignment(QtCore.Qt.AlignCenter)

        # Login Container
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

        # Login Button
        self.login_button = QtWidgets.QPushButton("LOGIN", self.container)
        self.login_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.login_button.setStyleSheet("""
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
        self.login_button.clicked.connect(self.check_login)

        # Forgot Password Link
        self.forgot_password_label = QtWidgets.QLabel("<a href='#'>Forgot Password?</a>", self.container)
        self.forgot_password_label.setStyleSheet("color: blue; font-size: 13px; padding: 5px;")
        self.forgot_password_label.setAlignment(QtCore.Qt.AlignCenter)
        self.forgot_password_label.setTextInteractionFlags(QtCore.Qt.TextBrowserInteraction)
        self.forgot_password_label.linkActivated.connect(self.forgot_password_clicked)

        # Signup Link
        self.signup_label = QtWidgets.QLabel("<a href='#'>Do not have an account?</a>", self.container)
        self.signup_label.setStyleSheet("color: blue; font-size: 13px; padding: 5px;")
        self.signup_label.setAlignment(QtCore.Qt.AlignCenter)
        self.signup_label.setTextInteractionFlags(QtCore.Qt.TextBrowserInteraction)
        self.signup_label.linkActivated.connect(self.signup_clicked)

        self.resizeUI()

    def resizeUI(self):
        """Adjusts the UI dynamically based on window size"""
        width, height = self.width(), self.height()

        # Background Full-Screen
        self.background_label.setGeometry(0, 0, width, height)

        # Main Header at the Top
        self.main_label.setGeometry(int(width * 0.2), int(height * 0.1), int(width * 0.6), 200)

        # Centering Login Container
        container_width, container_height = int(width * 0.3), int(height * 0.4)
        self.container.setGeometry(int((width - container_width) / 2), int(height * 0.3), container_width, container_height)

        # Adjust Child Widgets inside Container
        padding_x, padding_y = 30, 20
        input_width, input_height = container_width - 2 * padding_x, 40
        button_width, button_height = input_width, 50  

        self.username.setGeometry(padding_x, 50, input_width, input_height)
        self.password.setGeometry(padding_x, 110, input_width, input_height)
        self.login_button.setGeometry(padding_x, 170, button_width, button_height)
        self.forgot_password_label.setGeometry(padding_x, 225, button_width, button_height)
        self.signup_label.setGeometry(padding_x, 250, button_width, button_height)

    def resizeEvent(self, event):
        """Triggers UI update when window is resized"""
        self.resizeUI()

    def check_login(self):
        """Verify user login details"""
        username = self.username.text()
        password = self.password.text()

        if self.authenticate_user(username, password):
            session.session.username = username
            session.session.password = password  

            # ✅ Save session in the database
            conn = sqlite3.connect("IDS.db")
            cursor = conn.cursor()
            cursor.execute("DELETE FROM session")  # Clear old session
            cursor.execute("INSERT INTO session (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            conn.close()

            print(f"Session Updated: {session.session.username}")

            self.open_main_dashboard()
        else:
            QtWidgets.QMessageBox.warning(self, "Login Failed", "Invalid username or password!")

    def authenticate_user(self, username, password):
        """Check username and password in the database"""
        conn = sqlite3.connect(os.path.join(os.getcwd(), "IDS.db"))
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user WHERE name = ? AND password = ?", (username, password))
        result = cursor.fetchone()
        conn.close()
        return result is not None

    def open_main_dashboard(self):
        """Open the main IDS dashboard"""
        self.close()
        os.system("python mainscreen/main_page.py")

    def forgot_password_clicked(self):
        os.system("python forget.py")

    def signup_clicked(self):
        window.close()
        os.system("python mainscreen/signup.py")

if __name__ == "__main__":
    app = QtWidgets.QApplication([])
    window = LoginWindow()
    window.showMaximized()
    app.exec_()
