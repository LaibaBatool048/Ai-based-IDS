from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QComboBox, QFrame, QGridLayout, QPushButton, QHBoxLayout, QMessageBox
)
from PyQt5.QtCore import Qt
import sys
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import sqlite3
import datetime
from openpyxl import load_workbook

class ReportsPage(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Attack Reports")
        self.setGeometry(200, 200, 500, 400)
        self.setStyleSheet("background-color:rgb(240, 240, 240); color: white;")
        
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        
        header = QLabel("ATTACK REPORTS", self)
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("font-size: 32px; font-weight: bold; color:rgb(18, 96, 165) ;")
        layout.addWidget(header)
        
        container = QFrame(self)
        container.setStyleSheet("background-color: #d4d4d4; padding: 20px; border-radius: 10px; color: black;")
        container_layout = QGridLayout()
        
        type_label = QLabel("Attack Type:")
        type_label.setStyleSheet("font-size: 22px;font-weight: bold;")
        self.type_dropdown = QComboBox()
        self.type_dropdown.addItems(["DOS", "Probe", "U2R", "R2L", "ALL"])
        self.type_dropdown.setStyleSheet("font-size: 17px;")
        
        self.type_dropdown.setInsertPolicy(QComboBox.NoInsert)
        self.type_dropdown.setMaxVisibleItems(5)
        self.type_dropdown.setDuplicatesEnabled(False)
        self.type_dropdown.setPlaceholderText("Select Types...")
        
        time_label = QLabel("Time:")
        time_label.setStyleSheet("font-size: 22px;font-weight: bold;")
        self.time_dropdown = QComboBox()
        self.time_dropdown.addItems(["Monthly", "Weekly", "Daily"])
        self.time_dropdown.setStyleSheet("font-size: 17px;")
        
        format_label = QLabel("Format:")
        format_label.setStyleSheet("font-size: 22px;font-weight: bold;")
        self.format_dropdown = QComboBox()
        self.format_dropdown.addItems(["Excel", "PDF"])
        self.format_dropdown.setStyleSheet("font-size: 17px;")
        
        self.generate_button = QPushButton("GENERATE REPORT")
        self.generate_button.setStyleSheet(
            "QPushButton {"
            "background-color: rgb(18, 96, 165); color: white; font-size: 18px;font-weight: bold; padding: 10px; border-radius: 5px; border: none;"
            "} "
            "QPushButton:hover {"
            "background-color: #004080; "
            "} "
        )
        self.generate_button.setCursor(Qt.PointingHandCursor)
        self.generate_button.clicked.connect(self.generate_report)

        container_layout.addWidget(type_label, 0, 0)
        container_layout.addWidget(self.type_dropdown, 0, 1)
        container_layout.addWidget(time_label, 1, 0)
        container_layout.addWidget(self.time_dropdown, 1, 1)
        container_layout.addWidget(format_label, 2, 0)
        container_layout.addWidget(self.format_dropdown, 2, 1)
        container_layout.addWidget(self.generate_button, 3, 0, 1, 2)
        
        container.setLayout(container_layout)
        container.setFixedWidth(450)
        container.setFixedHeight(450)
        
        container_h_layout = QHBoxLayout()
        container_h_layout.addWidget(container)
        container_h_layout.setAlignment(Qt.AlignCenter)
        
        layout.addLayout(container_h_layout)
        
        self.setLayout(layout)
    
    def show_message(self, title, message):
        msg = QMessageBox()
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setIcon(QMessageBox.Information)
        msg.exec_()
    
    def generate_pdf(self, df):
        pdf_filename = "attack_report.pdf"
        c = canvas.Canvas(pdf_filename, pagesize=letter)
        c.drawString(100, 750, "Attack Report")

        y_position = 720
        for index, row in df.iterrows():
            c.drawString(100, y_position, f"{row['prediction']} - {row['timestamp']}")
            y_position -= 20
            if y_position < 100:
                c.showPage()
                y_position = 750

        c.save()
        self.show_message("Success", "PDF report generated successfully!")

    def generate_excel(self, df):
        excel_filename = "attack_report.xlsx"
        df.to_excel(excel_filename, index=False, engine="openpyxl")
        wb = load_workbook(excel_filename)
        ws = wb.active

        for col in ws.columns:
            max_length = 0
            col_letter = col[0].column_letter
            for cell in col:
                try:
                    if cell.value:
                        max_length = max(max_length, len(str(cell.value)))
                except:
                    pass
            ws.column_dimensions[col_letter].width = max_length + 5

        wb.save(excel_filename)
        self.show_message("Success", "Excel report generated successfully!")

    def generate_report(self):
        attack_type = self.type_dropdown.currentText()
        time_frame = self.time_dropdown.currentText()
        file_format = self.format_dropdown.currentText()

        conn = sqlite3.connect("IDS.db")
        cursor = conn.cursor()

        now = datetime.datetime.now()
        time_filter = ""

        if time_frame == "Daily":
            time_filter = f"AND timestamp >= '{now.strftime('%Y-%m-%d')} 00:00:00'"
        elif time_frame == "Weekly":
            week_ago = now - datetime.timedelta(days=7)
            time_filter = f"AND timestamp >= '{week_ago.strftime('%Y-%m-%d')} 00:00:00'"
        elif time_frame == "Monthly":
            month_ago = now - datetime.timedelta(days=30)
            time_filter = f"AND timestamp >= '{month_ago.strftime('%Y-%m-%d')} 00:00:00'"

        query = "SELECT timestamp, prediction FROM detected_attacks WHERE 1=1 "
    
        if attack_type != "ALL":
            query += f"AND prediction = '{attack_type}' "
    
        query += time_filter

        df = pd.read_sql_query(query, conn)
        conn.close()

        if df.empty:
            self.show_message("No Data", "No data found for the selected filters.")
            return

        if file_format == "Excel":
            self.generate_excel(df)
        else:
            self.generate_pdf(df)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ReportsPage()
    window.show()
    window.showMaximized()
    sys.exit(app.exec_())
