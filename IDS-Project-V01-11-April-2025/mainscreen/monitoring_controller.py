from PyQt5.QtCore import QObject, pyqtSignal, QThread
import sqlite3
from scapy.all import sniff, IP, TCP, UDP, conf

# Set promiscuous mode on
conf.promisc = True  # Enable promiscuous mode

class MonitoringController(QObject):
    status_updated = pyqtSignal(str)
    alert_triggered = pyqtSignal(str, list)  # attack_type, preventions
    data_updated = pyqtSignal(int, int)  # (normal_count, attack_count)
    
    def __init__(self, main_page):
        super().__init__()
        self.main_page = main_page  # Store reference to main_page
        self.thread = None
        self.is_running = False
        self.normal_count = 0
        self.attack_count = 0
        self.db_connection = sqlite3.connect("IDS.db")
        self._init_db()
        
    def _init_db(self):
        cursor = self.db_connection.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS detected_attacks(
            timestamp TEXT,
            protocol_type VARCHAR(10), 
            src_bytes INTEGER, 
            dst_bytes INTEGER, 
            service VARCHAR(10), 
            flag INTEGER, 
            count INTEGER, 
            srv_count INTEGER, 
            same_srv_rate REAL, 
            diff_srv_rate REAL, 
            prediction VARCHAR(10)
        )""")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS suggestions(
            attack VARCHAR(10),
            preventions TEXT
        )""")
        self.db_connection.commit()
        
    def start_monitoring(self):
        if not self.is_running:
            self.thread = MonitoringThread(self)
            self.thread.packet_processed.connect(self.process_packet)
            self.thread.start()
            self.is_running = True
            self.status_updated.emit("Monitoring Starting!")
            
    def stop_monitoring(self):
        if self.is_running and self.thread:
            self.thread.stop()
            self.thread.wait()
            self.thread = None
            self.is_running = False
            self.status_updated.emit("Monitoring Stopping!")
            
    def process_packet(self, pkt):
        print(f"[Controller] Received packet type: {type(pkt)}")
        from monitoring import process_packet
    
        result = process_packet(pkt, self)
    
         # Update counts based on classification
        if result is not None and "Prediction: normal " in result:
            self.normal_count += 1
        elif result is not None and "Prediction: unknown" in result:
            pass  # Don't count unknown packets
        else:  # Any other classification counts as attack
            self.attack_count += 1
            print(f"Non-normal result: {result}")  # Debug
    
        # Emit updated counts after processing each packet
        self.data_updated.emit(self.normal_count, self.attack_count)
    
        if result:  # Ensure result isn't None
            self.status_updated.emit(result)

    def log_attack(self, attack_data):
        cursor = self.db_connection.cursor()
        cursor.execute("""
        INSERT INTO detected_attacks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, attack_data)
        self.db_connection.commit()
        
    def get_preventions(self, attack_type):
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT preventions FROM suggestions WHERE attack=?", (attack_type,))
        return cursor.fetchall()



from scapy.sendrecv import AsyncSniffer

class MonitoringThread(QThread):   #Threading for running monitoring process
    packet_processed = pyqtSignal(object)

    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.sniffer = None

    def run(self):
        try:
            # SIMPLE version - just capture on default interface
            self.sniffer = AsyncSniffer(
                prn=lambda pkt: pkt.haslayer(IP) and self.packet_processed.emit(pkt),
                store=0,
                filter="ip or tcp or icmp",  # Only capture these packets
                iface= "Intel(R) Dual Band Wireless-AC 7260"   # Specify the network interface
            )
            self.sniffer.start()
            self.sniffer.join()
        except Exception as e:
            print(f"Capture error: {e}")

    def stop(self):
        if self.sniffer:
            self.sniffer.stop()
