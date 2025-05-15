from PyQt5.QtWidgets import QWidget, QVBoxLayout
from PyQt5.QtCore import QTimer, QMutex
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt
from collections import deque
import time

class LiveGraph(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.mutex = QMutex()
        self.timestamps = deque(maxlen=1000)  # Keep last 1000 records
        self.normal_counts = deque(maxlen=1000)
        self.attack_counts = deque(maxlen=1000)

        self.fig, self.ax = plt.subplots(figsize=(8, 4))
        self.ax.set_xlabel("Time (seconds ago)", fontsize=10)
        self.ax.set_ylabel("Packet Count", fontsize=10)
        self.ax.grid(True, alpha=0.3)

        self.line_normal, = self.ax.plot([], [], label="Normal", color="lime", lw=2)
        self.line_attack, = self.ax.plot([], [], label="Attack", color="red", lw=2)
        self.ax.legend(loc="upper right")

        self.canvas = FigureCanvas(self.fig)
        layout = QVBoxLayout()
        layout.addWidget(self.canvas)
        self.setLayout(layout)

        # Update the graph every 2 seconds without blocking UI
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self._refresh_graph)
        self.update_timer.start(2000)  

    def update_graph(self, normal_count, attack_count):
        """Thread-safe data update (called from MonitoringThread)."""
        self.mutex.lock()
        self.timestamps.append(time.time())
        self.normal_counts.append(normal_count)
        self.attack_counts.append(attack_count)
        self.mutex.unlock()

        # Schedule a UI update without blocking the thread
        QTimer.singleShot(0, self._refresh_graph)

    def _refresh_graph(self):
        """Render updates (runs in the main UI thread)."""
        if not self.timestamps:
            return

        self.mutex.lock()
        base_time = self.timestamps[0]  # Take the first timestamp as reference
        seconds_ago = [t - base_time for t in self.timestamps]  # Normalize time values
        normal_counts = list(self.normal_counts)
        attack_counts = list(self.attack_counts)
        self.mutex.unlock()

        self.line_normal.set_data(seconds_ago, normal_counts)
        self.line_attack.set_data(seconds_ago, attack_counts)

        # Adjust X-axis dynamically (latest data always visible)
        self.ax.set_xlim(0, max(seconds_ago, default=60))
        self.ax.set_ylim(0, max(10, max(normal_counts, default=10), max(attack_counts, default=10)))

        self.ax.relim()
        self.ax.autoscale_view()
        self.canvas.draw()
