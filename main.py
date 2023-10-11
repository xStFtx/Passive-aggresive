import sys
import psutil
import pyshark
import subprocess
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QComboBox
from PyQt5.QtCore import QThread, pyqtSignal
import asyncio

class IPScanner(QThread):
    signal = pyqtSignal('PyQt_PyObject')

    def __init__(self, game_process, interface):
        super().__init__()
        self.game_process = game_process
        self.interface = interface

    def run(self):
        # Set up asyncio event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        pid = self.detect_game_process()
        if pid:
            ips = self.capture_game_traffic(pid)
            self.scan_with_nmap(ips)
            self.signal.emit(ips)
        else:
            self.signal.emit([])

    def detect_game_process(self):
        for proc in psutil.process_iter(attrs=["pid", "name"]):
            if proc.info['name'] == self.game_process:
                return proc.info['pid']
        return None

    def capture_game_traffic(self, pid, duration=30):
        capture = pyshark.LiveCapture(interface=self.interface, display_filter=f"ip.addr eq {pid}")
        capture.sniff(timeout=duration)
    
        ips = set()
        for packet in capture:
            if hasattr(packet, 'ip'):
                ips.add(packet.ip.dst)
                ips.add(packet.ip.src)
    
        return ips

    def scan_with_nmap(self, ip_addresses):
        for ip in ip_addresses:
            cmd_scan = ["nmap", "-sV", ip]
            subprocess.run(cmd_scan)

class App(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.statusLabel = QLabel(self)
        self.statusLabel.setText("Game Status: Not Detected")
        layout.addWidget(self.statusLabel)

        self.processComboBox = QComboBox(self)
        processes = [proc.info['name'] for proc in psutil.process_iter(attrs=["name"])]
        self.processComboBox.addItems(processes)
        layout.addWidget(self.processComboBox)

        self.interfaceComboBox = QComboBox(self)
        interfaces = self.get_windows_interfaces()
        self.interfaceComboBox.addItems(interfaces)
        layout.addWidget(self.interfaceComboBox)

        self.ipList = QTextEdit(self)
        layout.addWidget(self.ipList)

        self.scanButton = QPushButton("Scan IPs", self)
        self.scanButton.clicked.connect(self.on_scan)
        layout.addWidget(self.scanButton)

        self.setLayout(layout)
        self.setWindowTitle("Game IP Scanner")
        self.setGeometry(100, 100, 400, 300)

    def get_windows_interfaces(self):
        tshark_if_output = subprocess.check_output(["tshark", "-D"])
        lines = tshark_if_output.decode("utf-8").strip().split("\n")
        interfaces = []
        for line in lines:
            # Get the part of the line inside parentheses
            interface_name = line[line.find("(") + 1:line.find(")")]
            interfaces.append(interface_name)
        return interfaces


    def on_scan(self):
        game_process = self.processComboBox.currentText()
        interface = self.interfaceComboBox.currentText()
        self.scanner = IPScanner(game_process, interface)
        self.scanner.signal.connect(self.update_ips)
        self.scanner.start()

    def update_ips(self, ips):
        if ips:
            self.statusLabel.setText("Game Status: Detected")
            self.ipList.setText("\n".join(ips))
        else:
            self.statusLabel.setText("Game Status: Not Detected")
            self.ipList.setText("No IPs detected")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    ex.show()
    sys.exit(app.exec_())
