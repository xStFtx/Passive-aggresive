import sys
import psutil
import pyshark
import subprocess
import logging
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QComboBox, QProgressBar
from PyQt5.QtCore import QThread, pyqtSignal
import asyncio
import ipaddress

logging.basicConfig(level=logging.DEBUG)

class IPScanner(QThread):
    signal = pyqtSignal('PyQt_PyObject', 'QString')

    def __init__(self, game_process, interface, filter_local_ips=True):
        super().__init__()
        self.game_process = game_process
        self.interface = interface
        self.filter_local_ips = filter_local_ips

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        pid = self.detect_game_process()
        ips = self.capture_game_traffic(pid) if pid else []
        self.scan_with_nmap(ips)

    def detect_game_process(self):
        for proc in psutil.process_iter(attrs=["pid", "name"]):
            if proc.info['name'] == self.game_process:
                return proc.info['pid']
        return None

    def capture_game_traffic(self, pid, duration=10):
        capture = pyshark.LiveCapture(interface=self.interface, display_filter=f"ip.addr eq {pid}")
        capture.sniff(timeout=duration)

        ips = {packet.ip.dst for packet in capture if hasattr(packet, 'ip')} | \
              {packet.ip.src for packet in capture if hasattr(packet, 'ip')}
        
        if self.filter_local_ips:
            ips = {ip for ip in ips if not ipaddress.ip_address(ip).is_private}

        return ips

    def scan_with_nmap(self, ip_addresses):
        for ip in ip_addresses:
            try:
                cmd_scan = ["nmap", "-sV", ip]
                result = subprocess.check_output(cmd_scan, stderr=subprocess.STDOUT, text=True)
                self.signal.emit(set([ip]), result)
            except subprocess.CalledProcessError as e:
                logging.error(e.output)

class App(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.statusLabel = QLabel("Game Status: Not Detected")
        layout.addWidget(self.statusLabel)

        self.refreshButton = QPushButton("Refresh Processes")
        self.refreshButton.clicked.connect(self.refresh_processes)
        layout.addWidget(self.refreshButton)

        self.processComboBox = QComboBox()
        layout.addWidget(self.processComboBox)

        self.interfaceComboBox = QComboBox()
        self.interfaceComboBox.addItems(self.get_windows_interfaces())
        layout.addWidget(self.interfaceComboBox)

        self.ipList = QTextEdit()
        layout.addWidget(self.ipList)

        self.scanButton = QPushButton("Scan IPs")
        self.scanButton.clicked.connect(self.on_scan)
        layout.addWidget(self.scanButton)

        self.progressBar = QProgressBar(self)
        layout.addWidget(self.progressBar)

        self.setLayout(layout)
        self.setWindowTitle("Game IP Scanner")
        self.setGeometry(100, 100, 500, 400)
        self.refresh_processes()

    def refresh_processes(self):
        processes = [proc.info['name'] for proc in psutil.process_iter(attrs=["name"])]
        self.processComboBox.clear()
        self.processComboBox.addItems(processes)

    def get_windows_interfaces(self):
        try:
            tshark_if_output = subprocess.check_output(["tshark", "-D"])
            lines = tshark_if_output.decode("utf-8").strip().split("\n")
            return [line[line.find("(") + 1:line.find(")")] for line in lines]
        except Exception as e:
            logging.error(f"Error getting interfaces: {e}")
            return []

    def on_scan(self):
        game_process = self.processComboBox.currentText()
        interface = self.interfaceComboBox.currentText()
        self.scanner = IPScanner(game_process, interface)
        self.scanner.signal.connect(self.update_ips)
        self.progressBar.setMaximum(0)
        self.progressBar.setMinimum(0)
        self.scanner.start()

    def update_ips(self, ips, nmap_output):
        self.progressBar.setMaximum(1)
        self.progressBar.setValue(1)
        if ips:
            self.statusLabel.setText(f"Game Status: Detected\nIPs: {len(ips)}")
            self.ipList.append(nmap_output)
        else:
            self.statusLabel.setText("Game Status: Not Detected")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    ex.show()
    sys.exit(app.exec_())
