import sys
import psutil
import pyshark
import subprocess
import logging
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QComboBox, QProgressBar, QInputDialog, QErrorMessage, QListWidget, QCheckBox, QLineEdit
from PyQt5.QtCore import QThread, pyqtSignal
import asyncio
import ipaddress

logging.basicConfig(level=logging.DEBUG)

DEFAULT_SCAN_DURATION = 10
MIN_SCAN_DURATION = 5
MAX_SCAN_DURATION = 120

class IPScanner(QThread):
    signal = pyqtSignal('PyQt_PyObject', 'QString')
    progress_signal = pyqtSignal(str)

    def __init__(self, process, interface, duration, filter_local_ips=True):
        super().__init__()
        self.process = process
        self.interface = interface
        self.filter_local_ips = filter_local_ips
        self.duration = duration

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        pid = self.detect_process()
        ips = self.capture_traffic(pid) if pid else []
        self.scan_with_nmap(ips)

    def detect_process(self):
        for proc in psutil.process_iter(attrs=["pid", "name"]):
            if proc.info['name'].lower() == self.process.lower():
                return proc.info['pid']
        return None

    def capture_traffic(self, pid):
        try:
            capture = pyshark.LiveCapture(interface=self.interface, display_filter=f"ip.addr eq {pid}")
            capture.sniff(timeout=self.duration)
            ips = {packet.ip.dst for packet in capture if hasattr(packet, 'ip')} | \
                  {packet.ip.src for packet in capture if hasattr(packet, 'ip')}
            if self.filter_local_ips:
                ips = {ip for ip in ips if not ipaddress.ip_address(ip).is_private}
            return ips
        except Exception as e:
            logging.error(f"Error in capture_traffic: {e}")
            return set()

    def scan_with_nmap(self, ip_addresses):
        for ip in ip_addresses:
            self.progress_signal.emit(f"Scanning {ip} with nmap...")
            result = NmapScanner.scan_ip(ip)
            self.signal.emit(set([ip]), result)

class NmapScanner:
    @staticmethod
    def scan_ip(ip):
        try:
            cmd_scan = ["nmap", "-sV", ip]
            result = subprocess.check_output(cmd_scan, stderr=subprocess.STDOUT, text=True)
            return result
        except subprocess.CalledProcessError as e:
            logging.error(e.output)
            return f"Error scanning {ip}: {e.output}"

class App(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.statusLabel = QLabel("Game Status: Not Detected")
        layout.addWidget(self.statusLabel)

        self.processSearchBar = QLineEdit()
        self.processSearchBar.setPlaceholderText("Search processes...")
        self.processSearchBar.textChanged.connect(self.filter_processes)
        layout.addWidget(self.processSearchBar)

        self.refreshButton = QPushButton("Refresh Processes")
        self.refreshButton.clicked.connect(self.refresh_processes)
        layout.addWidget(self.refreshButton)

        self.processComboBox = QComboBox()
        layout.addWidget(self.processComboBox)

        self.interfaceComboBox = QComboBox()
        self.interfaceComboBox.addItems(self.get_windows_interfaces())
        layout.addWidget(self.interfaceComboBox)

        self.filterLocalIpsCheckbox = QCheckBox("Filter Local IPs")
        self.filterLocalIpsCheckbox.setChecked(True)
        layout.addWidget(self.filterLocalIpsCheckbox)

        self.ipListView = QListWidget()
        layout.addWidget(self.ipListView)

        self.scanButton = QPushButton("Scan IPs")
        self.scanButton.clicked.connect(self.on_scan)
        layout.addWidget(self.scanButton)

        self.progressBar = QProgressBar(self)
        layout.addWidget(self.progressBar)

        self.setLayout(layout)
        self.setWindowTitle("Game IP Scanner")
        self.setGeometry(100, 100, 600, 500)
        self.refresh_processes()

    def refresh_processes(self):
        try:
            network_processes = [conn.pid for conn in psutil.net_connections(kind='inet')]
        except psutil.Error as e:
            logging.error(f"Error fetching network connections: {e}")
            network_processes = []
        processes_info = psutil.process_iter(attrs=["name", "pid"])
        processes_list = [proc.info for proc in processes_info]
        processes = {proc['name'] for proc in processes_list if proc['pid'] in network_processes}
        self.processComboBox.clear()
        self.processComboBox.addItems(sorted(processes))
        if not processes:
            self.statusLabel.setText("Status: No network processes found.")
        else:
            self.statusLabel.setText("Status: Processes refreshed.")

    def filter_processes(self):
        search_text = self.processSearchBar.text().lower()
        for i in range(self.processComboBox.count()):
            item_text = self.processComboBox.itemText(i).lower()
            self.processComboBox.view().setRowHidden(i, search_text not in item_text)

    def get_windows_interfaces(self):
        try:
            tshark_if_output = subprocess.check_output(["tshark", "-D"])
            lines = tshark_if_output.decode("utf-8").strip().split("\n")
            return [line[line.find("(") + 1:line.find(")")] for line in lines]
        except FileNotFoundError:
            error_msg = QErrorMessage(self)
            error_msg.showMessage("tshark is not found. Please ensure Wireshark is installed.")
            return []

    def on_scan(self):
        process = self.processComboBox.currentText()
        interface = self.interfaceComboBox.currentText()
        filter_local_ips = self.filterLocalIpsCheckbox.isChecked()
        duration, ok = QInputDialog.getInt(self, 'Set Duration', 'Enter scan duration (seconds):', value=DEFAULT_SCAN_DURATION, min=MIN_SCAN_DURATION, max=MAX_SCAN_DURATION)
        if not ok:
            return
        self.scanner = IPScanner(process, interface, duration, filter_local_ips)
        self.scanner.signal.connect(self.update_ips)
        self.scanner.progress_signal.connect(self.update_progress)
        self.progressBar.setMaximum(0)
        self.progressBar.setMinimum(0)
        self.ipListView.clear()
        self.scanner.start()

    def update_ips(self, ips, nmap_output):
        if ips:
            ip = list(ips)[0]
            self.ipListView.addItem(f"Results for {ip}:\n{nmap_output}")
            self.progressBar.setMaximum(1)
            self.progressBar.setValue(1)
        else:
            self.statusLabel.setText("Status: Not Detected")

    def update_progress(self, message):
        self.statusLabel.setText(f"Status: {message}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    ex.show()
    sys.exit(app.exec_())
