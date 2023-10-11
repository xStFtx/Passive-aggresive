import sys
import psutil
import pyshark
import subprocess
import logging
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QComboBox,
                             QProgressBar, QInputDialog, QListWidget, QCheckBox, QLineEdit, QHBoxLayout, QErrorMessage)

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
        self.progress_signal.emit("Detecting processes...")
        pid = self.detect_process()
        if pid:
            self.progress_signal.emit(f"Capturing traffic for PID {pid}...")
            ips = self.capture_traffic(pid)
            self.scan_with_nmap(ips)
        else:
            self.signal.emit(set(), "Process not found!")

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
    def scan_ip(ip, scan_type='-sV', skip_host_discovery=False):
        try:
            cmd_scan = ["nmap", scan_type]
            if skip_host_discovery:
                cmd_scan.append('-Pn')
            cmd_scan.append(ip)
            result = subprocess.check_output(cmd_scan, stderr=subprocess.STDOUT, text=True)
            return result
        except subprocess.CalledProcessError as e:
            logging.error(e.output)
            return f"Error scanning {ip}: {e.output}"



def get_primary_interface():
    net_stats = psutil.net_io_counters(pernic=True)
    primary_interface = max(net_stats, key=lambda x: (net_stats[x].bytes_sent + net_stats[x].bytes_recv))
    return primary_interface


class App(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.logEdit = QTextEdit()
        self.logEdit.setReadOnly(True)
        layout.addWidget(self.logEdit)

        processLayout = QVBoxLayout()
        self.processSearchBar = QLineEdit()
        self.processSearchBar.setPlaceholderText("Search processes...")
        self.processSearchBar.textChanged.connect(self.filter_processes)
        processLayout.addWidget(self.processSearchBar)

        self.refreshButton = QPushButton("Refresh Processes")
        self.refreshButton.clicked.connect(self.refresh_processes)
        processLayout.addWidget(self.refreshButton)

        self.processComboBox = QComboBox()
        processLayout.addWidget(self.processComboBox)

        layout.addLayout(processLayout)

        self.interfaceComboBox = QComboBox()
        layout.addWidget(QLabel("Select Interface:"))
        interfaces = self.get_windows_interfaces()
        self.interfaceComboBox.addItems(interfaces)
        layout.addWidget(self.interfaceComboBox)

        self.filterLocalIpsCheckbox = QCheckBox("Filter Local IPs")
        self.filterLocalIpsCheckbox.setChecked(True)
        layout.addWidget(self.filterLocalIpsCheckbox)


        self.scanTypeComboBox = QComboBox()
        self.scanTypeComboBox.addItems(["-sV (Version detection)", "-sP (Ping scan)"])
        layout.addWidget(QLabel("Nmap Scan Type:"))
        layout.addWidget(self.scanTypeComboBox)
        self.nmapPnCheckbox = QCheckBox("-Pn (Skip host discovery)")
        layout.addWidget(self.nmapPnCheckbox)

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
        processes = {f"{proc['name']} ({proc['pid']})": proc['pid'] for proc in processes_list if proc['pid'] in network_processes}
        self.processComboBox.clear()
        for name, pid in sorted(processes.items()):
            self.processComboBox.addItem(name, pid)
        self.logEdit.append("Processes refreshed.")

    def filter_processes(self):
        search_text = self.processSearchBar.text().lower()
        for i in range(self.processComboBox.count()):
            item_text = self.processComboBox.itemText(i).lower()
            self.processComboBox.view().setRowHidden(i, search_text not in item_text)

    def get_windows_interfaces(self):
        try:
            tshark_if_output = subprocess.check_output(["tshark", "-D"])
            lines = tshark_if_output.decode("utf-8").strip().split("\n")
            interfaces = [line[line.find("(") + 1:line.find(")")] for line in lines]

            primary_interface = get_primary_interface()
            if primary_interface in interfaces:
                interfaces.remove(primary_interface)
                interfaces.insert(0, primary_interface) 

            return interfaces
        except FileNotFoundError:
            error_msg = QErrorMessage(self)
            error_msg.showMessage("tshark is not found. Please ensure Wireshark is installed.")
            return []

    def on_scan(self):
        process = self.processComboBox.currentData()  
        interface = self.interfaceComboBox.currentText()
        filter_local_ips = self.filterLocalIpsCheckbox.isChecked()
        skip_host_discovery = self.nmapPnCheckbox.isChecked()
        scan_type = self.scanTypeComboBox.currentText().split()[0] 

        duration, ok = QInputDialog.getInt(self, 'Set Duration', 'Enter scan duration (seconds):', value=DEFAULT_SCAN_DURATION, min=MIN_SCAN_DURATION, max=MAX_SCAN_DURATION)
        if not ok:
            return
        self.scanner = IPScanner(process, interface, duration, filter_local_ips)
        self.scanner.signal.connect(self.update_ips)
        self.scanner.progress_signal.connect(self.update_progress)
        self.progressBar.setMaximum(0)
        self.progressBar.setMinimum(0)
        self.logEdit.clear()
        self.scanner.start()


    def update_ips(self, ips, message):
        for ip in ips:
            self.logEdit.append(f"Detected IP: {ip}")
        if message:
            self.logEdit.append(message)
        self.progressBar.setMaximum(100)
        self.progressBar.setValue(100)

    def update_progress(self, message):
        self.logEdit.append(message)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    ex.show()
    sys.exit(app.exec_())
