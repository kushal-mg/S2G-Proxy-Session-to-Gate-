import sys
import os
import subprocess
import threading
import multiprocessing
import traceback

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QPushButton, QTextEdit, QLabel, QLineEdit, QGroupBox, QSpacerItem, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal, QObject
from PyQt6.QtGui import QFont
import psutil

class LogSignal(QObject):
    new_log = pyqtSignal(str)

class S2GProxyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("S2G Proxy Dashboard - Zero Trust Enforcer")
        self.setMinimumSize(600, 450)
        self.resize(900, 650)  # Make it resizable with a good default size
        
        # Enterprise Dark Theme
        self.setStyleSheet("""
            QMainWindow { background-color: #0d1117; }
            QLabel { color: #c9d1d9; font-family: 'Segoe UI', Arial, sans-serif; }
            
            QLabel#HeaderTitle { color: #58a6ff; font-size: 28px; font-weight: bold; letter-spacing: 1px; margin-bottom: 2px; }
            QLabel#HeaderSub { color: #8b949e; font-size: 14px; margin-bottom: 15px; }
            
            QPushButton {
                background-color: #238636;
                color: #ffffff;
                border: 1px solid rgba(240, 246, 252, 0.1);
                border-radius: 6px;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                font-family: 'Segoe UI', Arial;
            }
            QPushButton:hover { background-color: #2ea043; border-color: rgba(240, 246, 252, 0.4); }
            QPushButton:pressed { background-color: #238636; }
            QPushButton:disabled { background-color: #21262d; color: #484f58; border-color: transparent; }
            
            QPushButton#StopBtn { background-color: #da3633; }
            QPushButton#StopBtn:hover { background-color: #f85149; }
            QPushButton#StopBtn:pressed { background-color: #da3633; }
            QPushButton#StopBtn:disabled { background-color: #21262d; color: #484f58; border-color: transparent; }
            
            QTextEdit {
                background-color: #010409;
                color: #3fb950;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 12px;
                font-family: Consolas, 'Courier New', monospace;
                font-size: 13px;
                selection-background-color: #1f6feb;
            }
            
            QLineEdit {
                background-color: #0d1117;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 15px;
                font-family: 'Segoe UI', Arial;
            }
            QLineEdit:focus { border: 1px solid #58a6ff; }
            QLineEdit:disabled { background-color: #21262d; color: #8b949e; }
            
            QGroupBox {
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 15px;
                padding-top: 15px;
                font-size: 14px;
                color: #8b949e;
                font-weight: bold;
                font-family: 'Segoe UI', Arial;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 10px;
                left: 15px;
            }
            
            QLabel#StatusDot {
                background-color: #da3633;
                border-radius: 6px;
                min-width: 12px;
                min-height: 12px;
                max-width: 12px;
                max-height: 12px;
            }
            QLabel#StatusDot_Active { background-color: #3fb950; border-radius: 6px; min-width: 12px; min-height: 12px; max-width: 12px; max-height: 12px;}
        """)

        self.proxy_process = None
        self.log_signal = LogSignal()
        self.log_signal.new_log.connect(self.append_log)

        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(25, 25, 25, 25)
        main_layout.setSpacing(15)

        # Header Section
        header_layout = QVBoxLayout()
        header_title = QLabel("S2G Proxy Dashboard")
        header_title.setObjectName("HeaderTitle")
        header_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        header_sub = QLabel("Client-Side Zero-Trust Session Protection")
        header_sub.setObjectName("HeaderSub")
        header_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        header_layout.addWidget(header_title)
        header_layout.addWidget(header_sub)
        main_layout.addLayout(header_layout)

        # Controls Group
        controls_group = QGroupBox("Proxy Configuration")
        controls_layout = QHBoxLayout(controls_group)
        controls_layout.setContentsMargins(20, 20, 20, 20)
        controls_layout.setSpacing(15)
        
        self.status_dot = QLabel()
        self.status_dot.setObjectName("StatusDot")
        controls_layout.addWidget(self.status_dot)
        
        self.status_text = QLabel("Offline")
        self.status_text.setStyleSheet("color: #8b949e; font-size: 15px; font-weight: bold;")
        controls_layout.addWidget(self.status_text)
        
        controls_layout.addSpacerItem(QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))

        port_label = QLabel("Listening Port:")
        port_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        controls_layout.addWidget(port_label)
        
        self.port_input = QLineEdit("8080")
        self.port_input.setFixedWidth(80)
        self.port_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        controls_layout.addWidget(self.port_input)

        controls_layout.addSpacing(20)

        self.start_btn = QPushButton("🚀 Start Enforcer")
        self.start_btn.setMinimumWidth(160)
        self.start_btn.clicked.connect(self.start_proxy)
        controls_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("⏹ Stop Enforcer")
        self.stop_btn.setObjectName("StopBtn")
        self.stop_btn.setMinimumWidth(160)
        self.stop_btn.clicked.connect(self.stop_proxy)
        self.stop_btn.setEnabled(False)
        controls_layout.addWidget(self.stop_btn)

        main_layout.addWidget(controls_group)

        # Log Window
        log_group = QGroupBox("Real-time Security Logs")
        log_group.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        log_layout = QVBoxLayout(log_group)
        log_layout.setContentsMargins(15, 20, 15, 15)
        
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        log_layout.addWidget(self.log_output)
        
        main_layout.addWidget(log_group, stretch=1)
        
        self.append_log("[-] System ready. Awaiting proxy initialization...")

    def update_status(self, is_active):
        if is_active:
            self.status_dot.setObjectName("StatusDot_Active")
            self.status_text.setText("Active & Protected")
            self.status_text.setStyleSheet("color: #3fb950; font-size: 15px; font-weight: bold;")
        else:
            self.status_dot.setObjectName("StatusDot")
            self.status_text.setText("Offline")
            self.status_text.setStyleSheet("color: #8b949e; font-size: 15px; font-weight: bold;")
        
        # Force style re-evaluation
        self.status_dot.style().unpolish(self.status_dot)
        self.status_dot.style().polish(self.status_dot)

    def append_log(self, text):
        self.log_output.append(text)
        scrollbar = self.log_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def start_proxy(self):
        port = self.port_input.text()

        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))
            
        addon_path = os.path.join(base_path, "proxy_addon.py")
        cert_dir = os.path.join(base_path, 'certs')
        
        if not os.path.exists(addon_path):
            self.append_log(f"[!] Error: Could not find '{addon_path}'")
            return

        # Execute our own script but as a mitmproxy worker
        cmd = [
            sys.executable,
            "--run-mitmproxy",
            str(port),
            addon_path,
            cert_dir
        ]

        # Prevent showing a console window on Windows when starting a subprocess
        creationflags = 0x08000000 if os.name == 'nt' else 0

        self.append_log(f"[*] Starting S2G Proxy on 127.0.0.1:{port}...")
        
        try:
            self.proxy_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                creationflags=creationflags
            )
            
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.port_input.setEnabled(False)
            self.update_status(True)

            self.log_thread = threading.Thread(target=self.read_proxy_logs, daemon=True)
            self.log_thread.start()
            
            # Start Packet Capture Detection
            self.pcap_thread = threading.Thread(target=self.monitor_packet_capture, daemon=True)
            self.pcap_thread.start()
            
        except Exception as e:
            self.append_log(f"[!] Failed to start process: {e}")

    def read_proxy_logs(self):
        try:
            for line in iter(self.proxy_process.stdout.readline, ''):
                if line:
                    self.log_signal.new_log.emit(line.strip())
        except Exception as e:
            self.log_signal.new_log.emit(f"Log reading error: {e}")

    def monitor_packet_capture(self):
        """Continuously monitors for known packet capture drivers/services"""
        suspicious_services = ['npf', 'npcap', 'wincap', 'pktg']
        reported = False
        while self.proxy_process is not None:
            try:
                for proc in psutil.process_iter(['name']):
                    name = proc.info['name'].lower()
                    if any(s in name for s in suspicious_services) or 'wireshark' in name:
                        if not reported:
                            self.log_signal.new_log.emit("[!] WARNING: Packet capture or sniffer detected (e.g., Wireshark/Npcap)!")
                            reported = True
                        break
            except Exception:
                pass
            import time
            time.sleep(5)

    def stop_proxy(self):
        if self.proxy_process:
            self.append_log("[*] Stopping proxy and clearing session state...")
            self.proxy_process.terminate()
            self.proxy_process.wait(timeout=3)
            self.proxy_process = None
            
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.port_input.setEnabled(True)
        self.update_status(False)
        self.append_log("[*] Proxy Enforcer stopped successfully.")

    def closeEvent(self, event):
        self.stop_proxy()
        event.accept()

if __name__ == '__main__':
    multiprocessing.freeze_support()

    # Mitmproxy Worker Entrypoint
    if len(sys.argv) > 1 and sys.argv[1] == "--run-mitmproxy":
        port = sys.argv[2]
        addon_path = sys.argv[3]
        cert_dir = sys.argv[4]
        
        from mitmproxy.tools.main import mitmdump
        sys.argv = ["mitmdump", "-p", port, "-s", addon_path, "--set", f"confdir={cert_dir}", "--set", "listen_host=127.0.0.1"]
        sys.exit(mitmdump())

    # Main Application Core
    app = QApplication(sys.argv)
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    window = S2GProxyApp()
    window.show()
    sys.exit(app.exec())
