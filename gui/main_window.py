# gui/main_window.py
from PyQt6.QtWidgets import QMainWindow, QWidget, QHBoxLayout, QFileDialog, QMessageBox
from PyQt6.QtGui import QAction
from PyQt6.QtCore import QTimer

from gui.packet_list import PacketList
from gui.packet_details import PacketDetails
from capture.simulator import PacketSimulator
from core.dispatcher import parse_packet
from capture import pcap_reader  # ensure capture package exists (capture/__init__.py)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Sniffer de Red - Proyecto Escolar")
        self.resize(1000, 600)

        # simulator (keeps working for demo)
        self.simulator = PacketSimulator()
        self.capture_timer = QTimer()
        self.capture_timer.timeout.connect(self.generate_simulated_payload)

        self.create_menu()

        container = QWidget()
        layout = QHBoxLayout()

        self.packet_list = PacketList()
        self.packet_list.packet_selected.connect(self.show_parsed_packet)

        self.packet_details = PacketDetails()

        layout.addWidget(self.packet_list, 3)
        layout.addWidget(self.packet_details, 2)

        container.setLayout(layout)
        self.setCentralWidget(container)

    def create_menu(self):
        menu_bar = self.menuBar()

        capture_menu = menu_bar.addMenu("Captura")
        start_action = QAction("Iniciar captura (simulada)", self)
        start_action.triggered.connect(self.start_capture)
        capture_menu.addAction(start_action)

        stop_action = QAction("Detener captura", self)
        stop_action.triggered.connect(self.stop_capture)
        capture_menu.addAction(stop_action)

        file_menu = menu_bar.addMenu("Archivo")
        open_pcap_action = QAction("Abrir PCAP…", self)
        open_pcap_action.triggered.connect(self.open_pcap)
        file_menu.addAction(open_pcap_action)
        exit_action = QAction("Salir", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        view_menu = menu_bar.addMenu("Vista")
        stats_action = QAction("Ver estadísticas", self)
        stats_action.triggered.connect(self.show_stats)
        view_menu.addAction(stats_action)

    # -------------------------
    # Simulation: generates L2-like raw bytes? (we'll create minimal raw Ethernet bytes)
    # -------------------------
    def generate_simulated_payload(self):
        pkt = self.simulator.generate_packet()
        # Build a minimal fake Ethernet+IPv4+UDP header if possible, else parse a summary
        # For now we create a tiny pseudo-raw payload so dispatcher can process: (Ether + IPv4 minimal)
        # If you want real bytes, later connect to actual capture or pcap.
        # Here we'll parse using a synthetic raw bytes only for demonstration when possible.
        # fallback: create a parsed dict manually
        parsed = {
            "layers": [
                {"layer":"Simulated","fields":pkt}
            ],
            "raw": b"",
            "summary": pkt.get("info","")
        }
        # If you have real raw bytes from simulator, you would call: parsed = parse_packet(raw_bytes)
        self.packet_list.add_parsed_packet(parsed)

    def start_capture(self):
        self.simulator.start()
        self.capture_timer.start(300)

    def stop_capture(self):
        self.simulator.stop()
        self.capture_timer.stop()

    def open_pcap(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Abrir PCAP", "", "PCAP Files (*.pcap *.pcapng)")
        if not fname:
            return
        try:
            def on_pkt(parsed):
                # runs in the same thread: ensure GUI-safe updates (PyQt is single-thread; for large pcaps run threaded)
                self.packet_list.add_parsed_packet(parsed)
            pcap_reader.read_pcap(fname, on_pkt)
            QMessageBox.information(self, "PCAP", f"Lectura finalizada: {fname}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def show_stats(self):
        QMessageBox.information(self, "Estadísticas", "Por implementar (próximos pasos).")

    def show_parsed_packet(self, parsed):
        self.packet_details.show_packet(parsed)
