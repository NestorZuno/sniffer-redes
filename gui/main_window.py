# gui/main_window.py
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QFileDialog, QMessageBox, QInputDialog
)
from PyQt6.QtGui import QAction
from PyQt6.QtCore import QTimer
import threading

from gui.packet_list import PacketList
from gui.packet_details import PacketDetails
from capture.simulator import PacketSimulator
from capture import pcap_reader
from capture.live_capture import start_live_capture


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Sniffer de Red - Proyecto Escolar")
        self.resize(1100, 650)

        # ------ SIMULADOR ------
        self.simulator = PacketSimulator()
        self.capture_timer = QTimer()
        self.capture_timer.timeout.connect(self.generate_simulated_payload)

        # Menús
        self.create_menu()

        # Layout principal
        container = QWidget()
        layout = QHBoxLayout()

        self.packet_list = PacketList()
        self.packet_list.packet_selected.connect(self.show_parsed_packet)

        self.packet_details = PacketDetails()

        layout.addWidget(self.packet_list, 3)
        layout.addWidget(self.packet_details, 2)

        container.setLayout(layout)
        self.setCentralWidget(container)

    # ==========================================================
    # MENÚ
    # ==========================================================
    def create_menu(self):
        menu_bar = self.menuBar()

        # ---- MENÚ CAPTURA ----
        capture_menu = menu_bar.addMenu("Captura")

        sim_start = QAction("Iniciar captura SIMULADA", self)
        sim_start.triggered.connect(self.start_simulated_capture)
        capture_menu.addAction(sim_start)

        sim_stop = QAction("Detener captura simulada", self)
        sim_stop.triggered.connect(self.stop_capture)
        capture_menu.addAction(sim_stop)

        real_start = QAction("Iniciar captura REAL (Scapy)", self)
        real_start.triggered.connect(self.start_real_capture)
        capture_menu.addAction(real_start)

        # ---- MENÚ ARCHIVO ----
        file_menu = menu_bar.addMenu("Archivo")

        open_pcap = QAction("Abrir archivo PCAP…", self)
        open_pcap.triggered.connect(self.open_pcap)
        file_menu.addAction(open_pcap)

        exit_action = QAction("Salir", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # ---- MENÚ VISTA ----
        view_menu = menu_bar.addMenu("Vista")
        stats_action = QAction("Ver estadísticas", self)
        stats_action.triggered.connect(self.show_stats)
        view_menu.addAction(stats_action)

    # ==========================================================
    # CAPTURA SIMULADA
    # ==========================================================
    def start_simulated_capture(self):
        self.simulator.start()
        self.capture_timer.start(300)
        QMessageBox.information(self, "Simulador", "Captura simulada iniciada.")

    def generate_simulated_payload(self):
        pkt = self.simulator.generate_packet()

        parsed = {
            "layers": [
                {"layer": "Simulated", "fields": pkt}
            ],
            "raw": b"",
            "summary": pkt.get("info", "")
        }

        self.packet_list.add_parsed_packet(parsed)

    def stop_capture(self):
        self.simulator.stop()
        self.capture_timer.stop()
        QMessageBox.information(self, "Simulador", "Captura simulada detenida.")

    # ==========================================================
    # CAPTURA REAL
    # ==========================================================
    def start_real_capture(self):
        iface, ok = QInputDialog.getText(
            self,
            "Interfaz de red",
            "Ingresa la interfaz (ejemplo: eth0, wlan0, en0):"
        )

        if not ok or not iface.strip():
            return

        def on_real_packet(parsed):
            self.packet_list.add_parsed_packet(parsed)

        # Lanzar scapy sniff en thread
        t = threading.Thread(
            target=start_live_capture,
            args=(iface.strip(), on_real_packet)
        )
        t.daemon = True
        t.start()

        QMessageBox.information(
            self,
            "Captura real",
            f"Captura REAL iniciada en {iface}.\nAsegúrate de tener permisos de administrador."
        )

    # ==========================================================
    # LECTURA DE PCAP
    # ==========================================================
    def open_pcap(self):
        fname, _ = QFileDialog.getOpenFileName(
            self,
            "Abrir archivo PCAP",
            "",
            "PCAP Files (*.pcap *.pcapng)"
        )
        if not fname:
            return

        try:
            def on_pkt(parsed):
                self.packet_list.add_parsed_packet(parsed)

            pcap_reader.read_pcap(fname, on_pkt)
            QMessageBox.information(self, "PCAP", f"Lectura finalizada: {fname}")

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # ==========================================================
    # INTERFAZ
    # ==========================================================
    def show_stats(self):
        QMessageBox.information(self, "Estadísticas", "Por implementar.")

    def show_parsed_packet(self, parsed):
        self.packet_details.show_packet(parsed)
