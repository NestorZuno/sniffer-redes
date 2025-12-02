from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QSplitter, QFileDialog, QMessageBox
)
from PyQt6.QtCore import Qt

from gui.packet_list import PacketList
from gui.packet_details import PacketDetails
from gui.hex_viewer import HexViewer

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Sniffer de Redes - Proyecto")
        self.resize(1200, 700)

        self._setup_menu()
        self._setup_layout()

    def _setup_menu(self):
        menu = self.menuBar()

        # --- FILE MENU ---
        file_menu = menu.addMenu("Archivo")

        load_pcap = file_menu.addAction("Cargar PCAP…")
        load_pcap.triggered.connect(self.load_pcap)

        file_menu.addSeparator()

        exit_action = file_menu.addAction("Salir")
        exit_action.triggered.connect(self.close)

        # --- CAPTURE MENU ---
        capture_menu = menu.addMenu("Captura")

        start_action = capture_menu.addAction("Iniciar Captura")
        start_action.triggered.connect(self.start_capture)

        stop_action = capture_menu.addAction("Detener Captura")
        stop_action.triggered.connect(self.stop_capture)

    def _setup_layout(self):
        central_widget = QWidget()
        layout = QVBoxLayout(central_widget)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Panel izquierdo: lista de paquetes
        self.packet_list = PacketList()
        self.packet_list.packet_selected.connect(self.show_packet_details)

        # Panel derecho superior: detalles por capas
        self.packet_details = PacketDetails()

        # Panel derecho inferior: hexdump
        self.hex_viewer = HexViewer()

        right_splitter = QSplitter(Qt.Orientation.Vertical)
        right_splitter.addWidget(self.packet_details)
        right_splitter.addWidget(self.hex_viewer)
        right_splitter.setSizes([400, 300])

        splitter.addWidget(self.packet_list)
        splitter.addWidget(right_splitter)
        splitter.setSizes([400, 800])

        layout.addWidget(splitter)
        self.setCentralWidget(central_widget)

    # ------------------------------------------
    #  EVENTOS DE MENU
    # ------------------------------------------

    def load_pcap(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Abrir archivo PCAP", "", "PCAP Files (*.pcap *.pcapng)"
        )
        if not path:
            return

        # Aquí conectarás el lector de pcap real:
        QMessageBox.information(self, "PCAP", f"PCAP cargado:\n{path}")

    def start_capture(self):
        QMessageBox.information(self, "Captura", "Iniciando captura real…")
        # Aquí se conectará live_capture.start()

    def stop_capture(self):
        QMessageBox.warning(self, "Captura", "Captura detenida.")
        # Aquí se conectará live_capture.stop()

    # ------------------------------------------
    #  EVENTO: CUANDO SE SELECCIONA UN PAQUETE
    # ------------------------------------------

    def show_packet_details(self, packet):
        """
        packet = {
            "summary": "...",
            "layers": [
                { "layer": "Ethernet", "fields": {...} },
                { "layer": "IPv4", "fields": {...} },
                ...
            ],
            "raw": b"\x00\x14..."
        }
        """
        if not packet:
            return

        self.packet_details.display(packet["layers"])
        self.hex_viewer.display(packet["raw"])
