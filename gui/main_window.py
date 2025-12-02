from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QFileDialog, QMessageBox
)
from PyQt6.QtGui import QAction, QIcon

from gui.packet_list import PacketList
from gui.packet_details import PacketDetails

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Sniffer de Red - Proyecto Escolar")
        self.resize(1000, 600)

        # ===== MENU =====
        self.create_menu()

        # ===== UI PRINCIPAL =====
        container = QWidget()
        layout = QHBoxLayout()

        self.packet_list = PacketList()
        self.packet_details = PacketDetails()

        layout.addWidget(self.packet_list, 3)
        layout.addWidget(self.packet_details, 2)

        container.setLayout(layout)
        self.setCentralWidget(container)

    # -------------------------------
    #       MENÚ DE LA APLICACIÓN
    # -------------------------------
    def create_menu(self):
        menu_bar = self.menuBar()

        # ---- Menú Captura ----
        capture_menu = menu_bar.addMenu("Captura")

        start_action = QAction("Iniciar captura", self)
        start_action.triggered.connect(self.start_capture)
        capture_menu.addAction(start_action)

        stop_action = QAction("Detener captura", self)
        stop_action.triggered.connect(self.stop_capture)
        capture_menu.addAction(stop_action)

        # ---- Menú Archivo ----
        file_menu = menu_bar.addMenu("Archivo")

        open_pcap_action = QAction("Abrir PCAP…", self)
        open_pcap_action.triggered.connect(self.open_pcap)
        file_menu.addAction(open_pcap_action)

        exit_action = QAction("Salir", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # ---- Menú Vista ----
        view_menu = menu_bar.addMenu("Vista")

        stats_action = QAction("Ver estadísticas", self)
        stats_action.triggered.connect(self.show_stats)
        view_menu.addAction(stats_action)

    # -------------------------------
    #    FUNCIONES DE MENÚ (VACÍAS POR AHORA)
    # -------------------------------
    def start_capture(self):
        QMessageBox.information(self, "Captura", "Iniciando captura (simulada por ahora).")

    def stop_capture(self):
        QMessageBox.information(self, "Captura", "Captura detenida.")

    def open_pcap(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Abrir archivo PCAP", "", "PCAP Files (*.pcap)")
        if file_name:
            QMessageBox.information(self, "PCAP", f"Abriste: {file_name}\n(El lector PCAP se añadirá después)")

    def show_stats(self):
        QMessageBox.information(self, "Estadísticas", "Vista de estadísticas (por implementar).")
