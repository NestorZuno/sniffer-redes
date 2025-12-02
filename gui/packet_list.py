from PyQt6.QtWidgets import QWidget, QTableWidget, QVBoxLayout, QTableWidgetItem
from PyQt6.QtCore import pyqtSignal, Qt

class PacketList(QWidget):

    packet_selected = pyqtSignal(dict)  # Envía un paquete al main_window

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["#", "Tiempo", "Origen", "Destino", "Protocolo"])

        self.table.cellClicked.connect(self._row_clicked)

        layout.addWidget(self.table)

        # Listado interno de paquetes
        self.packets = []

    def add_packet(self, packet: dict):
        row = self.table.rowCount()
        self.table.insertRow(row)

        self.packets.append(packet)

        self.table.setItem(row, 0, QTableWidgetItem(str(len(self.packets))))
        self.table.setItem(row, 1, QTableWidgetItem(packet.get("time", "0")))
        self.table.setItem(row, 2, QTableWidgetItem(packet.get("src", "")))
        self.table.setItem(row, 3, QTableWidgetItem(packet.get("dst", "")))
        self.table.setItem(row, 4, QTableWidgetItem(packet.get("protocol", "")))

    def _row_clicked(self, row, col):
        packet = self.packets[row]
        self.packet_selected.emit(packet)
