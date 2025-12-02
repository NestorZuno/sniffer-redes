from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem
from PyQt6.QtCore import pyqtSignal, Qt

class PacketList(QTableWidget):
    # Señal que enviará el paquete seleccionado
    packet_selected = pyqtSignal(dict)

    def __init__(self):
        super().__init__(0, 7)
        self.setHorizontalHeaderLabels(
            ["#", "Time", "Source", "Destination", "Protocol", "Size", "Info"]
        )

        # Cuando el usuario haga click en una fila → ejecutar row_clicked
        self.cellClicked.connect(self.row_clicked)

    def add_packet(self, num, time, src, dst, proto, size, info):
        row = self.rowCount()
        self.insertRow(row)

        data = [num, time, src, dst, proto, size, info]

        for col, value in enumerate(data):
            item = QTableWidgetItem(str(value))
            self.setItem(row, col, item)

        # Guardamos el diccionario dentro del primer item de la fila
        self.setRowData(row, {
            "num": num,
            "time": time,
            "src": src,
            "dst": dst,
            "proto": proto,
            "size": size,
            "info": info
        })

    def setRowData(self, row, data):
        self.item(row, 0).setData(Qt.ItemDataRole.UserRole, data)

    def row_clicked(self, row, col):
        data = self.item(row, 0).data(Qt.ItemDataRole.UserRole)
        if data:
            self.packet_selected.emit(data)
