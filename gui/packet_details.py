from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem

class PacketDetails(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()
        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Campo", "Valor"])

        layout.addWidget(self.table)
        self.setLayout(layout)

    def show_packet(self, packet_dict):
        self.table.setRowCount(0)

        for key, value in packet_dict.items():
            row = self.table.rowCount()
            self.table.insertRow(row)

            self.table.setItem(row, 0, QTableWidgetItem(str(key)))
            self.table.setItem(row, 1, QTableWidgetItem(str(value)))

