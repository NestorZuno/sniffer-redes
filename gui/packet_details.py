# gui/packet_details.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView
from PyQt6.QtGui import QColor, QFont

class PacketDetails(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()
        # 0 filas iniciales, 2 columnas (Campo, Valor)
        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Campo", "Valor"])
        
        # Ajustar columnas automáticamente
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        layout.addWidget(self.table)
        self.setLayout(layout)

    def show_packet(self, packet_dict):
        """
        Muestra los detalles del paquete desglosados por capas.
        """
        self.table.setRowCount(0)

        # Si no hay capas, no hacemos nada
        if "layers" not in packet_dict:
            return

        # Recorremos cada capa (Ethernet -> IP -> TCP...)
        for layer_data in packet_dict["layers"]:
            layer_name = layer_data.get("layer", "Unknown Layer")
            fields = layer_data.get("fields", {})

            # 1. Crear una fila de TÍTULO para la capa (ej: "--- IPv4 ---")
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            # Celda de título
            header_item = QTableWidgetItem(f"--- {layer_name} ---")
            # Le ponemos negrita y color de fondo gris suave
            font = QFont()
            font.setBold(True)
            header_item.setFont(font)
            header_item.setBackground(QColor("#d3d3d3")) # Gris claro
            
            self.table.setItem(row, 0, header_item)
            
            # La segunda celda también gris para que se vea como una barra completa
            empty_item = QTableWidgetItem("")
            empty_item.setBackground(QColor("#d3d3d3"))
            self.table.setItem(row, 1, empty_item)

            # 2. Listar los campos de esa capa
            for key, value in fields.items():
                row = self.table.rowCount()
                self.table.insertRow(row)
                
                # Nombre del campo
                self.table.setItem(row, 0, QTableWidgetItem(str(key)))
                # Valor del campo
                self.table.setItem(row, 1, QTableWidgetItem(str(value)))