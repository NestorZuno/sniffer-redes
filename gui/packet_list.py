# gui/packet_list.py
from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem
from PyQt6.QtCore import pyqtSignal, Qt

class PacketList(QTableWidget):
    packet_selected = pyqtSignal(dict)

    def __init__(self):
        super().__init__(0, 7)
        self.setHorizontalHeaderLabels(
            ["#", "Time", "Source", "Destination", "Protocol", "Length", "Summary"]
        )
        self.cellClicked.connect(self.row_clicked)

    # En gui/packet_list.py

    def add_parsed_packet(self, parsed):
        row = self.rowCount()
        self.insertRow(row)
        num = row + 1

        # 1. TIEMPO (Timestamp)
        # Si no viene en el paquete, ponemos la hora actual del sistema aquí mismo
        import datetime
        ts = parsed.get("timestamp") or parsed.get("time") or parsed.get("_pcap_ts")
        if not ts:
            ts = datetime.datetime.now().strftime("%H:%M:%S")

        # 2. FUENTE Y DESTINO
        src = "Desconocido"
        dst = "Desconocido"
        
        # Buscamos en todas las capas
        for layer in parsed["layers"]:
            f = layer.get("fields", {})
            # Buscamos cualquier llave que parezca una IP o MAC
            # Prioridad: Source > src > Sender IP > src_mac
            s = f.get("Source") or f.get("src") or f.get("Sender IP") or f.get("Source IPv6")
            d = f.get("Destination") or f.get("dst") or f.get("Target IP") or f.get("Destination IPv6")
            
            if s: src = s
            if d: dst = d
            
        # Si seguimos en "Desconocido", intentamos Ethernet (MAC)
        if src == "Desconocido" and len(parsed["layers"]) > 0:
            eth = parsed["layers"][0]["fields"]
            src = eth.get("src_mac", src)
            dst = eth.get("dst_mac", dst)

        # 3. PROTOCOLO
        l4 = next((l for l in parsed["layers"] if l["layer"] in ("TCP","UDP","ICMP", "ICMPv6")), None)
        proto = l4["layer"] if l4 else parsed["layers"][-1]["layer"]

        # 4. LONGITUD
        length = len(parsed.get("raw", b"")) or parsed["layers"][0]["fields"].get("size", 0)

        # 5. RESUMEN
        summary = parsed.get("summary", "")

        # Insertar en la tabla
        self.setItem(row, 0, QTableWidgetItem(str(num)))
        self.setItem(row, 1, QTableWidgetItem(str(ts)))
        self.setItem(row, 2, QTableWidgetItem(str(src)))
        self.setItem(row, 3, QTableWidgetItem(str(dst)))
        self.setItem(row, 4, QTableWidgetItem(str(proto)))
        self.setItem(row, 5, QTableWidgetItem(str(length)))
        self.setItem(row, 6, QTableWidgetItem(str(summary)))

        self.item(row,0).setData(Qt.ItemDataRole.UserRole, parsed)

    def row_clicked(self, row, col):
        parsed = self.item(row,0).data(Qt.ItemDataRole.UserRole)
        if parsed:
            self.packet_selected.emit(parsed)