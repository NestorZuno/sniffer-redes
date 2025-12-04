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

    def add_parsed_packet(self, parsed):
        row = self.rowCount()
        self.insertRow(row)

        num = row + 1

        # ===============================
        # TIMESTAMP
        # ===============================
        ts = parsed.get("_pcap_ts") or parsed.get("timestamp") or ""

        # ===============================
        # L3 & L4 SEARCH
        # ===============================
        l3 = next((l for l in parsed["layers"] if l["layer"] in ("IPv4","IPv6")), None)
        l4 = next((l for l in parsed["layers"] if l["layer"] in ("TCP","UDP","ICMP")), None)

        # ===============================
        # SOURCE / DESTINATION
        # ===============================
        if l3:
            src = l3["fields"].get("src", "")
            dst = l3["fields"].get("dst", "")
        else:
            # SIMULATED PACKET
            fields = parsed["layers"][0]["fields"]
            src = fields.get("src", "")
            dst = fields.get("dst", "")

        # ===============================
        # PROTOCOL
        # ===============================
        if l4:
            proto = l4["layer"]
        else:
            proto = parsed.get("proto") or parsed["layers"][-1]["layer"]

        # ===============================
        # LENGTH
        # ===============================
        raw_bytes = parsed.get("raw", b"")

        # Si raw tiene bytes reales (PCAP o captura real)
        if raw_bytes:
            length = len(raw_bytes)
        # Si es un paquete simulado, usar el campo 'size'
        else:
            length = parsed["layers"][0]["fields"].get("size", 0)


        # ===============================
        # SUMMARY
        # ===============================
        summary = parsed.get("summary", "")

        cells = [num, ts, src, dst, proto, length, summary]
        for col, val in enumerate(cells):
            self.setItem(row, col, QTableWidgetItem(str(val)))

        # store parsed packet
        self.item(row,0).setData(Qt.ItemDataRole.UserRole, parsed)

    def row_clicked(self, row, col):
        parsed = self.item(row,0).data(Qt.ItemDataRole.UserRole)
        if parsed:
            self.packet_selected.emit(parsed)
