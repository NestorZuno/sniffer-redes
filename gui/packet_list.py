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
        """
        parsed -> dict returned by core.dispatcher.parse_packet
        """
        row = self.rowCount()
        self.insertRow(row)

        num = row + 1
        ts = parsed.get("_pcap_ts", "")
        # find L3 and L4
        l3 = next((l for l in parsed["layers"] if l["layer"] in ("IPv4","IPv6")), None)
        l4 = next((l for l in parsed["layers"] if l["layer"] in ("TCP","UDP")), None)
        src = l3["fields"].get("src","") if l3 else parsed["layers"][0]["fields"].get("src_mac","")
        dst = l3["fields"].get("dst","") if l3 else parsed["layers"][0]["fields"].get("dst_mac","")
        proto = l4["layer"] if l4 else parsed["layers"][-1]["layer"]
        length = len(parsed.get("raw", b""))
        summary = parsed.get("summary","")

        cells = [num, ts, src, dst, proto, length, summary]
        for col, val in enumerate(cells):
            item = QTableWidgetItem(str(val))
            self.setItem(row, col, item)

        # store full parsed dict in row for later retrieval
        self.item(row,0).setData(Qt.ItemDataRole.UserRole, parsed)

    def row_clicked(self, row, col):
        parsed = self.item(row,0).data(Qt.ItemDataRole.UserRole)
        if parsed:
            self.packet_selected.emit(parsed)
