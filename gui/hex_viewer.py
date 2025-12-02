from PyQt6.QtWidgets import QWidget, QTextEdit, QVBoxLayout

class HexViewer(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)
        self.text = QTextEdit()
        self.text.setReadOnly(True)

        layout.addWidget(self.text)

    def display(self, raw: bytes):
        if not raw:
            self.text.clear()
            return

        lines = []
        for i in range(0, len(raw), 16):
            chunk = raw[i:i+16]
            hex_bytes = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{i:04X}  {hex_bytes:<48}  {ascii_part}")

        self.text.setText("\n".join(lines))
