# parsers/ndp.py

import struct

class NDP:
    """
    Parser para mensajes Neighbor Discovery Protocol (IPv6).
    Compatible con Neighbor Solicitation (135) y Advertisement (136).
    """

    def __init__(self, raw_data):
        self.raw = raw_data

        # Tipo ICMPv6 (NS=135, NA=136)
        self.type = raw_data[0]

        # Código ICMPv6 (normalmente 0)
        self.code = raw_data[1]

        # Checksum ICMPv6
        self.checksum = struct.unpack("!H", raw_data[2:4])[0]

        # Target IPv6 (16 bytes desde offset 8)
        self.target = self._format_ipv6(raw_data[8:24]) if len(raw_data) >= 24 else None

    def _format_ipv6(self, b):
        return ":".join(f"{b[i] << 8 | b[i+1]:x}" for i in range(0, 16, 2))

    def to_dict(self):
        return {
            "NDP Type": self.type,
            "Code": self.code,
            "Checksum": hex(self.checksum),
            "Target IPv6": self.target,
        }
