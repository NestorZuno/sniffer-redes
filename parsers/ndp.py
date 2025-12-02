# parsers/ndp.py

import struct

class NDP:
    """
    Parser para mensajes Neighbor Discovery Protocol (IPv6).
    """

    def __init__(self, raw_data):
        self.raw = raw_data

        # Tipo ICMPv6 automáticamente
        self.type = raw_data[0]

        # Target IPv6 (16 bytes desde offset 8)
        self.target = self._format_ipv6(raw_data[8:24])

    def _format_ipv6(self, b):
        return ":".join(f"{b[i] << 8 | b[i+1]:x}" for i in range(0, 16, 2))

    def to_dict(self):
        return {
            "NDP Type": self.type,
            "Target IPv6": self.target,
        }
