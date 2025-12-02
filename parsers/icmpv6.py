# parsers/icmpv6.py

import struct

class ICMPv6:
    """
    Parser de mensajes ICMPv6.
    """

    def __init__(self, raw_data):
        self.raw = raw_data

        self.type, self.code, self.checksum = struct.unpack("!BBH", raw_data[:4])

    def to_dict(self):
        return {
            "Type": self.type,
            "Code": self.code,
            "Checksum": hex(self.checksum),
        }
