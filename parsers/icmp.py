# parsers/icmp.py

import struct

class ICMP:
    """
    Parser para ICMPv4.
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
