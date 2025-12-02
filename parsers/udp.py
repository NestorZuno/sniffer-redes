# parsers/udp.py

import struct

class UDP:
    """
    Parser para datagramas UDP.
    """

    def __init__(self, raw_data):
        self.raw = raw_data

        self.src_port, self.dst_port, self.length, self.checksum = struct.unpack(
            "!HHHH", raw_data[:8]
        )

    def to_dict(self):
        return {
            "Source Port": self.src_port,
            "Destination Port": self.dst_port,
            "Length": self.length,
            "Checksum": hex(self.checksum),
        }
