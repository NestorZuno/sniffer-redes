# parsers/icmp.py

import struct

class ICMP:
    """
    Parser para ICMPv4.
    """

    def __init__(self, raw_data):
        self.raw = raw_data

        # Los primeros 4 bytes son: Type, Code, Checksum
        self.type, self.code, self.checksum = struct.unpack("!BBH", raw_data[:4])

    def to_dict(self):
        return {
            "Type": self.type,
            "Code": self.code,
            "Checksum": hex(self.checksum),
        }

def parse_icmp(raw_data):
    """
    Esta función la usa dispatcher.py
    Siempre debe devolver un diccionario.
    """
    try:
        icmp = ICMP(raw_data)
        return icmp.to_dict()
    except Exception as e:
        return { "error": f"ICMP parse error: {e}" }
