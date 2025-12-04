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
        # Mapa de tipos comunes de ICMP
        types_map = {
            0: "Echo (ping) reply",
            3: "Destination Unreachable",
            4: "Source Quench",
            5: "Redirect",
            8: "Echo (ping) request",
            11: "Time Exceeded",
            12: "Parameter Problem"
        }
        
        type_str = types_map.get(self.type, str(self.type))

        return {
            "Type": self.type,
            "Code": self.code,
            "Description": type_str, # <--- Campo nuevo útil
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
