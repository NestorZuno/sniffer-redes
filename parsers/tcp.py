# parsers/tcp.py

import struct

class TCP:
    """
    Parser para segmentos TCP.
    """

    def __init__(self, raw_data):
        self.raw = raw_data

        (self.src_port,
         self.dst_port,
         self.seq,
         self.ack,
         offset_reserved_flags,
         self.window,
         self.checksum,
         self.urg_ptr) = struct.unpack("!HHLLHHHH", raw_data[:20])

        # Header length → (offset en palabras de 32 bits) * 4
        self.offset = (offset_reserved_flags >> 12) * 4

        # Flags (9 bits)
        self.flags = offset_reserved_flags & 0x01FF

        # -------------------------
        # EXTRAER EL PAYLOAD TCP
        # -------------------------
        self.payload = raw_data[self.offset:]

    def to_dict(self):
        # Decodificar las banderas
        # Banderas (9 bits): NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
        flags_map = {
            0x001: "FIN",
            0x002: "SYN",
            0x004: "RST",
            0x008: "PSH",
            0x010: "ACK",
            0x020: "URG",
            0x040: "ECE",
            0x080: "CWR",
            0x100: "NS"
        }

        active_flags = []
        for bit, name in flags_map.items():
            if self.flags & bit:
                active_flags.append(name)
        
        flags_str = "[" + ", ".join(active_flags) + "]"

        return {
            "Source Port": self.src_port,
            "Destination Port": self.dst_port,
            "Sequence Number": self.seq,
            "Acknowledgment": self.ack,
            "Header Length": self.offset,
            "Flags": flags_str,       # <--- Ahora es legible (ej. "[SYN, ACK]")
            "Raw Flags": hex(self.flags),
            "Window Size": self.window,
            "Checksum": hex(self.checksum),
            "Urgent Pointer": self.urg_ptr,
            "Payload Length": len(self.payload),
        }