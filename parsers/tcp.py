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
        return {
            "Source Port": self.src_port,
            "Destination Port": self.dst_port,
            "Sequence Number": self.seq,
            "Acknowledgment": self.ack,
            "Header Length": self.offset,
            "Flags": bin(self.flags),
            "Window Size": self.window,
            "Checksum": hex(self.checksum),
            "Urgent Pointer": self.urg_ptr,
            "Payload Length": len(self.payload),
        }
