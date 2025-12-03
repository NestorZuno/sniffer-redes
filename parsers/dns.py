# parsers/dns.py

import struct

class DNS:
    """
    Parser básico de paquetes DNS (solo cabecera + primer query si existe).
    """

    def __init__(self, raw_data):
        self.raw = raw_data

        if len(raw_data) < 12:
            raise ValueError("DNS packet too short")

        # --------------------------
        # Cabecera DNS (12 bytes)
        # --------------------------
        (self.transaction_id,
         self.flags,
         self.qdcount,
         self.ancount,
         self.nscount,
         self.arcount) = struct.unpack("!HHHHHH", raw_data[:12])

        offset = 12

        # ---------------------------------------------
        # Parsear primer nombre de dominio (si existe)
        # ---------------------------------------------
        self.query_name = None
        self.query_type = None
        self.query_class = None

        if self.qdcount > 0:
            self.query_name, offset = self._parse_name(raw_data, offset)

            # Tipo (2 bytes) + clase (2 bytes)
            if len(raw_data) >= offset + 4:
                self.query_type, self.query_class = struct.unpack("!HH", raw_data[offset:offset+4])
            else:
                raise ValueError("DNS question section incomplete")

    # --------------------------------------------------------
    #   Función para decodificar nombres DNS con labels
    # --------------------------------------------------------
    def _parse_name(self, data, offset):
        labels = []
        original_offset = offset

        while True:
            length = data[offset]

            # Pointer de compresión (2 bytes)
            if (length & 0xC0) == 0xC0:
                ptr = ((length & 0x3F) << 8) | data[offset + 1]
                name, _ = self._parse_name(data, ptr)
                labels.append(name)
                offset += 2
                break

            # Fin del nombre
            if length == 0:
                offset += 1
                break

            offset += 1
            labels.append(data[offset:offset + length].decode(errors="ignore"))
            offset += length

        return ".".join(labels), offset

    # --------------------------------------------------------
    #     Exportar en diccionario
    # --------------------------------------------------------
    def to_dict(self):
        d = {
            "Transaction ID": hex(self.transaction_id),
            "Flags": hex(self.flags),
            "Questions": self.qdcount,
            "Answers": self.ancount,
            "Authority RRs": self.nscount,
            "Additional RRs": self.arcount,
        }

        if self.query_name:
            d.update({
                "Query Name": self.query_name,
                "Query Type": self.query_type,
                "Query Class": self.query_class
            })

        return d
