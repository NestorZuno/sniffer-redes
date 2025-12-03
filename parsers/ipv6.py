# parsers/ipv6.py

import struct

class IPv6:
    """
    Parser para paquetes IPv6 (RFC 2460).
    """

    def __init__(self, raw_data):
        self.raw = raw_data

        # Primeros 8 bytes: Version + Traffic Class + Flow Label + Payload Length + Next Header + Hop Limit
        ver_tc_fl, self.payload_len, self.next_header, self.hop_limit = struct.unpack(
            "!IHBB", raw_data[:8]
        )

        # ------------------------------
        #   Separar campos correctamente
        # ------------------------------
        self.version       = (ver_tc_fl >> 28) & 0xF
        self.traffic_class = (ver_tc_fl >> 20) & 0xFF
        self.flow_label    = ver_tc_fl & 0xFFFFF

        # --------------------------------------
        #   Direcciones IPv6: 16 bytes cada una
        # --------------------------------------
        self.src = self._format_ipv6(raw_data[8:24])
        self.dst = self._format_ipv6(raw_data[24:40])

        # Payload restante
        self.payload = raw_data[40:]

    # ------------------------------
    #   Formato IPv6 con compresión
    # ------------------------------
    def _format_ipv6(self, bytes_addr):
        # dividir en 8 bloques de 16 bits
        parts = [
            (bytes_addr[i] << 8) | bytes_addr[i+1]
            for i in range(0, 16, 2)
        ]

        # convertir a string hexadecimal sin ceros a la izquierda
        hex_parts = [f"{p:x}" for p in parts]

        # aplicar compresión (::)
        return self._compress_ipv6(hex_parts)

    def _compress_ipv6(self, parts):
        """
        Aplica compresión estándar RFC 5952: sustituye el bloque más largo de ceros por '::'
        """
        best_start = -1
        best_len = 0
        cur_start = -1
        cur_len = 0

        # Buscar la secuencia de ceros más larga
        for i, part in enumerate(parts):
            if part == "0":
                if cur_start == -1:
                    cur_start = i
                cur_len += 1
            else:
                if cur_len > best_len:
                    best_len = cur_len
                    best_start = cur_start
                cur_start = -1
                cur_len = 0

        if cur_len > best_len:
            best_len = cur_len
            best_start = cur_start

        # Si no hay secuencia de ceros → sin compresión
        if best_len <= 1:
            return ":".join(parts)

        # Construir dirección comprimida
        start = best_start
        end = best_start + best_len
        compressed = ":".join(parts[:start]) + "::" + ":".join(parts[end:])

        # Quitar : extra si queda algo como ":::" (puede pasar con extremos vacíos)
        return compressed.replace(":::", "::")

    # ------------------------------
    #   Exportar como diccionario
    # ------------------------------
    def to_dict(self):
        return {
            "Version": self.version,
            "Traffic Class": self.traffic_class,
            "Flow Label": self.flow_label,
            "Payload Length": self.payload_len,
            "Next Header": self.next_header,
            "Hop Limit": self.hop_limit,
            "Source IPv6": self.src,
            "Destination IPv6": self.dst,
        }


def parse_ipv6(raw_data):
    return IPv6(raw_data)
