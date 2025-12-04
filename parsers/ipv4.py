# parsers/ipv4.py
import struct

class IPv4Packet:
    def __init__(self, raw):
        # El encabezado mínimo son 20 bytes
        if len(raw) < 20:
            raise ValueError("IPv4 packet too short (min 20 bytes)")

        self.raw = raw

        # Byte 0: Versión e IHL
        version_ihl = raw[0]
        self.version = version_ihl >> 4
        self.ihl = (version_ihl & 0x0F) * 4  # Longitud del header en bytes

        if self.ihl < 20:
            raise ValueError("Invalid IPv4 header length")

        # Extraer campos fijos (Bytes 1 al 19)
        # CORRECCIÓN: Se agregó 'H' antes de las IPs para capturar el Checksum
        # Estructura: TOS(1), Len(2), ID(2), Flags(2), TTL(1), Proto(1), Checksum(2), Src(4), Dst(4)
        # Total bytes del formato: 1 + 2 + 2 + 2 + 1 + 1 + 2 + 4 + 4 = 19 bytes (Coincide con raw[1:20])
        (
            self.tos,
            self.total_length,
            self.identification,
            flags_fragment,
            self.ttl,
            self.proto,
            self.checksum,   # <--- Campo nuevo agregado
            src,
            dst
        ) = struct.unpack("! B H H H B B H 4s 4s", raw[1:20])

        # Procesar Flags y Offset
        self.flags = (flags_fragment >> 13) & 0x07
        self.fragment_offset = flags_fragment & 0x1FFF

        # Formatear IPs
        self.src = self.format_ip(src)
        self.dst = self.format_ip(dst)

        # Cargar Payload
        # (Si el paquete está truncado, ajustamos para no crashear)
        total_len_safe = min(self.total_length, len(raw))
        self.payload = raw[self.ihl : total_len_safe]

    def format_ip(self, ip_bytes):
        return ".".join(map(str, ip_bytes))

    # En parsers/ipv4.py dentro de la clase IPv4Packet

    def to_dict(self):
        # Mapa de protocolos comunes
        proto_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            58: "ICMPv6",
            89: "OSPF"
        }
        # Obtiene el nombre, o deja el número si no lo conoce
        proto_name = proto_map.get(self.proto, str(self.proto))

        return {
            "version": self.version,
            "ihl": self.ihl,
            "tos": self.tos,
            "total_length": self.total_length,
            "id": self.identification,
            "flags": self.flags,
            "fragment_offset": self.fragment_offset,
            "ttl": self.ttl,
            "protocol": proto_name,  # <--- AHORA DIRÁ "TCP" EN LUGAR DE "6"
            "checksum": hex(self.checksum),
            "src": self.src,
            "dst": self.dst
        }

def parse_ipv4(raw_data):
    """Compatibilidad con dispatcher.py"""
    return IPv4Packet(raw_data)