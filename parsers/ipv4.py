# parsers/ipv4.py
import struct

class IPv4Packet:
    def __init__(self, raw):
        if len(raw) < 20:
            raise ValueError("IPv4 packet too short (min 20 bytes)")

        self.raw = raw

        # Version + IHL
        version_ihl = raw[0]
        self.version = version_ihl >> 4
        self.ihl = (version_ihl & 0x0F) * 4  # header length in bytes

        if self.ihl < 20:
            raise ValueError("Invalid IPv4 header length")

        # Extract fixed header fields
        (
            self.tos,
            self.total_length,
            self.identification,
            flags_fragment,
            self.ttl,
            self.proto,
            src,
            dst
        ) = struct.unpack("! B H H H B B 4s 4s", raw[1:20])

        # Flags + Fragment offset
        self.flags = (flags_fragment >> 13) & 0x07
        self.fragment_offset = flags_fragment & 0x1FFF

        # Convert IPs to string format
        self.src = self.format_ip(src)
        self.dst = self.format_ip(dst)

        # Payload (L4 data)
        if self.total_length > len(raw):
            raise ValueError("IPv4 total_length larger than actual frame")

        self.payload = raw[self.ihl:self.total_length]

    def format_ip(self, ip_bytes):
        return ".".join(map(str, ip_bytes))

    def to_dict(self):
        return {
            "version": self.version,
            "ihl": self.ihl,
            "tos": self.tos,
            "total_length": self.total_length,
            "id": self.identification,
            "flags": self.flags,
            "fragment_offset": self.fragment_offset,
            "ttl": self.ttl,
            "protocol": self.proto,
            "src": self.src,
            "dst": self.dst
        }


def parse_ipv4(raw_data):
    """Compatibilidad con dispatcher.py"""
    return IPv4Packet(raw_data)
