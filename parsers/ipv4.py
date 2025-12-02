import struct

class IPv4Packet:
    def __init__(self, raw_data):
        version_header_length = raw_data[0]
        self.version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4

        self.ttl, self.proto, self.src, self.dst = struct.unpack(
            "!8x B B 2x 4s 4s", raw_data[:20]
        )

        self.src = self.format_ip(self.src)
        self.dst = self.format_ip(self.dst)

        self.payload = raw_data[header_length:]

    def format_ip(self, ip_bytes):
        return ".".join(map(str, ip_bytes))

def parse_ipv4(raw_data):
    return IPv4Packet(raw_data)
