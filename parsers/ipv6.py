# parsers/ipv6.py

import struct

class IPv6:
    """
    Parser para paquetes IPv6.
    """

    def __init__(self, raw_data):
        self.raw = raw_data

        ver_tc_fl, self.payload_len, self.next_header, self.hop_limit = struct.unpack(
            "!IHBB", raw_data[:8]
        )

        self.version = ver_tc_fl >> 28

        self.src = self._format_ipv6(raw_data[8:24])
        self.dst = self._format_ipv6(raw_data[24:40])

    def _format_ipv6(self, bytes_addr):
        return ":".join(f"{bytes_addr[i] << 8 | bytes_addr[i+1]:x}" for i in range(0,16,2))

    def to_dict(self):
        return {
            "Version": self.version,
            "Payload Length": self.payload_len,
            "Next Header": self.next_header,
            "Hop Limit": self.hop_limit,
            "Source IPv6": self.src,
            "Destination IPv6": self.dst,
        }
