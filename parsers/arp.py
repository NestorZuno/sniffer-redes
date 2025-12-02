import struct

class ARP:
    """
    Parser para paquetes ARP (Address Resolution Protocol).
    """

    def __init__(self, raw_data):
        self.raw = raw_data

        # Cabecera ARP son **28 bytes**
        arp_header = struct.unpack('!HHBBH6s4s6s4s', raw_data[:28])

        self.htype = arp_header[0]     # Hardware type
        self.ptype = arp_header[1]     # Protocol type
        self.hlen  = arp_header[2]     # Hardware size
        self.plen  = arp_header[3]     # Protocol size
        self.oper  = arp_header[4]     # Opcode (1 request, 2 reply)

        self.sha = self._mac_format(arp_header[5])  # Sender MAC
        self.spa = self._ip_format(arp_header[6])   # Sender IP
        self.tha = self._mac_format(arp_header[7])  # Target MAC
        self.tpa = self._ip_format(arp_header[8])   # Target IP

    # ----------------------------
    #   FORMATO LEGIBLE
    # ----------------------------
    def _mac_format(self, bytes_addr):
        return ':'.join(f'{b:02x}' for b in bytes_addr)

    def _ip_format(self, bytes_addr):
        return '.'.join(str(b) for b in bytes_addr)

    # ----------------------------
    #   EXPORTAR COMO DICCIONARIO
    # ----------------------------
    def to_dict(self):
        return {
            "Hardware Type": self.htype,
            "Protocol Type": self.ptype,
            "Hardware Size": self.hlen,
            "Protocol Size": self.plen,
            "Opcode": "Request" if self.oper == 1 else "Reply" if self.oper == 2 else self.oper,
            "Sender MAC": self.sha,
            "Sender IP": self.spa,
            "Target MAC": self.tha,
            "Target IP": self.tpa,
        }
