import struct

class EthernetFrame:
    def __init__(self, raw_data):
        # Primeros 14 bytes: MAC destino, MAC origen, tipo
        dest_mac, src_mac, proto = struct.unpack("!6s6sH", raw_data[:14])
        self.dest_mac = self.mac_format(dest_mac)
        self.src_mac = self.mac_format(src_mac)
        self.proto = proto
        self.payload = raw_data[14:]

    def mac_format(self, bytes_mac):
        return ':'.join(f'{b:02x}' for b in bytes_mac)

def parse_ethernet(raw_data):
    return EthernetFrame(raw_data)
