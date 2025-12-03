# parsers/dhcp.py

import struct

class DHCP:
    """
    Parser básico para DHCPv4 (BOOTP + opciones).
    """

    def __init__(self, raw_data):
        self.raw = raw_data

        if len(raw_data) < 240:
            raise ValueError("DHCP packet too short")

        (
            self.op,        # 1 = BOOTREQUEST, 2 = BOOTREPLY
            self.htype,     # Tipo de hardware
            self.hlen,      # Longitud de MAC (6)
            self.hops,
            self.xid,       # Transaction ID
            self.secs,
            self.flags
        ) = struct.unpack("!BBBBIHH", raw_data[:12])

        self.ciaddr = raw_data[12:16]
        self.yiaddr = raw_data[16:20]
        self.siaddr = raw_data[20:24]
        self.giaddr = raw_data[24:28]

        # CHADDR (cliente hardware address) — primero hlen bytes dentro de 16
        self.chaddr = raw_data[28:28 + 16][:self.hlen]

        # Opciones DHCP empiezan en offset 240 (BOOTP header = 236 + 4 bytes magic cookie)
        # Si no hay magic cookie, se intenta a partir de 240 igualmente
        options_offset = 240
        self.options = self.parse_options(raw_data[options_offset:])

    # ---------------------------
    # FORMATEADORES
    # ---------------------------
    def format_ip(self, b):
        return ".".join(str(x) for x in b)

    def format_mac(self, b):
        return ":".join(f"{x:02x}" for x in b)

    # ---------------------------
    # PARSER DE OPCIONES DHCP
    # ---------------------------
    def parse_options(self, data):
        opts = {}
        i = 0
        # chequeo simple: data puede empezar con magic cookie (4 bytes) 99:130:83:99 (0x63 82 53 63)
        if len(data) >= 4 and data[:4] == b"\x63\x82\x53\x63":
            i = 4

        while i < len(data):
            opt = data[i]
            if opt == 255:     # END option
                break
            if opt == 0:       # Padding
                i += 1
                continue
            if i + 1 >= len(data):
                break
            length = data[i + 1]
            if i + 2 + length > len(data):
                # paquete truncado, salir
                break
            value = data[i + 2 : i + 2 + length]
            opts[opt] = value
            i += 2 + length

        return opts

    # ---------------------------
    # EXPORTAR A DICCIONARIO LEGIBLE
    # ---------------------------
    def to_dict(self):
        # convertir direcciones
        d = {
            "Operation": self.op,
            "Hardware Type": self.htype,
            "MAC Length": self.hlen,
            "Transaction ID": hex(self.xid),
            "Client IP": self.format_ip(self.ciaddr),
            "Assigned IP": self.format_ip(self.yiaddr),
            "Server IP": self.format_ip(self.siaddr),
            "Gateway IP": self.format_ip(self.giaddr),
            "Client MAC": self.format_mac(self.chaddr),
        }

        # convertir opciones a representación legible
        opts_readable = {}
        for code, val in self.options.items():
            # decodificar opciones conocidas
            if code == 53 and len(val) == 1:  # DHCP Message Type
                msg_types = {
                    1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
                    5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"
                }
                opts_readable["DHCP Message Type"] = msg_types.get(val[0], val[0])
            elif code in (50, 54) and len(val) == 4:  # Requested IP / Server identifier
                opts_readable[f"Option {code}"] = self.format_ip(val)
            elif code == 1 and len(val) == 4:  # Subnet mask
                opts_readable["Subnet Mask"] = self.format_ip(val)
            elif code == 12:  # Hostname (string)
                try:
                    opts_readable["Hostname"] = val.decode('utf-8', errors='ignore')
                except Exception:
                    opts_readable["Hostname"] = list(val)
            else:
                # por defecto: mostrar bytes como lista de ints para evitar problemas con non-printables
                opts_readable[f"Option {code}"] = list(val)

        d["Options"] = opts_readable
        return d
