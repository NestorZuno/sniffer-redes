# core/dispatcher.py
# Dispatcher por capas: Ethernet -> ARP/IPv4/IPv6 -> TCP/UDP/ICMP -> App (DNS/HTTP/etc)
# Devuelve un dict con layers, raw y summary

import struct

# -------------------------------------------------------------------------
# IMPORTAR TODOS LOS PARSERS (si alguno no existe, se ignora)
# -------------------------------------------------------------------------
def try_import(path, name):
    try:
        module = __import__(path, fromlist=[name])
        return getattr(module, name)
    except Exception:
        return None

EthernetFrame = try_import("parsers.ethernet", "EthernetFrame")
IPv4Packet    = try_import("parsers.ipv4", "IPv4Packet")
IPv6          = try_import("parsers.ipv6", "IPv6")
ARP           = try_import("parsers.arp", "ARP")
TCP           = try_import("parsers.tcp", "TCP")
UDP           = try_import("parsers.udp", "UDP")
ICMP          = try_import("parsers.icmp", "ICMP")
ICMPv6        = try_import("parsers.icmpv6", "ICMPv6")
NDP           = try_import("parsers.ndp", "NDP")
DNS           = try_import("parsers.dns", "DNS")
DHCP          = try_import("parsers.dhcp", "DHCP")
HTTP          = try_import("parsers.http", "HTTP")
FTP           = try_import("parsers.ftp", "FTP")
SMTP          = try_import("parsers.smtp", "SMTP")
POP3          = try_import("parsers.pop3", "POP3")
IMAP          = try_import("parsers.imap", "IMAP")

# -------------------------------------------------------------------------
# CONSTANTES
# -------------------------------------------------------------------------
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP  = 0x0806
ETHERTYPE_IPV6 = 0x86DD

IPPROTO_TCP   = 6
IPPROTO_UDP   = 17
IPPROTO_ICMP  = 1
IPPROTO_ICMPV6 = 58

# -------------------------------------------------------------------------
# FUNCIONES AYUDA
# -------------------------------------------------------------------------
def mac_format(b):
    return ":".join(f"{x:02x}" for x in b)

def parse_ethernet(raw):
    if len(raw) < 14:
        return None
    dst = raw[0:6]
    src = raw[6:12]
    ethertype = struct.unpack("!H", raw[12:14])[0]
    payload = raw[14:]
    return {
        "layer": "Ethernet",
        "fields": {
            "dst_mac": mac_format(dst),
            "src_mac": mac_format(src),
            "ethertype": f"0x{ethertype:04x}"
        },
        "payload": payload,
        "ethertype": ethertype
    }

# -------------------------------------------------------------------------
# DETECCIÓN DE APLICACIONES POR PUERTO
# -------------------------------------------------------------------------
def detect_application(l4):
    try:
        sport = int(l4.get("Source Port", 0))
        dport = int(l4.get("Destination Port", 0))
    except:
        return None

    if 80 in (sport, dport):
        return {"layer": "HTTP", "fields": {"info": "HTTP"}}
    if 53 in (sport, dport):
        return {"layer": "DNS", "fields": {"info": "DNS"}}
    if sport in (67,68) or dport in (67,68):
        return {"layer": "DHCP", "fields": {"info": "DHCP"}}
    if 21 in (sport, dport):
        return {"layer": "FTP"}
    if 25 in (sport, dport):
        return {"layer": "SMTP"}
    if 110 in (sport, dport):
        return {"layer": "POP3"}
    if 143 in (sport, dport):
        return {"layer": "IMAP"}

    return None

# -------------------------------------------------------------------------
# PARSEAR PAQUETE
# -------------------------------------------------------------------------
def parse_packet(raw_bytes):
    out = {"layers": [], "raw": raw_bytes, "summary": ""}

    # ------------------ ETHERNET ------------------
    eth = parse_ethernet(raw_bytes)
    if not eth:
        out["summary"] = "Trama muy corta"
        return out

    out["layers"].append({"layer": "Ethernet", "fields": eth["fields"]})
    payload = eth["payload"]
    ethertype = eth["ethertype"]

    # ------------------ ARP ------------------
    if ethertype == ETHERTYPE_ARP and ARP:
        try:
            arp = ARP(payload)
            out["layers"].append({"layer": "ARP", "fields": arp.to_dict()})
            out["summary"] = f"ARP {arp.spa} -> {arp.tpa}"
        except:
            out["layers"].append({"layer": "ARP", "fields": {"error": "ARP parse failed"}})
        return out

    # ------------------ IPv4 ------------------
    if ethertype == ETHERTYPE_IPV4 and IPv4Packet:
        try:
            ip = IPv4Packet(payload)
            out["layers"].append({"layer": "IPv4", "fields": {
                "Version": ip.version,
                "TTL": ip.ttl,
                "Protocol": ip.proto,
                "Source": ip.src,
                "Destination": ip.dst
            }})
            l4_payload = ip.payload
            l4_proto = ip.proto
        except Exception as e:
            out["layers"].append({"layer":"IPv4", "fields": {"error": str(e)}})
            return out

    # ------------------ IPv6 ------------------
    elif ethertype == ETHERTYPE_IPV6 and IPv6:
        try:
            ip6 = IPv6(payload)
            out["layers"].append({"layer": "IPv6", "fields": ip6.to_dict()})
            l4_payload = payload[40:]
            l4_proto = ip6.next_header
        except:
            out["layers"].append({"layer":"IPv6","fields":{"error":"IPv6 parse failed"}})
            return out

    else:
        return out

    # ------------------ TCP ------------------
    if l4_proto == IPPROTO_TCP and TCP:
        try:
            tcp = TCP(l4_payload)
            f = tcp.to_dict()
            out["layers"].append({"layer": "TCP", "fields": f})
            app = detect_application(f)
            if app: out["layers"].append(app)
        except:
            out["layers"].append({"layer":"TCP","fields":{"error":"TCP fail"}})

    # ------------------ UDP ------------------
    if l4_proto == IPPROTO_UDP and UDP:
        try:
            udp = UDP(l4_payload)
            f = udp.to_dict()
            out["layers"].append({"layer": "UDP", "fields": f})
            app = detect_application(f)
            if app: out["layers"].append(app)
        except:
            out["layers"].append({"layer":"UDP","fields":{"error":"UDP fail"}})

    # ------------------ ICMPv4 ------------------
    if l4_proto == IPPROTO_ICMP and ICMP:
        try:
            ic = ICMP(l4_payload)
            out["layers"].append({"layer":"ICMP","fields":ic.to_dict()})
        except:
            out["layers"].append({"layer":"ICMP","fields":{"error":"ICMP fail"}})

    # ------------------ ICMPv6 / NDP ------------------
    if l4_proto == IPPROTO_ICMPV6 and ICMPv6:
        try:
            ic = ICMPv6(l4_payload)
            out["layers"].append({"layer":"ICMPv6","fields":ic.to_dict()})

            # NDP detection (types 135/136)
            if NDP and ic.type in (135, 136):
                ndp = NDP(l4_payload)
                out["layers"].append({"layer":"NDP","fields":ndp.to_dict()})

        except:
            out["layers"].append({"layer":"ICMPv6","fields":{"error":"ICMPv6 fail"}})

    return out
