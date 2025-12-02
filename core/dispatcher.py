# core/dispatcher.py
# Dispatcher por capas: Ethernet -> L3 (ARP/IPv4/IPv6) -> L4 (TCP/UDP/ICMP) -> App (HTTP/DNS...)
# Devuelve: { "layers": [ {"layer":"Ethernet","fields":{...}}, ... ], "raw": b"...", "summary": "..." }

import struct

# Intentamos importar parsers si existen; sino usamos fallback básico
try:
    from parsers.arp import ARP
except Exception:
    ARP = None

try:
    from parsers.ipv4 import IPv4Packet
except Exception:
    IPv4Packet = None

try:
    from parsers.ipv6 import IPv6Packet
except Exception:
    IPv6Packet = None

try:
    from parsers.tcp import parse_tcp as tcp_parser
except Exception:
    tcp_parser = None

try:
    from parsers.udp import parse_udp as udp_parser
except Exception:
    udp_parser = None

try:
    from parsers.icmp import parse_icmp as icmp_parser
except Exception:
    icmp_parser = None

# Simple helpers
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

# Map for well-known ethertypes
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP  = 0x0806
ETHERTYPE_IPV6 = 0x86DD

# Map for L4 numbers
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMP = 1
IPPROTO_ICMPV6 = 58

def detect_application(l4_fields):
    """
    Detección básica de aplicaciones por puertos (si se proveen).
    Devuelve dict aplicación simple o None.
    """
    app = None
    try:
        sport = int(l4_fields.get("sport", 0))
        dport = int(l4_fields.get("dport", 0))
    except Exception:
        return None

    # HTTP
    if sport == 80 or dport == 80:
        app = {"layer": "HTTP", "fields": {"info": "HTTP (detected by port 80)"}}
    # HTTPS (no parse)
    elif sport == 443 or dport == 443:
        app = {"layer": "TLS/SSL", "fields": {"info": "TLS/SSL (port 443)"}}
    # DNS
    elif sport == 53 or dport == 53:
        app = {"layer": "DNS", "fields": {"info": "DNS (port 53)"}}
    # DHCP (ports 67/68 UDP)
    elif sport in (67,68) or dport in (67,68):
        app = {"layer": "DHCP", "fields": {"info": "DHCP (ports 67/68)"}}
    # FTP, SMTP, POP, IMAP (basic)
    elif sport in (21,25,110,143) or dport in (21,25,110,143):
        app = {"layer": "Application", "fields": {"info": f"App on ports {sport}/{dport}"}}

    return app

def parse_packet(raw_bytes):
    """
    Entrada: raw_bytes (bytes)
    Salida: dict con keys: layers (list), raw (bytes), summary (str)
    """
    out = {
        "layers": [],
        "raw": raw_bytes,
        "summary": ""
    }

    eth = parse_ethernet(raw_bytes)
    if not eth:
        out["summary"] = "Trama demasiado corta"
        return out

    out["layers"].append({"layer": eth["layer"], "fields": eth["fields"]})

    ethertype = eth["ethertype"]
    payload = eth["payload"]

    # L3: ARP
    if ethertype == ETHERTYPE_ARP:
        if ARP:
            try:
                arp_obj = ARP(payload)
                fields = arp_obj.to_dict() if hasattr(arp_obj, "to_dict") else {}
            except Exception as e:
                fields = {"error": f"ARP parse error: {e}"}
        else:
            # fallback: parse minimal ARP header if at least 28 bytes
            if len(payload) >= 28:
                try:
                    htype, ptype, hlen, plen, oper = struct.unpack("!HHBBH", payload[:8])
                    sha = mac_format(payload[8:14])
                    spa = ".".join(str(b) for b in payload[14:18])
                    tha = mac_format(payload[18:24])
                    tpa = ".".join(str(b) for b in payload[24:28])
                    fields = {
                        "Hardware Type": htype,
                        "Protocol Type": ptype,
                        "Hardware Size": hlen,
                        "Protocol Size": plen,
                        "Opcode": "Request" if oper==1 else "Reply" if oper==2 else oper,
                        "Sender MAC": sha, "Sender IP": spa,
                        "Target MAC": tha, "Target IP": tpa
                    }
                except Exception as e:
                    fields = {"error": f"ARP fallback parse error: {e}"}
            else:
                fields = {"error": "ARP payload too short"}
        out["layers"].append({"layer": "ARP", "fields": fields})
        out["summary"] = f"ARP {fields.get('Sender IP','')} -> {fields.get('Target IP','')}"
        return out

    # L3: IPv4
    if ethertype == ETHERTYPE_IPV4:
        if IPv4Packet:
            try:
                ip_pkt = IPv4Packet(payload)
                ip_fields = {
                    "version": ip_pkt.version,
                    "ihl": getattr(ip_pkt, "ihl", None),
                    "total_length": getattr(ip_pkt, "total_length", None),
                    "ttl": getattr(ip_pkt, "ttl", None),
                    "protocol": getattr(ip_pkt, "proto", None),
                    "src": getattr(ip_pkt, "src", None),
                    "dst": getattr(ip_pkt, "dst", None)
                }
                out["layers"].append({"layer": "IPv4", "fields": ip_fields})
                l4_payload = ip_pkt.payload
                l4_proto = ip_pkt.proto
            except Exception as e:
                out["layers"].append({"layer":"IPv4","fields":{"error":str(e)}})
                out["summary"] = "IPv4 parse error"
                return out
        else:
            # fallback: parse basic IPv4 header
            if len(payload) >= 20:
                try:
                    version_ihl = payload[0]
                    version = version_ihl >> 4
                    ihl = (version_ihl & 0x0F) * 4
                    total_len = struct.unpack("!H", payload[2:4])[0]
                    ttl = payload[8]
                    proto = payload[9]
                    src_ip = ".".join(str(b) for b in payload[12:16])
                    dst_ip = ".".join(str(b) for b in payload[16:20])
                    ip_fields = {"version": version, "ihl": ihl, "total_length": total_len, "ttl": ttl, "protocol": proto, "src": src_ip, "dst": dst_ip}
                    out["layers"].append({"layer":"IPv4","fields":ip_fields})
                    l4_payload = payload[ihl:total_len]
                    l4_proto = proto
                except Exception as e:
                    out["layers"].append({"layer":"IPv4","fields":{"error":str(e)}})
                    out["summary"] = "IPv4 fallback error"
                    return out
            else:
                out["layers"].append({"layer":"IPv4","fields":{"error":"too short"}})
                return out

    # L3: IPv6
    elif ethertype == ETHERTYPE_IPV6:
        if IPv6Packet:
            try:
                ip6 = IPv6Packet(payload)
                ip6_fields = {
                    "version": ip6.version,
                    "traffic_class": ip6.traffic_class,
                    "flow_label": ip6.flow_label,
                    "payload_length": ip6.payload_length,
                    "next_header": ip6.next_header,
                    "hop_limit": ip6.hop_limit,
                    "src": ip6.src,
                    "dst": ip6.dst
                }
                out["layers"].append({"layer": "IPv6", "fields": ip6_fields})
                l4_payload = ip6.payload
                l4_proto = ip6.next_header
            except Exception as e:
                out["layers"].append({"layer":"IPv6","fields":{"error":str(e)}})
                out["summary"] = "IPv6 parse error"
                return out
        else:
            out["layers"].append({"layer":"IPv6","fields":{"error":"no parser installed"}})
            return out
    else:
        out["summary"] = f"Unknown EtherType 0x{ethertype:04x}"
        return out

    # --- L4 parsing based on l4_proto ---
    l4_fields = {}
    if l4_proto == IPPROTO_TCP:
        if tcp_parser:
            try:
                t = tcp_parser(l4_payload)
                l4_fields = t
            except Exception as e:
                l4_fields = {"error": f"tcp parse error: {e}"}
        else:
            # minimal TCP parse: sport,dport,data_offset
            if len(l4_payload) >= 20:
                sport, dport, seq, ack, offset_reserved_flags = struct.unpack("!HHIIH", l4_payload[:14])
                data_offset = (offset_reserved_flags >> 12) * 4
                l4_fields = {"proto":"TCP","sport":sport,"dport":dport,"seq":seq,"ack":ack,"data_offset":data_offset}
            else:
                l4_fields = {"error":"tcp payload too short"}
        out["layers"].append({"layer":"TCP","fields":l4_fields})

    elif l4_proto == IPPROTO_UDP:
        if udp_parser:
            try:
                u = udp_parser(l4_payload)
                l4_fields = u
            except Exception as e:
                l4_fields = {"error": f"udp parse error: {e}"}
        else:
            if len(l4_payload) >= 8:
                sport, dport, length = struct.unpack("!HHH", l4_payload[:6])
                l4_fields = {"proto":"UDP","sport":sport,"dport":dport,"length":length}
            else:
                l4_fields = {"error":"udp payload too short"}
        out["layers"].append({"layer":"UDP","fields":l4_fields})

    elif l4_proto == IPPROTO_ICMP:
        if icmp_parser:
            try:
                ic = icmp_parser(l4_payload)
                l4_fields = ic
            except Exception as e:
                l4_fields = {"error": f"icmp parse error: {e}"}
        else:
            if len(l4_payload) >= 4:
                ic_type = l4_payload[0]
                ic_code = l4_payload[1]
                l4_fields = {"proto":"ICMP","type":ic_type,"code":ic_code}
            else:
                l4_fields = {"error":"icmp payload too short"}
        out["layers"].append({"layer":"ICMP","fields":l4_fields})

    else:
        out["layers"].append({"layer":"L4","fields":{"proto":l4_proto}})

    # Detect app-layer basics
    app = detect_application(l4_fields)
    if app:
        out["layers"].append(app)

    # Build summary
    try:
        l3 = next((l for l in out["layers"] if l["layer"] in ("IPv4","IPv6")), None)
        l4 = next((l for l in out["layers"] if l["layer"] in ("TCP","UDP")), None)
        if l3 and l4:
            out["summary"] = f"{l3['fields'].get('src','')} -> {l3['fields'].get('dst','')} {l4['layer']}"
        elif l3:
            out["summary"] = f"{l3['fields'].get('src','')} -> {l3['fields'].get('dst','')}"
        else:
            out["summary"] = eth["fields"].get("ethertype","")
    except Exception:
        pass

    return out
