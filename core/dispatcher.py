# core/dispatcher.py
import struct

# -------------------------------------------------------------------------
# IMPORTAR TODOS LOS PARSERS
# -------------------------------------------------------------------------
def try_import(path, name):
    try:
        module = __import__(path, fromlist=[name])
        return getattr(module, name)
    except Exception as e:
        print(f"⚠️  ERROR IMPORTANDO {name}: {e}")
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
# DETECCIÓN GENÉRICA (Solo para etiquetas simples)
# -------------------------------------------------------------------------
def detect_application(l4):
    try:
        sport = int(l4.get("Source Port", 0))
        dport = int(l4.get("Destination Port", 0))
    except:
        return None

    # Nota: DHCP y DNS ahora se manejan con parsers reales, los quitamos de aquí
    # para no duplicar información o etiquetas simples.
    if 80 in (sport, dport):
        return {"layer": "HTTP", "fields": {"info": "HTTP Traffic"}}
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
    
    l4_payload = b""
    l4_proto = None

    # ------------------ ARP ------------------
    if ethertype == ETHERTYPE_ARP and ARP:
        try:
            arp = ARP(payload)
            out["layers"].append({"layer": "ARP", "fields": arp.to_dict()})
            out["summary"] = f"ARP Who has {arp.tpa}? Tell {arp.spa}"
        except:
            out["layers"].append({"layer": "ARP", "fields": {"error": "ARP parse failed"}})
        return out

    # ------------------ IPv4 ------------------
    if ethertype == ETHERTYPE_IPV4 and IPv4Packet:
        try:
            ip = IPv4Packet(payload)
            out["layers"].append({"layer": "IPv4", "fields": ip.to_dict()})
            out["summary"] = f"IPv4 {ip.src} -> {ip.dst}"
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
            out["summary"] = f"IPv6 {ip6.src} -> {ip6.dst}"
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
            
            # Resumen TCP básico
            sport = f.get("Source Port")
            dport = f.get("Destination Port")
            flags = f.get("Flags")
            out["summary"] = f"{sport} -> {dport} [TCP] {flags}"
            
            # --- AQUÍ ESTÁ LA MEJORA PARA PROTOCOLOS TCP ---
            # El payload TCP empieza en l4_payload[tcp.offset:]
            # tcp.offset es el tamaño del header calculado en el parser TCP
            tcp_payload_data = tcp.payload # Tu parser TCP ya tiene esto guardado en self.payload
            
            # 1. HTTP (Puerto 80)
            if (sport == 80 or dport == 80) and HTTP:
                try:
                    http_parsed = HTTP(tcp_payload_data)
                    out["layers"].append({"layer": "HTTP", "fields": http_parsed.to_dict()})
                    
                    # Resumen Inteligente HTTP
                    d = http_parsed.to_dict()
                    if d.get("Type") == "request":
                        out["summary"] = f"HTTP {d.get('Method')} {d.get('Path')}"
                    elif d.get("Type") == "response":
                        out["summary"] = f"HTTP {d.get('Status Code')} {d.get('Reason')}"
                    else:
                        out["summary"] = "HTTP Data"
                except:
                    pass

            # 2. FTP (Puerto 21)
            elif (sport == 21 or dport == 21) and FTP:
                try:
                    ftp_parsed = FTP(tcp_payload_data)
                    out["layers"].append({"layer": "FTP", "fields": ftp_parsed.to_dict()})
                    
                    # Mostrar primer comando o respuesta en el resumen
                    parsed_lines = ftp_parsed.to_dict().get("Parsed", [])
                    if parsed_lines:
                        first = parsed_lines[0]
                        if first["type"] == "command":
                            out["summary"] = f"FTP Cmd: {first['raw']}"
                        elif first["type"] == "response":
                            out["summary"] = f"FTP Resp: {first['code']} {first['message']}"
                    else:
                        out["summary"] = "FTP Control"
                except:
                    pass

            # 3. SMTP (Puerto 25)
            elif (sport == 25 or dport == 25) and SMTP:
                try:
                    smtp_parsed = SMTP(tcp_payload_data)
                    out["layers"].append({"layer": "SMTP", "fields": smtp_parsed.to_dict()})
                    out["summary"] = "SMTP Email Exchange"
                except:
                    pass

            # 4. POP3 (Puerto 110)
            elif (sport == 110 or dport == 110) and POP3:
                try:
                    pop3_parsed = POP3(tcp_payload_data)
                    out["layers"].append({"layer": "POP3", "fields": pop3_parsed.to_dict()})
                    out["summary"] = f"POP3 {pop3_parsed.to_dict().get('First Line')}"
                except:
                    pass

            # 5. IMAP (Puerto 143)
            elif (sport == 143 or dport == 143) and IMAP:
                try:
                    imap_parsed = IMAP(tcp_payload_data)
                    out["layers"].append({"layer": "IMAP", "fields": imap_parsed.to_dict()})
                    out["summary"] = "IMAP Traffic"
                except:
                    pass

            # Si no es ninguno de los anteriores, usamos la detección simple
            else:
                app = detect_application(f)
                if app: 
                    out["layers"].append(app)
                    if "info" in app["fields"]:
                            out["summary"] = f"{app['layer']} {app['fields']['info']}"

        except Exception as e:
            out["layers"].append({"layer":"TCP","fields":{"error": f"TCP fail: {e}"}})

    # ------------------ UDP ------------------
    if l4_proto == IPPROTO_UDP and UDP:
        try:
            udp = UDP(l4_payload)
            f = udp.to_dict()
            out["layers"].append({"layer": "UDP", "fields": f})
            
            sport = f.get("Source Port")
            dport = f.get("Destination Port")
            length = f.get("Length")
            out["summary"] = f"{sport} -> {dport} [UDP] Len={length}"

            # --- AQUI ESTA LA MAGIA PARA DHCP y DNS ---
            
            # 1. DHCP (Puertos 67 Servidor / 68 Cliente)
            if (sport in (67, 68) or dport in (67, 68)) and DHCP:
                try:
                    # El payload UDP empieza después de los 8 bytes del encabezado UDP
                    dhcp_data = l4_payload[8:]
                    dhcp_parsed = DHCP(dhcp_data)
                    out["layers"].append({"layer": "DHCP", "fields": dhcp_parsed.to_dict()})
                    
                    # Actualizamos el resumen con info útil
                    opts = dhcp_parsed.to_dict().get("Options", {})
                    msg_type = opts.get("DHCP Message Type", "Transaction")
                    out["summary"] = f"DHCP {msg_type}"
                except Exception as e:
                        # Si falla (ej. paquete truncado), mostramos error
                        out["layers"].append({"layer": "DHCP", "fields": {"error": f"DHCP Parse Error: {e}"}})
            # 2. DNS (Puerto 53)
            elif (sport == 53 or dport == 53) and DNS:
                try:
                    dns_data = l4_payload[8:]
                    dns_parsed = DNS(dns_data)
                    d_dict = dns_parsed.to_dict() # Guardamos el dict
                    out["layers"].append({"layer": "DNS", "fields": d_dict})
                    
                    # Resumen VIP:
                    q_name = d_dict.get("Query Name", "Unknown")
                    out["summary"] = f"DNS Query: {q_name}"
                except:
                    pass
            
            # 3. Otras aplicaciones simples
            else:
                app = detect_application(f)
                if app: 
                    out["layers"].append(app)
                    if "info" in app["fields"]:
                            out["summary"] = f"{app['layer']} {app['fields']['info']}"

        except:
            out["layers"].append({"layer":"UDP","fields":{"error":"UDP fail"}})

# ------------------ ICMPv4 ------------------
    if l4_proto == IPPROTO_ICMP and ICMP:
        try:
            ic = ICMP(l4_payload)
            # Guardamos el diccionario primero para poder leer la 'Description'
            ic_data = ic.to_dict()
            
            out["layers"].append({"layer": "ICMP", "fields": ic_data})
            
            # Usamos la descripción legible (ej. "Echo (ping) request")
            # Si no existe el campo (por si no guardaste el otro archivo), usa el Type/Code
            desc = ic_data.get("Description", f"Type={ic.type} Code={ic.code}")
            
            out["summary"] = f"ICMP {desc}"
        except:
            out["layers"].append({"layer":"ICMP","fields":{"error":"ICMP fail"}})
            
    return out