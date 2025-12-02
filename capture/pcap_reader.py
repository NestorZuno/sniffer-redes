# capture/pcap_reader.py
from core.dispatcher import parse_packet
import time

def read_pcap(path, on_packet):
    """
    Lee un pcap y para cada paquete llama on_packet(parsed_dict).
    Requiere scapy; si no está instalado, lanza excepción instructiva.
    on_packet: función que recibe el resultado de parse_packet(raw_bytes)
    """
    try:
        from scapy.all import rdpcap, RawPcapReader
    except Exception as e:
        raise RuntimeError("scapy no está instalado. Instálalo: pip install scapy") from e

    # Usamos RawPcapReader para obtener bytes crudos
    for ts, pkt_bytes in RawPcapReader(path):
        # pkt_bytes ya es bytes de la trama (incluye layer 2 si es pcap normal)
        parsed = parse_packet(bytes(pkt_bytes))
        parsed["_pcap_ts"] = ts
        on_packet(parsed)
        # pequeña pausa opcional
        time.sleep(0.001)
