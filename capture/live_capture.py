# capture/live_capture.py
# Captura en vivo con scapy; requiere permisos de administrador/root
from scapy.all import sniff
from core.dispatcher import parse_packet

def start_live_capture(interface, on_packet, count=0):
    """
    Inicia captura en la interfaz y llama on_packet(parsed) por cada paquete.
    on_packet recibe dict retornado por parse_packet.
    count=0 -> captura infinita.
    """
    def _handle(pkt):
        raw = bytes(pkt)
        parsed = parse_packet(raw)
        on_packet(parsed)

    sniff(iface=interface, prn=_handle, store=False, count=count)
