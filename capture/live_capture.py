# capture/live_capture.py
from scapy.all import sniff
from core.dispatcher import parse_packet
import time

def start_live_capture(interface, on_packet, stop_callback=None, count=0):
    """
    Inicia captura en la interfaz y llama on_packet(parsed).
    Revisa stop_callback() para saber si debe detenerse.
    """
    def _handle(pkt):
        raw = bytes(pkt)
        parsed = parse_packet(raw)
        
        # Agregar timestamp
        parsed["timestamp"] = time.strftime("%H:%M:%S")
        
        on_packet(parsed)

    # Función que Scapy ejecuta con cada paquete para ver si para
    def _stop_check(pkt):
        if stop_callback and stop_callback():
            return True
        return False

    # Iniciamos el sniff pasando el stop_filter
    sniff(
        iface=interface, 
        prn=_handle, 
        stop_filter=_stop_check, 
        store=False, 
        count=count
    )