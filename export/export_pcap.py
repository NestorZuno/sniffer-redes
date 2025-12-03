# export/export_pcap.py
from scapy.all import wrpcap, Raw

def export_pcap(path, packets):
    """
    Exporta los bytes crudos de cada paquete a un archivo PCAP.
    Solo funciona si parsed["raw"] contiene bytes reales.
    """
    try:
        raw_list = []

        for p in packets:
            raw = p.get("raw", None)
            if raw:
                raw_list.append(Raw(raw))

        if raw_list:
            wrpcap(path, raw_list)
            return True
        else:
            print("No hay paquetes RAW para exportar.")
            return False

    except Exception as e:
        print("Error exportando PCAP:", e)
        return False
