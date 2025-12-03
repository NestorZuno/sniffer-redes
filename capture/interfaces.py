# capture/interfaces.py
# Lista interfaces disponibles usando Scapy

def list_interfaces():
    """
    Devuelve una lista de interfaces disponibles en el sistema.
    Requiere scapy.
    """
    try:
        from scapy.all import get_if_list
    except Exception as e:
        raise RuntimeError(
            "scapy no está instalado. Instálalo con: pip install scapy"
        ) from e

    return get_if_list()

def print_interfaces():
    """
    Imprime las interfaces disponibles de manera numerada.
    """
    interfaces = list_interfaces()
    print("=== Interfaces disponibles ===")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")

if __name__ == "__main__":
    print_interfaces()
