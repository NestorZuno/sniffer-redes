import random
import time
from datetime import datetime

PROTOCOLS = ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP"]

IP_POOL = [
    "192.168.1.10",
    "192.168.1.20",
    "192.168.1.30",
    "10.0.0.5",
    "172.16.0.3",
    "8.8.8.8",
    "1.1.1.1"
]

class PacketSimulator:
    """
    Genera paquetes simulados para alimentar el sniffer.
    """

    def __init__(self):
        self.counter = 0
        self.running = False

    def start(self):
        """Inicia la generación de paquetes."""
        self.running = True

    def stop(self):
        """Detiene la generación de paquetes."""
        self.running = False

    def generate_packet(self):
        """Genera un paquete con campos realistas."""
        self.counter += 1

        proto = random.choice(PROTOCOLS)
        src = random.choice(IP_POOL)
        dst = random.choice(IP_POOL)

        # Evitar src == dst
        while dst == src:
            dst = random.choice(IP_POOL)

        size = random.randint(60, 1500)
        timestamp = f"{random.random():.6f}"

        info = self._generate_info(proto)

        return {
            "num": self.counter,
            "time": timestamp,
            "src": src,
            "dst": dst,
            "proto": proto,
            "size": size,
            "info": info,
        }

    def _generate_info(self, proto):
        """Crea texto tipo Wireshark según protocolo."""
        if proto == "DNS":
            domain = random.choice(["google.com", "youtube.com", "openai.com"])
            return f"Standard query A {domain}"

        if proto == "HTTP":
            return "GET /index.html 200 OK"

        if proto == "TCP":
            return "TCP Handshake / ACK"

        if proto == "UDP":
            return "UDP datagram"

        if proto == "ICMP":
            return "Echo (ping) request"

        if proto == "ARP":
            return "Who has 192.168.1.1? Tell 192.168.1.20"

        return "Tráfico desconocido"
