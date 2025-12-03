# core/packet.py
from dataclasses import dataclass, field
from typing import Any, Dict, List

@dataclass
class Packet:
    """
    Representación simple y serializable de un paquete dentro del sniffer.
    - raw: bytes originales del frame completo (Ethernet + ...)
    - timestamp: opcional, marca temporal si la captura la provee
    - layers: lista ordenada de capas parseadas (cada elemento es dict {"layer":name,"fields":{...}})
    - meta: espacio libre para datos auxiliares (por ejemplo: interfaz, index, flags)
    """
    raw: bytes
    timestamp: float = 0.0
    layers: List[Dict[str, Any]] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def add_layer(self, layer_name: str, fields: Dict[str, Any]):
        """Añade una capa parseada al final de self.layers."""
        self.layers.append({"layer": layer_name, "fields": fields})

    def get_layer(self, name: str):
        """Devuelve la primera capa cuyo 'layer' coincida con name, o None."""
        for l in self.layers:
            if l.get("layer") == name:
                return l
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Exporta una representación limpia (serializable) del paquete."""
        return {
            "timestamp": self.timestamp,
            "layers": self.layers,
            "meta": self.meta,
            "raw_len": len(self.raw),
        }

    def summary(self) -> str:
        """
        Genera un resumen legible. Intenta sacar IPv4/IPv6 + L4 si existen,
        y si no, devuelve el tipo Ethernet (ethertype).
        """
        l3 = self.get_layer("IPv4") or self.get_layer("IPv6")
        l4 = self.get_layer("TCP") or self.get_layer("UDP")
        if l3 and l4:
            src = l3["fields"].get("src") or l3["fields"].get("Source")
            dst = l3["fields"].get("dst") or l3["fields"].get("Destination")
            return f"{src} -> {dst} {l4['layer']}"
        if l3:
            src = l3["fields"].get("src") or l3["fields"].get("Source")
            dst = l3["fields"].get("dst") or l3["fields"].get("Destination")
            return f"{src} -> {dst}"
        eth = self.get_layer("Ethernet")
        if eth:
            return eth["fields"].get("ethertype", "Ethernet frame")
        return "Unknown packet"

# -------------------------------------------------
# Nueva clase Ethernet para que pasen los tests
# -------------------------------------------------

class Ethernet:
    """
    Parser mínimo para cabeceras Ethernet.
    El test solo evalúa que eth.ethertype funcione.
    """
    def __init__(self, raw: bytes):
        self.raw = raw

        if len(raw) < 14:
            raise ValueError("Frame Ethernet demasiado corto")

        # MAC destino (6 bytes)
        self.dst = raw[0:6]

        # MAC origen (6 bytes)
        self.src = raw[6:12]

        # Ethertype (2 bytes)
        self.ethertype = int.from_bytes(raw[12:14], byteorder="big")

    def __repr__(self):
        return f"Ethernet(ethertype=0x{self.ethertype:04x})"