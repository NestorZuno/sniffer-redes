# core/utils.py

import binascii
import datetime

def mac_format(raw):
    """Convierte 6 bytes en una dirección MAC legible."""
    return ":".join(f"{b:02x}" for b in raw)

def ipv4_format(raw):
    """Convierte 4 bytes en una dirección IPv4."""
    return ".".join(str(b) for b in raw)

def hexdump(data, length=16):
    """Genera un hexdump legible para depuración."""
    result = []
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        ascii_bytes = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        result.append(f"{i:04x}  {hex_bytes:<48}  {ascii_bytes}")
    return "\n".join(result)

def timestamp():
    """Devuelve timestamp legible."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def safe_decode(data):
    """
    Intenta decodificar bytes como texto sin crashear.
    Útil para protocolos que pueden mezclar binario/texto.
    """
    try:
        return data.decode(errors="replace")
    except:
        return str(data)

def checksum(data):
    """Calcula un checksum simple (para debug, no para validación real)."""
    if len(data) % 2:
        data += b'\x00'

    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i+1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)

    return ~total & 0xFFFF
