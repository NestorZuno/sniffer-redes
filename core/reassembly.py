# core/reassembly.py

class ReassemblyBuffer:
    """
    Maneja el reensamblado de fragmentos IP.
    Compatible con IPv4 (y adaptable a IPv6 con pocos cambios).
    """

    def __init__(self):
        # Diccionario donde cada clave es un ID de fragmento
        # y el valor es otro diccionario con la info acumulada
        self.buffers = {}

    def add_fragment(self, src, dst, ident, offset, more_fragments, data):
        """
        Agrega un fragmento al buffer.

        src, dst: IP origen/destino
        ident: ID de fragmentación
        offset: offset del fragmento
        more_fragments: flag MF
        data: payload del fragmento
        """

        key = (src, dst, ident)

        if key not in self.buffers:
            self.buffers[key] = {
                "fragments": {},
                "total_size": None,
                "complete": False
            }

        entry = self.buffers[key]

        # Guardar el fragmento usando offset como índice
        entry["fragments"][offset] = data

        # Si MF = 0 → este es el último fragmento y define el tamaño total
        if more_fragments == 0:
            entry["total_size"] = offset + len(data)

        # Verificar si ya están todos los fragmentos
        return self._try_reassemble(key)

    def _try_reassemble(self, key):
        """
        Intenta ensamblar el paquete completo.
        Devuelve:
            - bytes completos si está listo
            - None si falta algún fragmento
        """

        entry = self.buffers[key]

        if entry["total_size"] is None:
            return None  # Falta el último fragmento

        total = entry["total_size"]
        fragments = entry["fragments"]

        # Crear buffer de tamaño final
        assembled = bytearray(total)

        for offset, data in fragments.items():
            assembled[offset:offset+len(data)] = data

        # Verificar si hay datos faltantes
        for i in range(total):
            if assembled[i] == 0:
                return None  # Aún incompleto

        entry["complete"] = True
        return bytes(assembled)
