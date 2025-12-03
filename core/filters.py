# core/filters.py

class PacketFilter:
    """
    Sistema básico de filtros para paquetes.
    Los filtros pueden usarse para ignorar tráfico innecesario.
    """

    def __init__(self):
        self.filters = []

    def add_filter(self, func):
        """
        Agrega una función de filtro.
        La función debe recibir un diccionario con los datos del paquete
        y devolver True si el paquete debe PASAR o False si debe ser descartado.
        """
        if callable(func):
            self.filters.append(func)

    def apply(self, packet_dict):
        """
        Ejecuta todos los filtros. 
        Si alguno devuelve False, el paquete es descartado.
        """
        for f in self.filters:
            if not f(packet_dict):
                return False
        return True
