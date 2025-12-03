# parsers/pop3.py

class POP3:
    """
    Parser simple para mensajes POP3.
    POP3 es completamente basado en texto (líneas).
    """

    def __init__(self, raw_data):
        self.raw = raw_data

        try:
            self.text = raw_data.decode(errors="replace")
        except:
            self.text = ""

        # La primera línea indica +OK o -ERR
        self.first_line = self.text.split("\r\n")[0] if self.text else ""

    def to_dict(self):
        return {
            "Status": "OK" if self.first_line.startswith("+OK") else "ERROR" if self.first_line.startswith("-ERR") else "Unknown",
            "First Line": self.first_line,
            "Full Message": self.text
        }
