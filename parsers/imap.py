# parsers/imap.py

class IMAP:
    """
    Parser simple para mensajes IMAP.
    Este protocolo es basado en texto, por lo que solo formateamos líneas.
    """

    def __init__(self, raw_data):
        self.raw = raw_data

        try:
            # Intentamos decodificar como texto ASCII/UTF-8
            text = raw_data.decode(errors="ignore")
            self.lines = text.split("\r\n")
        except:
            self.lines = ["<IMAP data not printable>"]

    def to_dict(self):
        return {
            "Protocol": "IMAP",
            "Lines": self.lines
        }
