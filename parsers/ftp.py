# parsers/ftp.py

class FTP:
    """
    Parser sencillo para tráfico FTP en texto plano.
    No decodifica datos binarios (solo control channel: puerto 21).
    """

    def __init__(self, raw_data):
        try:
            self.text = raw_data.decode(errors="replace")
        except Exception:
            self.text = "<no decodable text>"

        self.lines = [l.strip() for l in self.text.split("\n") if l.strip()]
        self.parsed = [self._parse_line(l) for l in self.lines]

    def _parse_line(self, line):
        """
        Clasifica si la línea es un comando o una respuesta.
        """

        # Ejemplos de comandos FTP típicos
        ftp_cmds = {
            "USER", "PASS", "LIST", "RETR", "STOR", "PWD",
            "CWD", "QUIT", "TYPE", "PORT", "PASV", "SYST"
        }

        # Si empieza con un comando conocido
        for cmd in ftp_cmds:
            if line.upper().startswith(cmd):
                return {"type": "command", "command": cmd, "raw": line}

        # Si empieza con respuesta numérica (2xx, 3xx, etc)
        if len(line) >= 3 and line[:3].isdigit():
            return {"type": "response", "code": line[:3], "message": line[4:]}

        # Otro texto que no coincide
        return {"type": "unknown", "raw": line}

    def to_dict(self):
        return {
            "Lines": self.lines,
            "Parsed": self.parsed,
        }


def parse_ftp(raw_data):
    return FTP(raw_data)
