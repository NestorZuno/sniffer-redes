# parsers/http.py

class HTTP:
    """
    Parser muy simple para solicitudes y respuestas HTTP.
    Detecta método, ruta, versión, headers y payload textual.
    """

    HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}

    def __init__(self, raw_data):
        self.raw = raw_data

        try:
            text = raw_data.decode(errors="replace")
        except:
            text = ""

        self.headers = {}
        self.body = ""

        lines = text.split("\r\n")

        # -------------------------------
        #  Detectar si es Request o Response
        # -------------------------------
        first = lines[0]

        if any(first.startswith(m) for m in self.HTTP_METHODS):
            # HTTP Request
            parts = first.split()
            self.type = "request"
            self.method = parts[0]
            self.path = parts[1] if len(parts) > 1 else "/"
            self.version = parts[2] if len(parts) > 2 else "HTTP/1.1"

        elif first.startswith("HTTP/"):
            # HTTP Response
            parts = first.split()
            self.type = "response"
            self.version = parts[0]
            self.status_code = parts[1] if len(parts) > 1 else "0"
            self.reason = " ".join(parts[2:]) if len(parts) > 2 else ""
        else:
            # No parece HTTP
            self.type = "unknown"
            return

        # -------------------------------
        #  Headers
        # -------------------------------
        i = 1
        while i < len(lines) and lines[i] != "":
            if ":" in lines[i]:
                k, v = lines[i].split(":", 1)
                self.headers[k.strip()] = v.strip()
            i += 1

        # -------------------------------
        #  Body
        # -------------------------------
        self.body = "\n".join(lines[i+1:])

    def to_dict(self):
        base = {
            "Type": self.type,
            "Headers": self.headers,
            "Body": self.body[:200]  # limitar tamaño para evitar gigantadas
        }

        if self.type == "request":
            base.update({
                "Method": self.method,
                "Path": self.path,
                "Version": self.version,
            })

        elif self.type == "response":
            base.update({
                "Version": self.version,
                "Status Code": self.status_code,
                "Reason": self.reason,
            })

        return base
