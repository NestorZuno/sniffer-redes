# parsers/smtp.py

class SMTP:
    """
    Parser simple para tráfico SMTP basado en texto.
    No interpreta comandos, solo separa encabezados y cuerpo.
    """

    def __init__(self, raw_data):
        # Intentamos decodificar como texto
        try:
            text = raw_data.decode(errors="replace")
        except:
            text = ""

        self.raw_text = text

        # SMTP separa encabezados y cuerpo por una línea vacía
        if "\r\n\r\n" in text:
            headers, body = text.split("\r\n\r\n", 1)
        else:
            headers = text
            body = ""

        # Convertimos encabezados en diccionario
        self.headers = {}
        for line in headers.split("\r\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                self.headers[key.strip()] = value.strip()

        self.body = body

    def to_dict(self):
        return {
            "SMTP Headers": self.headers,
            "Body": self.body[:500] + ("..." if len(self.body) > 500 else ""),  # Evitar saturar la GUI
            "Raw Text": self.raw_text[:500] + ("..." if len(self.raw_text) > 500 else "")
        }
