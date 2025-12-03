# export/export_json.py
import json

def export_json(path, packets):
    """
    Exporta la lista completa de 'packets' (dicts ya parseados)
    a un archivo JSON.
    """
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(packets, f, indent=4)
        return True
    except Exception as e:
        print("Error exportando JSON:", e)
        return False
