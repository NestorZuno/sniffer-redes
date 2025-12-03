# export/export_csv.py
import csv

def export_csv(path, packets):
    """
    Exporta los paquetes a CSV.
    Usa solo columnas básicas para no complicarlo.
    """
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["#", "Time", "Source", "Destination", "Protocol", "Summary"])

            for i, p in enumerate(packets, 1):
                layers = p.get("layers", [])
                l3 = next((l for l in layers if l["layer"] in ("IPv4", "IPv6")), None)
                l4 = next((l for l in layers if l["layer"] in ("TCP", "UDP", "ICMP")), None)

                src = l3["fields"].get("src", "") if l3 else ""
                dst = l3["fields"].get("dst", "") if l3 else ""
                proto = l4["layer"] if l4 else layers[-1]["layer"]
                summary = p.get("summary", "")
                timestamp = p.get("_pcap_ts", "")

                writer.writerow([i, timestamp, src, dst, proto, summary])

        return True
    except Exception as e:
        print("Error exportando CSV:", e)
        return False
