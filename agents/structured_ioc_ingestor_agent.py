#!/usr/bin/env python3
import csv
import io
import ipaddress
import json
from datetime import datetime, UTC
from pathlib import Path
from urllib.parse import urlparse

import requests

BASE = Path.home() / "soc"
INTEL_DIR = BASE / "intel"
IOC_DIR = INTEL_DIR / "iocs"
STRUCTURED_DIR = INTEL_DIR / "structured"

URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_online/"


def ensure_dirs():
    IOC_DIR.mkdir(parents=True, exist_ok=True)
    STRUCTURED_DIR.mkdir(parents=True, exist_ok=True)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def split_host_and_port(host: str):
    host = host.strip().lower()

    if ":" in host and host.count(":") == 1:
        left, right = host.rsplit(":", 1)
        if right.isdigit():
            return left, int(right)

    return host, None


def parse_host_from_url(url: str):
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower().strip()

        if not netloc:
            return None, None

        if netloc.startswith("www."):
            netloc = netloc[4:]

        host, port = split_host_and_port(netloc)
        return host, port
    except Exception:
        return None, None


def fetch_urlhaus_csv():
    r = requests.get(
        URLHAUS_CSV,
        timeout=60,
        headers={"User-Agent": "Mozilla/5.0 Vultron-Intel-Agent"}
    )
    r.raise_for_status()
    return r.text


def parse_urlhaus_csv(csv_text: str):
    entries = []

    lines = []
    header_found = False

    for raw_line in csv_text.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("# id,dateadded,url,"):
            line = line[2:] if line.startswith("# ") else line[1:]
            lines.append(line)
            header_found = True
            continue

        if line.startswith("#"):
            continue

        lines.append(line)

    if not header_found or not lines:
        print("No usable header found in URLhaus CSV.")
        return entries

    reader = csv.DictReader(io.StringIO("\n".join(lines)))

    for row in reader:
        url = (row.get("url") or "").strip()
        if not url:
            continue

        host, port = parse_host_from_url(url)

        entries.append({
            "source": "urlhaus",
            "id": (row.get("id") or "").strip(),
            "dateadded": (row.get("dateadded") or "").strip(),
            "url": url,
            "url_status": (row.get("url_status") or "").strip(),
            "last_online": (row.get("last_online") or "").strip(),
            "threat": (row.get("threat") or "").strip(),
            "tags": [t.strip() for t in ((row.get("tags") or "").split(",")) if t.strip()],
            "urlhaus_link": (row.get("urlhaus_link") or "").strip(),
            "reporter": (row.get("reporter") or "").strip(),
            "host": host,
            "port": port,
            "host_type": "ip" if host and is_ip(host) else "domain" if host else None,
        })

    return entries


def build_ioc_objects(urlhaus_entries):
    """
    Build enriched IOC objects instead of flat ip/domain/url arrays.
    """
    iocs = []
    seen = set()

    for e in urlhaus_entries:
        source = "urlhaus"
        confidence = "high"
        threat = e.get("threat", "")
        tags = e.get("tags", [])
        first_seen = e.get("dateadded", "")

        host = e.get("host")
        port = e.get("port")
        url = e.get("url")

        # URL IOC
        if url:
            key = ("url", url)
            if key not in seen:
                seen.add(key)
                iocs.append({
                    "value": url,
                    "type": "url",
                    "source": source,
                    "confidence": confidence,
                    "threat": threat,
                    "tags": tags,
                    "first_seen": first_seen,
                })

        # Domain or IP IOC
        if host:
            if e.get("host_type") == "ip":
                key = ("ip", host)
                if key not in seen:
                    seen.add(key)
                    iocs.append({
                        "value": host,
                        "type": "ip",
                        "source": source,
                        "confidence": confidence,
                        "threat": threat,
                        "tags": tags,
                        "first_seen": first_seen,
                    })

                if port is not None:
                    key = ("ip_port", f"{host}:{port}")
                    if key not in seen:
                        seen.add(key)
                        iocs.append({
                            "value": f"{host}:{port}",
                            "type": "ip_port",
                            "ip": host,
                            "port": port,
                            "source": source,
                            "confidence": confidence,
                            "threat": threat,
                            "tags": tags,
                            "first_seen": first_seen,
                        })

            elif e.get("host_type") == "domain":
                key = ("domain", host)
                if key not in seen:
                    seen.add(key)
                    iocs.append({
                        "value": host,
                        "type": "domain",
                        "source": source,
                        "confidence": confidence,
                        "threat": threat,
                        "tags": tags,
                        "first_seen": first_seen,
                    })

    return iocs


def run():
    ensure_dirs()

    timestamp = datetime.now(UTC).strftime("%Y-%m-%d")
    generated_at = datetime.now(UTC).isoformat()

    csv_text = fetch_urlhaus_csv()
    urlhaus_entries = parse_urlhaus_csv(csv_text)

    urlhaus_file = STRUCTURED_DIR / f"{timestamp}_urlhaus_entries.json"
    urlhaus_file.write_text(json.dumps(urlhaus_entries, indent=2), encoding="utf-8")

    ioc_objects = build_ioc_objects(urlhaus_entries)

    structured_iocs = {
        "generated_at": generated_at,
        "source": "urlhaus",
        "ioc_count": len(ioc_objects),
        "iocs": ioc_objects,
    }

    out_file = IOC_DIR / f"{timestamp}_structured_iocs.json"
    out_file.write_text(json.dumps(structured_iocs, indent=2), encoding="utf-8")

    print("Structured IOC file created:", out_file)
    print("URLhaus entries:", len(urlhaus_entries))
    print("Total IOC objects:", len(ioc_objects))

    by_type = {}
    for ioc in ioc_objects:
        by_type[ioc["type"]] = by_type.get(ioc["type"], 0) + 1

    print("IOC counts by type:", by_type)

    if ioc_objects:
        print("Sample IOCs:")
        for ioc in ioc_objects[:10]:
            print(f"  - {ioc['type']}: {ioc['value']} ({ioc['threat']})")


if __name__ == "__main__":
    run()
