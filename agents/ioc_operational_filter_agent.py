#!/usr/bin/env python3

import json
from datetime import datetime, UTC
from pathlib import Path

import yaml

BASE = Path.home() / "soc"
INTEL_DIR = BASE / "intel"

ENRICHED_DIR = INTEL_DIR / "enriched"
OP_DIR = INTEL_DIR / "operational"
CONFIGS_DIR = BASE / "configs"

KNOWN_GOOD_FILE = CONFIGS_DIR / "known_good_iocs.yaml"

MIN_SCORE = 70
MAX_IOCS = 2000


def ensure_dirs():
    OP_DIR.mkdir(parents=True, exist_ok=True)


def latest_enriched_file():
    files = sorted(ENRICHED_DIR.glob("*_enriched_iocs.json"))
    if not files:
        return None
    return files[-1]


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_known_good():
    if not KNOWN_GOOD_FILE.exists():
        return {
            "known_good_ips": set(),
            "known_good_internal_ips": set(),
            "known_good_domains": set(),
        }

    with open(KNOWN_GOOD_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    return {
        "known_good_ips": set(data.get("known_good_ips", []) or []),
        "known_good_internal_ips": set(data.get("known_good_internal_ips", []) or []),
        "known_good_domains": set(d.lower() for d in (data.get("known_good_domains", []) or [])),
    }


def is_known_good_ioc(ioc, known_good):
    ioc_type = ioc.get("type")
    value = str(ioc.get("value", "")).strip()
    lowered = value.lower()

    if ioc_type == "ip":
        if value in known_good["known_good_ips"]:
            return True
        if value in known_good["known_good_internal_ips"]:
            return True

    elif ioc_type == "ip_port":
        ip = str(ioc.get("ip", "")).strip()
        if ip in known_good["known_good_ips"]:
            return True
        if ip in known_good["known_good_internal_ips"]:
            return True

    elif ioc_type == "domain":
        if lowered in known_good["known_good_domains"]:
            return True
        if any(lowered.endswith("." + d) for d in known_good["known_good_domains"]):
            return True

    elif ioc_type == "url":
        # For URLs, suppress if the host matches known-good domains
        from urllib.parse import urlparse
        try:
            host = urlparse(value).netloc.lower()
            if host.startswith("www."):
                host = host[4:]
            if host in known_good["known_good_domains"]:
                return True
            if any(host.endswith("." + d) for d in known_good["known_good_domains"]):
                return True
        except Exception:
            pass

    return False


def filter_iocs(iocs, known_good):
    filtered = []
    suppressed = []

    for ioc in iocs:
        score = ioc.get("malicious_score", 0)
        source = str(ioc.get("source", "")).lower()
        threat = str(ioc.get("threat", "")).lower()
        ioc_type = ioc.get("type")

        if ioc_type not in ["ip", "domain", "ip_port", "url"]:
            continue

        if is_known_good_ioc(ioc, known_good):
            suppressed.append({
                "value": ioc.get("value"),
                "type": ioc.get("type"),
                "reason": "known_good_suppression",
            })
            continue

        if score >= MIN_SCORE:
            filtered.append(ioc)
            continue

        if source == "urlhaus" and "malware" in threat:
            filtered.append(ioc)

    filtered.sort(key=lambda x: x.get("malicious_score", 0), reverse=True)
    filtered = filtered[:MAX_IOCS]

    return filtered, suppressed


def summarize_by_type(iocs):
    counts = {}
    for ioc in iocs:
        t = ioc.get("type", "unknown")
        counts[t] = counts.get(t, 0) + 1
    return counts


def run():
    ensure_dirs()

    enriched_file = latest_enriched_file()
    if not enriched_file:
        print("No enriched IOC file found.")
        return

    known_good = load_known_good()

    data = load_json(enriched_file)
    iocs = data.get("iocs", [])

    filtered, suppressed = filter_iocs(iocs, known_good)

    output = {
        "generated_at": datetime.now(UTC).isoformat(),
        "source_file": enriched_file.name,
        "operational_ioc_count": len(filtered),
        "suppressed_ioc_count": len(suppressed),
        "min_score": MIN_SCORE,
        "max_iocs": MAX_IOCS,
        "known_good_file": str(KNOWN_GOOD_FILE) if KNOWN_GOOD_FILE.exists() else None,
        "ioc_type_counts": summarize_by_type(filtered),
        "suppressed_examples": suppressed[:50],
        "iocs": filtered,
    }

    timestamp = datetime.now(UTC).strftime("%Y-%m-%d")
    out_file = OP_DIR / f"{timestamp}_operational_iocs.json"

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print("Operational IOC file created:", out_file)
    print("Operational IOC count:", len(filtered))
    print("Suppressed known-good IOCs:", len(suppressed))
    print("IOC counts by type:", output["ioc_type_counts"])

    print("\nTop IOCs:")
    for ioc in filtered[:10]:
        print(
            f"{ioc['type']} {ioc['value']} "
            f"score={ioc.get('malicious_score')} "
            f"action={ioc.get('recommended_action')}"
        )

    if suppressed:
        print("\nSuppressed examples:")
        for item in suppressed[:10]:
            print(f"  - {item['type']} {item['value']} ({item['reason']})")


if __name__ == "__main__":
    run()
