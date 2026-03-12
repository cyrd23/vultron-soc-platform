#!/usr/bin/env python3
import json
import os
from datetime import datetime, UTC
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = Path.home() / "soc"
INTEL_DIR = BASE / "intel"
IOC_DIR = INTEL_DIR / "iocs"
ENRICHED_DIR = INTEL_DIR / "enriched"

IPINFO_TOKEN = os.environ.get("IPINFO", "").strip()

IPINFO_URL = "https://ipinfo.io"


def ensure_dirs():
    ENRICHED_DIR.mkdir(parents=True, exist_ok=True)


def latest_structured_ioc_file() -> Path | None:
    files = sorted(IOC_DIR.glob("*_structured_iocs.json"))
    return files[-1] if files else None


def load_json(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def ipinfo_lookup(ip: str) -> dict:
    if not IPINFO_TOKEN:
        return {"error": "missing_ipinfo_token"}

    try:
        r = requests.get(
            f"{IPINFO_URL}/{ip}/json",
            params={"token": IPINFO_TOKEN},
            timeout=30,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def score_ioc(ioc: dict, enrichment: dict | None = None) -> tuple[int, list[str]]:
    score = 0
    reasons = []

    source = str(ioc.get("source", "")).lower()
    confidence = str(ioc.get("confidence", "")).lower()
    threat = str(ioc.get("threat", "")).lower()
    tags = [str(t).lower() for t in ioc.get("tags", []) if str(t).strip()]

    if source == "urlhaus":
        score += 40
        reasons.append("IOC sourced from URLhaus")

    if confidence == "high":
        score += 20
        reasons.append("High source confidence")

    if "malware" in threat:
        score += 15
        reasons.append("Threat classified as malware-related")

    if "download" in threat:
        score += 10
        reasons.append("Threat indicates malware download infrastructure")

    tag_hits = {"mozi", "njrat", "elf", "infostealer", "ransomware", "botnet"}
    matched_tags = sorted(tag_hits.intersection(set(tags)))
    if matched_tags:
        score += 10
        reasons.append(f"Suspicious malware-family or campaign tags present: {', '.join(matched_tags)}")

    if enrichment and isinstance(enrichment, dict):
        country = str(enrichment.get("country", "")).upper()
        org = str(enrichment.get("org", ""))

        if country:
            reasons.append(f"IP geolocated to country: {country}")

        if org:
            reasons.append(f"ASN/Org observed: {org}")

    score = max(0, min(score, 100))
    return score, reasons


def recommend_action(score: int, ioc_type: str) -> str:
    if score >= 80:
        return f"escalate_and_review_{ioc_type}"
    if score >= 60:
        return f"high_priority_review_{ioc_type}"
    if score >= 40:
        return f"monitor_and_hunt_{ioc_type}"
    return f"context_only_{ioc_type}"


def enrich_ioc(ioc: dict) -> dict:
    enriched = dict(ioc)

    enrichment = {}
    if ioc.get("type") == "ip":
        enrichment = ipinfo_lookup(ioc["value"])

    score, reasons = score_ioc(ioc, enrichment)

    enriched["enrichment"] = enrichment
    enriched["malicious_score"] = score
    enriched["score_reasons"] = reasons
    enriched["recommended_action"] = recommend_action(score, ioc.get("type", "ioc"))

    return enriched


def run():
    ensure_dirs()

    latest = latest_structured_ioc_file()
    if not latest:
        print("No structured IOC file found.")
        return

    data = load_json(latest)
    iocs = data.get("iocs", [])

    enriched_iocs = []
    for idx, ioc in enumerate(iocs, start=1):
        enriched_iocs.append(enrich_ioc(ioc))
        if idx % 100 == 0:
            print(f"Processed {idx} IOCs...")

    output = {
        "generated_at": datetime.now(UTC).isoformat(),
        "source_file": latest.name,
        "ioc_count": len(enriched_iocs),
        "iocs": enriched_iocs,
    }

    timestamp = datetime.now(UTC).strftime("%Y-%m-%d")
    out_file = ENRICHED_DIR / f"{timestamp}_enriched_iocs.json"
    out_file.write_text(json.dumps(output, indent=2), encoding="utf-8")

    print(f"Enriched IOC file created: {out_file}")
    print(f"Total enriched IOCs: {len(enriched_iocs)}")

    top = sorted(
        enriched_iocs,
        key=lambda x: x.get("malicious_score", 0),
        reverse=True
    )[:10]

    if top:
        print("Top IOC scores:")
        for ioc in top:
            print(
                f"  - {ioc.get('type')} {ioc.get('value')} "
                f"score={ioc.get('malicious_score')} "
                f"action={ioc.get('recommended_action')}"
            )


if __name__ == "__main__":
    run()
