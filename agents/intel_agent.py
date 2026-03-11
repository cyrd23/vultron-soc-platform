#!/usr/bin/env python3
import json
from pathlib import Path
import os

BASE = Path.home() / "soc"
#REPORTS_DIR = BASE / "reports"
REPORTS_DIR = Path(os.environ.get("VULTRON_RUN_DIR", BASE / "reports"))

def load_summary(summary_file):
    with open(summary_file, "r") as f:
        return json.load(f)

def enrich_entities(summary):
    entities = summary.get("entities", {})
    enriched = {
        "hunt": summary.get("hunt"),
        "status": summary.get("status"),
        "findings": summary.get("findings"),
        "enrichment": {
            "users": [{"value": u, "type": "user"} for u in entities.get("users", [])],
            "ips": [{"value": ip, "type": "ip"} for ip in entities.get("ips", [])],
            "apps": [{"value": app, "type": "app"} for app in entities.get("apps", [])],
            "hosts": [{"value": h, "type": "host"} for h in entities.get("hosts", [])],
            "domains": [{"value": d, "type": "domain"} for d in entities.get("domains", [])],
        }
    }
    return enriched

def main():
    summary_files = [
        REPORTS_DIR / "password_spray_summary.json",
        REPORTS_DIR / "oauth_consent_abuse_summary.json",
    ]

    for summary_file in summary_files:
        if not summary_file.exists():
            continue
        summary = load_summary(summary_file)
        enriched = enrich_entities(summary)
        out_file = REPORTS_DIR / f"{summary['hunt']}_intel.json"
        out_file.write_text(json.dumps(enriched, indent=2))
        print(f"Intel output saved: {out_file}")

if __name__ == "__main__":
    main()
