#!/usr/bin/env python3
import json
from pathlib import Path
import os

BASE = Path.home() / "soc"
#REPORTS_DIR = BASE / "reports"
REPORTS_DIR = Path(os.environ.get("VULTRON_RUN_DIR", BASE / "reports"))

def load_json(file_path):
    with open(file_path, "r") as f:
        return json.load(f)


def triage(summary, intel):
    hunt = summary.get("hunt")
    findings = summary.get("findings", 0)
    entities = summary.get("entities", {})
    notes = []
    verdict = "clean"

    if findings == 0:
        return {
            "hunt": hunt,
            "verdict": "clean",
            "notes": ["No findings returned by the hunt"]
        }

    if hunt == "password_spray":
        ips = entities.get("ips", [])
        users = entities.get("users", [])

        if findings >= 1:
            verdict = "suspicious"
            notes.append("Multiple failed logins detected from one or more source IPs")

        if ips:
            notes.append(f"Observed source IP count: {len(ips)}")

        if users:
            notes.append(f"Observed targeted user count: {len(users)}")

    elif hunt == "oauth_consent_abuse":
        users = entities.get("users", [])
        apps = entities.get("apps", [])
        ips = entities.get("ips", [])

        verdict = "needs_review"
        notes.append("OAuth consent, grant, or application-related activity detected")

        if users:
            notes.append(f"Observed user count: {len(users)}")

        if apps:
            notes.append(f"Observed app/action count: {len(apps)}")

        if ips:
            notes.append(f"Observed IP count: {len(ips)}")

    elif hunt == "impossible_travel":
        verdict = "clean"
        notes.append("No suspicious multi-country sign-in pattern returned by current hunt logic")

    else:
        verdict = "needs_review"
        notes.append("Unhandled hunt type; manual review recommended")

    return {
        "hunt": hunt,
        "verdict": verdict,
        "notes": notes
    }


def main():
    summary_files = sorted(REPORTS_DIR.glob("*_summary.json"))

    if not summary_files:
        print("No summary files found.")
        return

    for summary_path in summary_files:
        summary = load_json(summary_path)

        intel_path = REPORTS_DIR / f"{summary['hunt']}_intel.json"
        intel = {}
        if intel_path.exists():
            intel = load_json(intel_path)

        triage_result = triage(summary, intel)

        out_file = REPORTS_DIR / f"{summary['hunt']}_triage.json"
        out_file.write_text(json.dumps(triage_result, indent=2))

        print(f"Triage saved: {out_file}")


if __name__ == "__main__":
    main()
