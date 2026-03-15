#!/usr/bin/env python3
import json
import os
from pathlib import Path

BASE = Path.home() / "soc"
REPORTS_DIR = Path(os.environ.get("VULTRON_RUN_DIR", BASE / "reports"))


def load_json(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_columns(summary):
    return summary.get("columns", []) or []


def has_column(summary, column_name):
    return column_name in get_columns(summary)


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

    # ----------------------------
    # Existing identity hunts
    # ----------------------------
    if hunt == "password_spray":
        ips = entities.get("ips", [])
        users = entities.get("users", [])

        verdict = "suspicious"
        notes.append("Multiple failed logins detected from one or more source IPs")

        if ips:
            notes.append(f"Observed source IP count: {len(ips)}")

        if users:
            notes.append(f"Observed targeted user count: {len(users)}")

        if findings >= 10:
            notes.append("Finding volume is elevated for password spray behavior")

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

        if findings >= 20:
            notes.append("Finding volume is notable and warrants review for expected vs suspicious app activity")

    elif hunt == "impossible_travel":
        verdict = "clean"
        notes.append("No suspicious multi-country sign-in pattern returned by current hunt logic")

    # ----------------------------
    # IOC-driven hunts
    # ----------------------------
    elif hunt == "malicious_ip_matches":
        ips = entities.get("ips", [])
        apps = entities.get("apps", [])

        # Start conservative but meaningful
        verdict = "needs_review"
        notes.append("Threat-intel IP matches were observed in environment telemetry")

        if ips:
            notes.append(f"Matched IOC IP count: {len(ips)}")

        if apps:
            notes.append(f"Observed action/app indicators: {len(apps)}")

        if has_column(summary, "destination.ip"):
            notes.append("Results include destination IP context")

        if has_column(summary, "source.ip"):
            notes.append("Results include source IP context")

        if findings >= 25:
            verdict = "suspicious"
            notes.append("High volume of matched malicious IP findings")

        if "deny" in [a.lower() for a in apps]:
            notes.append("Some matched traffic appears denied or blocked; review whether this reflects effective control or scanning noise")

        if "userloginfailed" in [a.lower() for a in apps]:
            verdict = "suspicious"
            notes.append("Matched IOC IP activity overlaps with failed login telemetry")

        if "sign-in activity" in [a.lower() for a in apps]:
            verdict = "suspicious"
            notes.append("Matched IOC IP activity overlaps with authentication-related telemetry")

    elif hunt == "malicious_domain_matches":
        domains = entities.get("domains", [])
        ips = entities.get("ips", [])

        verdict = "needs_review"
        notes.append("Threat-intel domain matches were observed in DNS telemetry")

        if domains:
            notes.append(f"Matched domain count: {len(domains)}")

        if ips:
            notes.append(f"Source IP count associated with matched domains: {len(ips)}")

        if findings >= 10:
            verdict = "suspicious"
            notes.append("Repeated malicious-domain matches observed")

        # Common benign false-positive guardrail
        benign_like = {"github.com", "google.com", "microsoft.com"}
        if any(d.lower() in benign_like for d in domains):
            notes.append("One or more matched domains appear potentially benign and should be validated against IOC source filtering")

    elif hunt == "malicious_ip_port_matches":
        ips = entities.get("ips", [])

        verdict = "needs_review"
        notes.append("Threat-intel IP:port matches were observed in network telemetry")

        if ips:
            notes.append(f"Matched IOC IP count: {len(ips)}")

        if findings >= 5:
            verdict = "suspicious"
            notes.append("Multiple malicious IP:port matches observed")

        if has_column(summary, "destination.port"):
            notes.append("Destination port context is available for review")

    # ----------------------------
    # Fallback
    # ----------------------------
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
        out_file.write_text(json.dumps(triage_result, indent=2), encoding="utf-8")

        print(f"Triage saved: {out_file}")


if __name__ == "__main__":
    main()
