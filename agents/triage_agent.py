#!/usr/bin/env python3
import json
import os
from collections import Counter
from pathlib import Path

BASE = Path.home() / "soc"
REPORTS_DIR = Path(os.environ.get("VULTRON_RUN_DIR", BASE / "reports"))

NON_HUNT_SUMMARY_FILES = {
    "crowdstrike_alerts_summary.json",
    "crowdstrike_triage_summary.json",
    "crowdstrike_ir_summary.json",
    "crowdstrike_decision_summary.json",
    "cases_summary.json",
    "vultron_run_summary.json",
}


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


def triage_crowdstrike_alert(alert):
    alert_id = alert.get("alert_id")
    display_name = alert.get("display_name") or alert.get("name") or "unknown"
    severity = alert.get("severity", 0)
    severity_name = alert.get("severity_name", "Unknown")
    hostname = alert.get("hostname")
    user = alert.get("user")
    tactic = alert.get("tactic")
    technique = alert.get("technique")
    technique_id = alert.get("technique_id")
    cmdline = alert.get("cmdline")
    pattern_disposition = alert.get("pattern_disposition")
    classification = alert.get("lab_context", {}).get("classification")
    likely_test_activity = alert.get("lab_context", {}).get("likely_test_activity", False)
    reason = alert.get("lab_context", {}).get("reason")

    notes = []
    verdict = "clean"

    if likely_test_activity or classification == "expected_lab_activity":
        verdict = "expected_lab_activity"
        notes.append("Connector classified this alert as expected lab/test activity")
        if reason:
            notes.append(reason)
    else:
        if severity >= 70:
            verdict = "suspicious"
            notes.append("High severity CrowdStrike alert requires immediate analyst review")
        elif severity >= 40:
            verdict = "needs_review"
            notes.append("Medium severity CrowdStrike alert requires analyst review")
        else:
            verdict = "clean"
            notes.append("Low severity CrowdStrike alert; review if additional context elevates concern")

    if hostname:
        notes.append(f"Host: {hostname}")

    if user:
        notes.append(f"User: {user}")

    if display_name:
        notes.append(f"Alert name: {display_name}")

    if tactic or technique or technique_id:
        technique_text = " / ".join([x for x in [tactic, technique, technique_id] if x])
        if technique_text:
            notes.append(f"MITRE context: {technique_text}")

    if pattern_disposition:
        notes.append(f"CrowdStrike disposition: {pattern_disposition}")

    if cmdline:
        shortened = cmdline if len(cmdline) <= 300 else cmdline[:300] + "..."
        notes.append(f"Command line: {shortened}")

    return {
        "hunt": "crowdstrike_alert",
        "source": "crowdstrike",
        "alert_id": alert_id,
        "display_name": display_name,
        "severity": severity,
        "severity_name": severity_name,
        "hostname": hostname,
        "user": user,
        "verdict": verdict,
        "notes": notes,
        "classification": classification,
        "event_timestamp": alert.get("event_timestamp"),
        "falcon_link": alert.get("falcon_link"),
    }


def build_crowdstrike_rollup(results):
    verdict_counts = Counter()
    severity_counts = Counter()

    for item in results:
        verdict_counts[item.get("verdict", "unknown")] += 1
        severity_counts[item.get("severity_name", "Unknown")] += 1

    return {
        "hunt": "crowdstrike_alerts",
        "source": "crowdstrike",
        "alert_count": len(results),
        "verdict_counts": dict(verdict_counts),
        "severity_counts": dict(severity_counts),
    }


def main():
    summary_files = sorted(REPORTS_DIR.glob("*_summary.json"))

    if not summary_files:
        print("No summary files found.")

    for summary_path in summary_files:
        if summary_path.name in NON_HUNT_SUMMARY_FILES:
            continue

        summary = load_json(summary_path)

        if not isinstance(summary, dict):
            print(f"Skipping non-dict summary file: {summary_path.name}")
            continue

        hunt = summary.get("hunt")
        if not hunt:
            hunt = summary_path.name.replace("_summary.json", "")

        # guardrail: if this still looks like a non-hunt rollup, skip it
        if hunt in {"crowdstrike_alerts", "crowdstrike_triage", "crowdstrike_ir", "crowdstrike_decision", "cases"}:
            print(f"Skipping non-hunt summary file: {summary_path.name}")
            continue

        summary["hunt"] = hunt

        intel_path = REPORTS_DIR / f"{hunt}_intel.json"
        intel = {}
        if intel_path.exists():
            intel = load_json(intel_path)

        triage_result = triage(summary, intel)

        out_file = REPORTS_DIR / f"{hunt}_triage.json"
        out_file.write_text(json.dumps(triage_result, indent=2), encoding="utf-8")

        print(f"Triage saved: {out_file}")

    # ----------------------------
    # CrowdStrike alert triage
    # ----------------------------
    crowdstrike_alerts_file = REPORTS_DIR / "crowdstrike_alerts.json"
    if crowdstrike_alerts_file.exists():
        alerts = load_json(crowdstrike_alerts_file)

        if not isinstance(alerts, list):
            print("crowdstrike_alerts.json is not a list; skipping CrowdStrike triage")
            return

        crowdstrike_results = [triage_crowdstrike_alert(alert) for alert in alerts]

        detailed_out = REPORTS_DIR / "crowdstrike_alerts_triage.json"
        detailed_out.write_text(json.dumps(crowdstrike_results, indent=2), encoding="utf-8")
        print(f"Triage saved: {detailed_out}")

        rollup = build_crowdstrike_rollup(crowdstrike_results)
        rollup_out = REPORTS_DIR / "crowdstrike_triage_summary.json"
        rollup_out.write_text(json.dumps(rollup, indent=2), encoding="utf-8")
        print(f"Triage saved: {rollup_out}")


if __name__ == "__main__":
    main()
