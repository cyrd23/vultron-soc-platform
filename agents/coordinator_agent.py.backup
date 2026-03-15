#!/usr/bin/env python3
import json
import os
from pathlib import Path

BASE = Path.home() / "soc"
REPORTS_DIR = Path(os.environ.get("VULTRON_RUN_DIR", BASE / "reports"))


def load_json(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_ioc_activity_summary(ir: dict) -> dict:
    return ir.get("ioc_activity_summary", {}) or {}


def extract_row_level_summary(ir: dict) -> dict:
    return ir.get("row_level_summary", {}) or {}


def has_finding_file(hunt: str, suffix: str) -> bool:
    return (REPORTS_DIR / f"{hunt}_{suffix}.json").exists()


def classify(hunt: str, summary: dict, triage: dict, ir: dict | None):
    triage_verdict = triage.get("verdict", "unknown")
    triage_notes = triage.get("notes", []) or []

    ir_verdict = None
    ir_notes = []
    ioc_activity = {}
    row_level = {}

    if ir:
        ir_verdict = ir.get("ir_verdict")
        ir_notes = ir.get("notes", []) or []
        ioc_activity = extract_ioc_activity_summary(ir)
        row_level = extract_row_level_summary(ir)

    decision = "needs_review"
    severity = "medium"
    rationale = []

    # ----------------------------
    # Clean / benign defaults
    # ----------------------------
    if triage_verdict == "clean":
        decision = "benign"
        severity = "low"
        rationale.append("Triage found no suspicious activity")
        return {
            "hunt": hunt,
            "decision": decision,
            "severity": severity,
            "rationale": rationale,
        }

    # ----------------------------
    # IOC: malicious_ip_matches
    # ----------------------------
    if hunt == "malicious_ip_matches":
        blocked = ioc_activity.get("blocked_events", 0)
        allowed_other = ioc_activity.get("allowed_or_other_events", 0)
        datasets = set(ioc_activity.get("datasets_observed", []))
        actions = set(ioc_activity.get("actions_observed", []))

        internal_hunt_summary_path = REPORTS_DIR / "internal_host_to_ioc_summary.json"
        internal_hunt_clean = False
        if internal_hunt_summary_path.exists():
            internal_summary = load_json(internal_hunt_summary_path)
            internal_hunt_clean = internal_summary.get("status") == "clean"

        # Best-case interpretation: inbound blocked hostile traffic
        if (
            ir_verdict == "network_overlap_found"
            and blocked > 0
            and allowed_other == 0
            and "fortinet_fortigate.log" in datasets
            and "deny" in actions
            and internal_hunt_clean
        ):
            decision = "blocked_inbound_hostile_traffic"
            severity = "low"
            rationale.append("Threat-intel IOC IPs were observed only in denied network events")
            rationale.append("Fortinet blocked the activity at the edge")
            rationale.append("No endpoint evidence of internal hosts contacting IOC infrastructure")
            return {
                "hunt": hunt,
                "decision": decision,
                "severity": severity,
                "rationale": rationale,
            }

        # Identity or cloud overlap is more serious
        if ir_verdict == "identity_or_cloud_overlap_found":
            decision = "escalate_identity_or_cloud_ioc_overlap"
            severity = "high"
            rationale.append("IOC IP activity overlaps with identity or cloud telemetry")
            rationale.extend(ir_notes[:3])
            return {
                "hunt": hunt,
                "decision": decision,
                "severity": severity,
                "rationale": rationale,
            }

        # Generic suspicious IOC overlap
        if triage_verdict == "suspicious":
            decision = "needs_investigation"
            severity = "medium"
            rationale.append("IOC IP overlap observed and triage flagged suspicious activity")
            rationale.extend(triage_notes[:3])
            if ir_notes:
                rationale.extend(ir_notes[:2])
            return {
                "hunt": hunt,
                "decision": decision,
                "severity": severity,
                "rationale": rationale,
            }

    # ----------------------------
    # IOC: malicious_domain_matches
    # ----------------------------
    elif hunt == "malicious_domain_matches":
        # Zeek-only domain match with known benign noise
        notes_text = " ".join(triage_notes).lower()
        if "potentially benign" in notes_text or "ioc source filtering" in notes_text:
            decision = "benign_filtering_noise"
            severity = "low"
            rationale.append("Matched domain appears to be benign or reflects IOC filtering noise")
            rationale.extend(triage_notes[:2])
            return {
                "hunt": hunt,
                "decision": decision,
                "severity": severity,
                "rationale": rationale,
            }

        if ir_verdict in ("repeated_dns_resolution_found", "limited_dns_resolution_found"):
            decision = "needs_dns_review"
            severity = "medium"
            rationale.append("Malicious-domain resolution was observed in DNS telemetry")
            rationale.extend(ir_notes[:2])
            return {
                "hunt": hunt,
                "decision": decision,
                "severity": severity,
                "rationale": rationale,
            }

    # ----------------------------
    # IOC: malicious_domain_matches_umbrella
    # ----------------------------
    elif hunt == "malicious_domain_matches_umbrella":
        if triage_verdict == "clean":
            decision = "benign"
            severity = "low"
            rationale.append("No Umbrella IOC domain findings returned")
            return {
                "hunt": hunt,
                "decision": decision,
                "severity": severity,
                "rationale": rationale,
            }

        if ir_verdict == "umbrella_allowed_activity_found":
            decision = "escalate_allowed_malicious_domain_activity"
            severity = "high"
            rationale.append("Umbrella shows allowed traffic to matched malicious domains")
            rationale.extend(ir_notes[:2])
            return {
                "hunt": hunt,
                "decision": decision,
                "severity": severity,
                "rationale": rationale,
            }

        if ir_verdict == "umbrella_activity_found":
            decision = "needs_umbrella_review"
            severity = "medium"
            rationale.append("Umbrella telemetry shows domain activity requiring analyst review")
            rationale.extend(ir_notes[:2])
            return {
                "hunt": hunt,
                "decision": decision,
                "severity": severity,
                "rationale": rationale,
            }

    # ----------------------------
    # IOC: malicious_ip_port_matches
    # ----------------------------
    elif hunt == "malicious_ip_port_matches":
        blocked = ioc_activity.get("blocked_events", 0)
        allowed_other = ioc_activity.get("allowed_or_other_events", 0)

        if ir_verdict == "ip_port_activity_found":
            if blocked > 0 and allowed_other == 0:
                decision = "blocked_inbound_hostile_traffic"
                severity = "low"
                rationale.append("IOC IP:port activity was observed but appears fully blocked")
                rationale.extend(ir_notes[:2])
                return {
                    "hunt": hunt,
                    "decision": decision,
                    "severity": severity,
                    "rationale": rationale,
                }

            decision = "needs_investigation"
            severity = "medium"
            rationale.append("IOC IP:port telemetry overlap was observed")
            rationale.extend(ir_notes[:2])
            return {
                "hunt": hunt,
                "decision": decision,
                "severity": severity,
                "rationale": rationale,
            }

        if triage_verdict == "clean":
            decision = "benign"
            severity = "low"
            rationale.append("No suspicious IP:port activity observed")
            return {
                "hunt": hunt,
                "decision": decision,
                "severity": severity,
                "rationale": rationale,
            }

    # ----------------------------
    # Compromise detection
    # ----------------------------
    elif hunt == "internal_host_to_ioc":
        if triage_verdict == "clean":
            decision = "no_endpoint_to_ioc_activity"
            severity = "low"
            rationale.append("No internal endpoint-to-IOC connections were found")
            return {
                "hunt": hunt,
                "decision": decision,
                "severity": severity,
                "rationale": rationale,
            }

        if ir_verdict == "internal_endpoint_to_ioc_activity_found":
            decision = "potential_compromised_host"
            severity = "critical"
            rationale.append("An internal endpoint contacted known malicious infrastructure")
            rationale.extend(ir_notes[:3])
            observed_hosts = ir.get("observed_hosts", []) or []
            if observed_hosts:
                rationale.append(f"Observed host count: {len(observed_hosts)}")
            return {
                "hunt": hunt,
                "decision": decision,
                "severity": severity,
                "rationale": rationale,
            }

    # ----------------------------
    # Identity hunts
    # ----------------------------
    elif hunt == "password_spray":
        if ir_verdict == "follow_on_success_found":
            decision = "escalate_possible_account_compromise"
            severity = "high"
            rationale.append("Password spray activity was followed by successful sign-ins")
            rationale.extend(ir_notes[:2])
            return {
                "hunt": hunt,
                "decision": decision,
                "severity": severity,
                "rationale": rationale,
            }

        if triage_verdict == "suspicious":
            decision = "monitor_password_spray_activity"
            severity = "medium"
            rationale.append("Password spray behavior observed without confirmed follow-on success")
            rationale.extend(triage_notes[:2])
            return {
                "hunt": hunt,
                "decision": decision,
                "severity": severity,
                "rationale": rationale,
            }

    elif hunt == "oauth_consent_abuse":
        if ir_verdict == "follow_on_o365_activity_found":
            decision = "escalate_possible_oauth_abuse"
            severity = "high"
            rationale.append("OAuth-related activity was followed by cloud/O365 activity")
            rationale.extend(ir_notes[:2])
            return {
                "hunt": hunt,
                "decision": decision,
                "severity": severity,
                "rationale": rationale,
            }

        if triage_verdict in ("suspicious", "needs_review"):
            decision = "needs_oauth_review"
            severity = "medium"
            rationale.append("OAuth consent or application activity requires analyst validation")
            rationale.extend(triage_notes[:2])
            return {
                "hunt": hunt,
                "decision": decision,
                "severity": severity,
                "rationale": rationale,
            }

    elif hunt == "impossible_travel":
        if triage_verdict == "clean":
            decision = "benign"
            severity = "low"
            rationale.append("No suspicious travel pattern was identified")
            return {
                "hunt": hunt,
                "decision": decision,
                "severity": severity,
                "rationale": rationale,
            }

    # ----------------------------
    # Generic fallback
    # ----------------------------
    decision = "needs_review"
    severity = "medium"
    rationale.append("No specific coordinator rule matched; manual analyst review recommended")
    if triage_notes:
        rationale.extend(triage_notes[:2])
    if ir_notes:
        rationale.extend(ir_notes[:2])

    return {
        "hunt": hunt,
        "decision": decision,
        "severity": severity,
        "rationale": rationale,
    }


def run():
    summary_files = sorted(REPORTS_DIR.glob("*_summary.json"))

    if not summary_files:
        print("No summary files found.")
        return

    for summary_path in summary_files:
        hunt = summary_path.name.replace("_summary.json", "")
        summary = load_json(summary_path)

        triage_path = REPORTS_DIR / f"{hunt}_triage.json"
        if not triage_path.exists():
            continue

        triage = load_json(triage_path)

        ir_path = REPORTS_DIR / f"{hunt}_ir.json"
        ir = load_json(ir_path) if ir_path.exists() else None

        result = classify(hunt, summary, triage, ir)

        out_file = REPORTS_DIR / f"{hunt}_decision.json"
        out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Decision saved: {out_file}")


if __name__ == "__main__":
    run()
