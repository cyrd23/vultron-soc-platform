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


def decide(summary, triage, ir=None):
    hunt = summary.get("hunt")
    triage_verdict = triage.get("verdict", "unknown")
    ir_verdict = ir.get("ir_verdict") if ir else None

    result = {
        "hunt": hunt,
        "coordinator_verdict": "review",
        "severity": "low",
        "recommended_actions": [],
        "playbook_recommendation": None,
        "detection_recommendation": False,
    }

    # Clean results stop here
    if triage_verdict == "clean":
        result["coordinator_verdict"] = "close"
        result["severity"] = "informational"
        result["recommended_actions"].append("Close as clean with no further action")
        return result

    # Password spray workflow
    if hunt == "password_spray":
        if ir_verdict == "follow_on_success_found":
            result["coordinator_verdict"] = "escalate"
            result["severity"] = "high"
            result["recommended_actions"] = [
                "Review successful sign-ins from suspicious spray IPs",
                "Assess impacted user accounts for compromise",
                "Consider temporary IP blocking if maliciousness is confirmed",
            ]
            result["playbook_recommendation"] = "password_spray_response"
            result["detection_recommendation"] = True

        elif ir_verdict == "no_follow_on_success":
            result["coordinator_verdict"] = "monitor"
            result["severity"] = "medium"
            result["recommended_actions"] = [
                "Monitor suspicious spray IPs for follow-on success",
                "Review targeted accounts for lockouts or risk signals",
            ]
            result["playbook_recommendation"] = "password_spray_response"
            result["detection_recommendation"] = True

        elif ir_verdict == "no_entities":
            result["coordinator_verdict"] = "review"
            result["severity"] = "medium"
            result["recommended_actions"] = [
                "Review hunt output because no source IPs were available for IR follow-up",
                "Validate field extraction and hunt logic",
            ]
            result["detection_recommendation"] = True

        else:
            result["coordinator_verdict"] = "review"
            result["severity"] = "medium"
            result["recommended_actions"] = [
                "Review password spray findings manually",
                "Validate whether follow-on authentication occurred",
            ]
            result["playbook_recommendation"] = "password_spray_response"
            result["detection_recommendation"] = True

    # OAuth consent / app grant workflow
    elif hunt == "oauth_consent_abuse":
        if ir_verdict == "follow_on_o365_activity_found":
            result["coordinator_verdict"] = "escalate"
            result["severity"] = "high"
            result["recommended_actions"] = [
                "Review OAuth grant and consented application",
                "Assess downstream O365 activity for impact",
                "Determine whether token or session revocation is needed",
            ]
            result["playbook_recommendation"] = "identity_compromise"
            result["detection_recommendation"] = True

        elif ir_verdict == "no_follow_on_o365_activity":
            result["coordinator_verdict"] = "review"
            result["severity"] = "medium"
            result["recommended_actions"] = [
                "Validate whether the consented application is expected",
                "Review granted permissions and user intent",
            ]
            result["playbook_recommendation"] = "identity_compromise"
            result["detection_recommendation"] = True

        elif ir_verdict == "no_entities":
            result["coordinator_verdict"] = "review"
            result["severity"] = "medium"
            result["recommended_actions"] = [
                "Review OAuth findings because no user entities were available for IR follow-up",
                "Validate field extraction and hunt logic",
            ]
            result["playbook_recommendation"] = "identity_compromise"
            result["detection_recommendation"] = True

        else:
            result["coordinator_verdict"] = "review"
            result["severity"] = "medium"
            result["recommended_actions"] = [
                "Review OAuth consent and grant activity manually",
                "Validate whether downstream O365 impact occurred",
            ]
            result["playbook_recommendation"] = "identity_compromise"
            result["detection_recommendation"] = True

    # Impossible travel workflow
    elif hunt == "impossible_travel":
        result["coordinator_verdict"] = "close"
        result["severity"] = "informational"
        result["recommended_actions"] = [
            "No suspicious multi-country sign-in pattern identified by the current hunt logic"
        ]
        result["detection_recommendation"] = False

    # Fallback for future hunts
    else:
        result["coordinator_verdict"] = "review"
        result["severity"] = "low"
        result["recommended_actions"] = [
            "Manual analyst review recommended",
            "No coordinator logic implemented yet for this hunt type",
        ]
        result["detection_recommendation"] = False

    return result


def main():
    summary_files = sorted(REPORTS_DIR.glob("*_summary.json"))

    if not summary_files:
        print("No summary files found.")
        return

    for summary_path in summary_files:
        summary = load_json(summary_path)
        hunt = summary.get("hunt")

        triage_path = REPORTS_DIR / f"{hunt}_triage.json"
        if not triage_path.exists():
            print(f"Skipping {hunt}: triage file not found")
            continue

        triage = load_json(triage_path)

        ir_path = REPORTS_DIR / f"{hunt}_ir.json"
        ir = load_json(ir_path) if ir_path.exists() else None

        decision = decide(summary, triage, ir)

        out_file = REPORTS_DIR / f"{hunt}_coordinator.json"
        out_file.write_text(json.dumps(decision, indent=2))
        print(f"Coordinator saved: {out_file}")


if __name__ == "__main__":
    main()
