#!/usr/bin/env python3
import json
import os
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = Path.home() / "soc"
#REPORTS_DIR = BASE / "reports"
REPORTS_DIR = Path(os.environ.get("VULTRON_RUN_DIR", BASE / "reports"))

ELASTIC_URL = os.environ["ELASTIC_URL"]
ELASTIC_API_KEY = os.environ["ELASTIC_API_KEY"]

HEADERS = {
    "Authorization": f"ApiKey {ELASTIC_API_KEY}",
    "Content-Type": "application/json",
}


def load_json(file_path):
    with open(file_path, "r") as f:
        return json.load(f)


def run_query(query_text):
    payload = {"query": query_text}
    r = requests.post(
        f"{ELASTIC_URL}/_query",
        headers=HEADERS,
        json=payload,
        verify=False,
        timeout=120,
    )
    if not r.ok:
        print("Elastic query failed:")
        print(r.text)
        r.raise_for_status()
    return r.json()


def investigate_password_spray(summary):
    ips = summary.get("entities", {}).get("ips", [])

    if not ips:
        return {
            "hunt": "password_spray",
            "ir_verdict": "no_entities",
            "notes": ["No IPs available for follow-on investigation"]
        }

    ip_filters = " OR ".join([f'source.ip == "{ip}"' for ip in ips[:10]])

    query = f'''
FROM logs-azure.signinlogs*
| WHERE event.outcome == "success" AND ({ip_filters})
| KEEP @timestamp, user.name, source.ip, geo.country_name
| SORT @timestamp DESC
| LIMIT 50
'''.strip()

    result = run_query(query)
    findings = len(result.get("values", []))

    verdict = "no_follow_on_success" if findings == 0 else "follow_on_success_found"
    notes = ["Checked for successful sign-ins from suspicious spray IPs"]

    return {
        "hunt": "password_spray",
        "ir_verdict": verdict,
        "notes": notes,
        "follow_on_success_count": findings,
        "sample_values": result.get("values", [])[:10]
    }


def investigate_oauth_consent(summary):
    users = summary.get("entities", {}).get("users", [])

    if not users:
        return {
            "hunt": "oauth_consent_abuse",
            "ir_verdict": "no_entities",
            "notes": ["No users available for follow-on investigation"]
        }

    user_filters = " OR ".join(
        [f'user.name == "{u}"' for u in users[:10]]
    )

    query = f'''
FROM logs-o365.audit*
| WHERE ({user_filters})
| KEEP @timestamp, user.name, event.action, source.ip
| SORT @timestamp DESC
| LIMIT 100
'''.strip()

    result = run_query(query)
    findings = len(result.get("values", []))

    verdict = "follow_on_o365_activity_found" if findings > 0 else "no_follow_on_o365_activity"
    notes = ["Checked for O365 activity involving users from OAuth consent hunt"]

    return {
        "hunt": "oauth_consent_abuse",
        "ir_verdict": verdict,
        "notes": notes,
        "follow_on_activity_count": findings,
        "sample_values": result.get("values", [])[:10]
    }


def main():
    triage_files = sorted(REPORTS_DIR.glob("*_triage.json"))

    for triage_path in triage_files:
        triage = load_json(triage_path)
        hunt = triage.get("hunt")
        verdict = triage.get("verdict")

        if verdict not in ("suspicious", "needs_review"):
            continue

        summary_path = REPORTS_DIR / f"{hunt}_summary.json"
        if not summary_path.exists():
            continue

        summary = load_json(summary_path)

        if hunt == "password_spray":
            ir_result = investigate_password_spray(summary)
        elif hunt == "oauth_consent_abuse":
            ir_result = investigate_oauth_consent(summary)
        else:
            ir_result = {
                "hunt": hunt,
                "ir_verdict": "not_implemented",
                "notes": ["No IR workflow implemented yet for this hunt"]
            }

        out_file = REPORTS_DIR / f"{hunt}_ir.json"
        out_file.write_text(json.dumps(ir_result, indent=2))
        print(f"IR saved: {out_file}")


if __name__ == "__main__":
    main()
