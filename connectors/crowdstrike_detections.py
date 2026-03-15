#!/usr/bin/env python3

import os
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

import requests
from falconpy import Alerts

BASE_URL = "https://api.us-2.crowdstrike.com"

# Optional runtime configuration
VULTRON_ALERT_URL = os.getenv("VULTRON_ALERT_URL")
MIN_SEVERITY = int(os.getenv("CS_MIN_SEVERITY", "40"))   # 40 = Medium
QUERY_LIMIT = int(os.getenv("CS_QUERY_LIMIT", "100"))
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "10"))

BASE_DIR = Path.home() / "soc"
STATE_DIR = BASE_DIR / "vultron" / "state"
STATE_DIR.mkdir(parents=True, exist_ok=True)

PROCESSED_IDS_FILE = STATE_DIR / "processed_alert_ids.json"


def load_processed_ids() -> Set[str]:
    if not PROCESSED_IDS_FILE.exists():
        return set()

    try:
        with PROCESSED_IDS_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return set(data)
    except Exception:
        return set()


def save_processed_ids(processed_ids: Set[str]) -> None:
    with PROCESSED_IDS_FILE.open("w", encoding="utf-8") as f:
        json.dump(sorted(processed_ids), f, indent=2)


def get_run_dir() -> Path:
    run_dir = Path(os.getenv("VULTRON_RUN_DIR", str(BASE_DIR / "runs" / "adhoc_crowdstrike_run")))
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def get_client() -> Alerts:
    client_id = os.getenv("CS_CLIENT_ID")
    client_secret = os.getenv("CS_CLIENT_SECRET")

    if not client_id or not client_secret:
        raise ValueError("CS_CLIENT_ID and CS_CLIENT_SECRET must be set.")

    return Alerts(
        client_id=client_id,
        client_secret=client_secret,
        base_url=BASE_URL
    )


def is_likely_test_activity(alert: Dict[str, Any]) -> bool:
    cmdline = (alert.get("cmdline") or "").lower()
    display_name = (alert.get("display_name") or "").lower()
    description = (alert.get("description") or "").lower()
    filename = (alert.get("filename") or "").lower()
    user_name = (alert.get("user_name") or "").lower()

    raw_blob = json.dumps(alert, default=str).lower()

    test_indicators = [
        "invoke-atomictest",
        "atomic-red-team",
        "redcanaryco/atomic-red-team",
        "winpwn",
        "s3cur3th1ssh1t",
        "testingactivity",
        "powershell-yaml",
        "psscriptpolicytest",
        "gsecdump.exe",
        "atomicredteam",
        "raw.githubusercontent.com",
        "powershellgallery.com",
    ]

    if any(indicator in raw_blob for indicator in test_indicators):
        return True

    if "test" in display_name or "test" in description:
        return True

    if filename == "powershell.exe" and "invoke-atomictest" in cmdline:
        return True

    # Keep your current lab account heuristic for now
    if user_name == "reg":
        return True

    return False


def extract_domains(alert: Dict[str, Any]) -> List[str]:
    domains = []
    for entry in alert.get("dns_requests", []) or []:
        domain = entry.get("domain_name")
        if domain:
            domains.append(domain)
    return sorted(set(domains))


def extract_network_connections(alert: Dict[str, Any]) -> List[Dict[str, Any]]:
    conns = []
    for entry in alert.get("network_accesses", []) or []:
        conns.append({
            "direction": entry.get("connection_direction"),
            "protocol": entry.get("protocol"),
            "local_address": entry.get("local_address"),
            "local_port": entry.get("local_port"),
            "remote_address": entry.get("remote_address"),
            "remote_port": entry.get("remote_port"),
            "timestamp": entry.get("access_timestamp"),
        })
    return conns


def normalize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    device = alert.get("device", {}) or {}
    mitre = alert.get("mitre_attack", []) or []
    first_mitre = mitre[0] if mitre else {}

    severity = alert.get("severity") or 0
    severity_name = alert.get("severity_name") or "Unknown"
    test_activity = is_likely_test_activity(alert)

    normalized = {
        "source": "crowdstrike",
        "vendor": "CrowdStrike",
        "product": alert.get("product"),
        "alert_id": alert.get("composite_id"),
        "indicator_id": alert.get("indicator_id"),
        "status": alert.get("status"),
        "name": alert.get("name"),
        "display_name": alert.get("display_name"),
        "description": alert.get("description"),
        "severity": severity,
        "severity_name": severity_name,
        "priority": alert.get("priority_value"),
        "confidence": alert.get("confidence"),
        "hostname": device.get("hostname"),
        "device_id": device.get("device_id"),
        "platform": device.get("platform_name"),
        "os_version": device.get("os_version"),
        "local_ip": device.get("local_ip"),
        "external_ip": device.get("external_ip"),
        "user": alert.get("user_name"),
        "cmdline": alert.get("cmdline"),
        "filename": alert.get("filename"),
        "filepath": alert.get("filepath"),
        "md5": alert.get("md5"),
        "sha256": alert.get("sha256"),
        "tactic": alert.get("tactic") or first_mitre.get("tactic"),
        "tactic_id": alert.get("tactic_id") or first_mitre.get("tactic_id"),
        "technique": alert.get("technique") or first_mitre.get("technique"),
        "technique_id": alert.get("technique_id") or first_mitre.get("technique_id"),
        "scenario": alert.get("scenario"),
        "objective": alert.get("objective"),
        "pattern_disposition": alert.get("pattern_disposition_description"),
        "created_timestamp": alert.get("created_timestamp"),
        "updated_timestamp": alert.get("updated_timestamp"),
        "event_timestamp": alert.get("timestamp"),
        "falcon_link": alert.get("falcon_host_link"),
        "domains": extract_domains(alert),
        "network_connections": extract_network_connections(alert),
        "lab_context": {
            "likely_test_activity": test_activity,
            "classification": "expected_lab_activity" if test_activity else "needs_triage",
            "reason": (
                "Matched Atomic Red Team / test activity indicators"
                if test_activity else
                "No known test indicators matched"
            ),
        },
        "raw": alert,
    }

    return normalized


def query_alert_ids(client: Alerts) -> List[str]:
    response = client.query_alerts_v2(
        limit=QUERY_LIMIT,
        sort="created_timestamp.desc"
    )

    body = response.get("body", {}) or {}
    errors = body.get("errors", []) or []
    ids = body.get("resources", []) or []

    if errors:
        raise RuntimeError(f"CrowdStrike API returned errors: {json.dumps(errors)}")

    return ids


def get_alert_details(client: Alerts, composite_ids: List[str]) -> List[Dict[str, Any]]:
    if not composite_ids:
        return []

    details = client.get_alerts_v2(composite_ids=composite_ids)
    body = details.get("body", {}) or {}
    errors = body.get("errors", []) or []
    resources = body.get("resources", []) or []

    if errors:
        raise RuntimeError(f"CrowdStrike alert detail fetch returned errors: {json.dumps(errors)}")

    return resources


def filter_alerts(normalized_alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    filtered = []

    for alert in normalized_alerts:
        severity = alert.get("severity") or 0

        # Keep likely lab/test activity even if low severity
        if alert.get("lab_context", {}).get("likely_test_activity"):
            filtered.append(alert)
            continue

        if severity >= MIN_SEVERITY:
            filtered.append(alert)

    return filtered


def remove_already_processed(alerts: List[Dict[str, Any]], processed_ids: Set[str]) -> List[Dict[str, Any]]:
    new_alerts = []
    for alert in alerts:
        alert_id = alert.get("alert_id")
        if alert_id and alert_id not in processed_ids:
            new_alerts.append(alert)
    return new_alerts


def build_summary(total_ids: int, raw_alerts: List[Dict[str, Any]], normalized: List[Dict[str, Any]],
                  filtered: List[Dict[str, Any]], new_alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    classification_counts: Dict[str, int] = {}
    severity_counts: Dict[str, int] = {}

    for alert in new_alerts:
        classification = alert.get("lab_context", {}).get("classification", "unknown")
        severity_name = alert.get("severity_name", "Unknown")

        classification_counts[classification] = classification_counts.get(classification, 0) + 1
        severity_counts[severity_name] = severity_counts.get(severity_name, 0) + 1

    return {
        "source": "crowdstrike",
        "generated_at": __import__("datetime").datetime.now(__import__("datetime").UTC).isoformat(),
        "query_limit": QUERY_LIMIT,
        "min_severity": MIN_SEVERITY,
        "alert_ids_found": total_ids,
        "raw_alert_objects": len(raw_alerts),
        "normalized_alerts": len(normalized),
        "alerts_after_filtering": len(filtered),
        "new_alerts_after_dedupe": len(new_alerts),
        "classification_counts": classification_counts,
        "severity_counts": severity_counts,
        "vultron_alert_url_configured": bool(VULTRON_ALERT_URL),
    }


def post_to_vultron(alerts: List[Dict[str, Any]], processed_ids: Set[str]) -> Set[str]:
    if not VULTRON_ALERT_URL:
        print("[*] VULTRON_ALERT_URL not set. Skipping POST to Vultron.")
        return processed_ids

    for alert in alerts:
        alert_id = alert.get("alert_id")
        try:
            response = requests.post(
                VULTRON_ALERT_URL,
                json=alert,
                timeout=HTTP_TIMEOUT
            )
            response.raise_for_status()
            print(f"[+] Posted alert to Vultron: {alert_id}")
            if alert_id:
                processed_ids.add(alert_id)
        except Exception as exc:
            print(f"[!] Failed to post alert {alert_id} to Vultron: {exc}")

    return processed_ids


def main() -> None:
    try:
        run_dir = get_run_dir()
        client = get_client()
        processed_ids = load_processed_ids()

        print(f"[+] CrowdStrike run dir: {run_dir}")
        print(f"[+] Using CrowdStrike base URL: {BASE_URL}")

        ids = query_alert_ids(client)
        if not ids:
            print("[!] No alert IDs returned.")

            empty_summary = {
                "source": "crowdstrike",
                "generated_at": __import__("datetime").datetime.now(__import__("datetime").UTC).isoformat(),
                "alert_ids_found": 0,
                "raw_alert_objects": 0,
                "normalized_alerts": 0,
                "alerts_after_filtering": 0,
                "new_alerts_after_dedupe": 0,
                "classification_counts": {},
                "severity_counts": {},
                "vultron_alert_url_configured": bool(VULTRON_ALERT_URL),
            }
            write_json(run_dir / "crowdstrike_alerts.json", [])
            write_json(run_dir / "crowdstrike_alerts_summary.json", empty_summary)
            return

        print(f"[+] Alert IDs found: {len(ids)}")

        raw_alerts = get_alert_details(client, ids)
        normalized = [normalize_alert(alert) for alert in raw_alerts]
        filtered = filter_alerts(normalized)
        new_alerts = remove_already_processed(filtered, processed_ids)

        print(f"[+] Raw alert objects: {len(raw_alerts)}")
        print(f"[+] Normalized alerts: {len(normalized)}")
        print(f"[+] Alerts after filtering: {len(filtered)}")
        print(f"[+] New alerts after dedupe: {len(new_alerts)}")

        summary = build_summary(
            total_ids=len(ids),
            raw_alerts=raw_alerts,
            normalized=normalized,
            filtered=filtered,
            new_alerts=new_alerts
        )

        # Write orchestrator artifacts
        write_json(run_dir / "crowdstrike_alerts_raw.json", raw_alerts)
        write_json(run_dir / "crowdstrike_alerts.json", new_alerts)
        write_json(run_dir / "crowdstrike_alerts_summary.json", summary)

        # Console output
        print(json.dumps(new_alerts, indent=2))
        print("[+] Wrote:", run_dir / "crowdstrike_alerts_raw.json")
        print("[+] Wrote:", run_dir / "crowdstrike_alerts.json")
        print("[+] Wrote:", run_dir / "crowdstrike_alerts_summary.json")

        # Optional API forwarding
        processed_ids = post_to_vultron(new_alerts, processed_ids)
        save_processed_ids(processed_ids)

        print("[+] Updated processed alert IDs:", PROCESSED_IDS_FILE)

    except Exception as exc:
        print(f"[!] Script failed: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
