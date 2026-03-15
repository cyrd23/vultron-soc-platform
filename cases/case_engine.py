#!/usr/bin/env python3
import json
import os
from datetime import datetime, UTC
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE = Path.home() / "soc"
RUN_DIR = Path(os.environ.get("VULTRON_RUN_DIR", BASE / "reports"))


def load_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def now_utc() -> str:
    return datetime.now(UTC).isoformat()


def severity_rank(severity: str) -> int:
    ranks = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "unknown": 0,
    }
    return ranks.get(str(severity).lower(), 0)


def should_create_case(decision: Dict[str, Any]) -> bool:
    decision_name = (decision.get("decision") or "").lower()
    severity = (decision.get("severity") or "unknown").lower()

    suppressions = {
        "benign",
        "blocked_inbound_hostile_traffic",
        "benign_filtering_noise",
        "no_endpoint_to_ioc_activity",
        "suppress_expected_lab_activity",
    }

    if decision_name in suppressions:
        return False

    return severity in {"medium", "high", "critical"} or decision_name.startswith("escalate_")


def safe_get_list(d: Dict[str, Any], key: str) -> List[str]:
    value = d.get(key, [])
    if isinstance(value, list):
        return [str(x) for x in value if x not in (None, "")]
    return []


def load_hunt_summary(run_dir: Path, hunt: Optional[str]) -> Dict[str, Any]:
    if not hunt:
        return {}
    path = run_dir / f"{hunt}_summary.json"
    if not path.exists():
        return {}
    try:
        data = load_json(path)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def extract_case_context_from_summary(summary: Dict[str, Any]) -> Dict[str, Any]:
    entities = summary.get("entities", {}) or {}

    users = safe_get_list(entities, "users")
    hosts = safe_get_list(entities, "hosts")
    apps = safe_get_list(entities, "apps")
    ips = safe_get_list(entities, "ips")
    domains = safe_get_list(entities, "domains")

    primary_user = users[0] if users else None
    primary_host = hosts[0] if hosts else None
    primary_app = apps[0] if apps else None
    primary_ip = ips[0] if ips else None
    primary_domain = domains[0] if domains else None

    return {
        "primary_user": primary_user,
        "primary_host": primary_host,
        "primary_app": primary_app,
        "primary_ip": primary_ip,
        "primary_domain": primary_domain,
        "users": users[:10],
        "hosts": hosts[:10],
        "apps": apps[:10],
        "ips": ips[:10],
        "domains": domains[:10],
        "findings": summary.get("findings"),
        "category": summary.get("category"),
        "status": summary.get("status"),
    }


def build_case_title(decision: Dict[str, Any], context: Dict[str, Any]) -> str:
    source = decision.get("source")
    hunt = decision.get("hunt", "unknown")
    display_name = decision.get("display_name")
    hostname = decision.get("hostname") or context.get("primary_host")
    user = decision.get("user") or context.get("primary_user")
    app = context.get("primary_app")

    if source == "crowdstrike":
        parts = [display_name or "CrowdStrike alert"]
        if hostname:
            parts.append(f"on {hostname}")
        if user:
            parts.append(f"for {user}")
        return " ".join(parts)

    base_title = hunt.replace("_", " ").title()

    if hunt == "service_principal_abuse" and app:
        return f"{base_title} involving {app}"

    if user:
        return f"{base_title} involving {user}"

    if hostname:
        return f"{base_title} on {hostname}"

    if context.get("primary_domain"):
        return f"{base_title} involving {context.get('primary_domain')}"

    if context.get("primary_ip"):
        return f"{base_title} involving {context.get('primary_ip')}"

    return base_title


def build_case_summary(decision: Dict[str, Any], context: Dict[str, Any]) -> str:
    decision_name = decision.get("decision", "needs_review")
    severity = decision.get("severity", "unknown")
    rationale = decision.get("rationale", []) or []
    findings = context.get("findings")
    category = context.get("category")

    parts = [f"Decision: {decision_name}.", f"Severity: {severity}."]

    if category:
        parts.append(f"Category: {category}.")

    if findings not in (None, ""):
        parts.append(f"Findings: {findings}.")

    if rationale:
        parts.append(rationale[0])

    return " ".join(parts)


def build_recommended_actions(decision: Dict[str, Any], context: Dict[str, Any]) -> List[str]:
    decision_name = (decision.get("decision") or "").lower()
    source = (decision.get("source") or "").lower()
    hunt = (decision.get("hunt") or "").lower()

    if decision_name == "escalate_crowdstrike_high_severity_alert":
        return [
            "Review process tree and parent-child execution chain",
            "Validate whether activity was authorized testing",
            "Review host telemetry in Elastic for related events",
            "Escalate to incident response if unauthorized",
        ]

    if decision_name == "investigate_crowdstrike_alert":
        return [
            "Review CrowdStrike alert details and command line",
            "Validate host activity in Elastic",
            "Determine whether activity is expected or suspicious",
            "Promote to incident if confirmed malicious",
        ]

    if decision_name == "escalate_possible_account_compromise":
        return [
            "Review authentication timeline for the affected account",
            "Validate source IP and geo context",
            "Reset credentials and revoke sessions if needed",
            "Escalate to identity response workflow",
        ]

    if decision_name == "escalate_possible_oauth_abuse":
        return [
            "Review consented application and permissions granted",
            "Identify affected users and tenant scope",
            "Revoke malicious or unauthorized application consent",
            "Escalate to cloud identity response workflow",
        ]

    if decision_name == "potential_compromised_host":
        return [
            "Isolate the host if activity is not expected",
            "Review related endpoint and network telemetry",
            "Collect volatile evidence if needed",
            "Escalate to full incident response",
        ]

    if hunt == "service_principal_abuse":
        return [
            "Review service principal permissions and recent actions",
            "Validate whether the activity is expected automation",
            "Review associated cloud audit activity and app context",
            "Escalate if privileges or behavior appear abnormal",
        ]

    if source == "crowdstrike":
        return [
            "Review the alert in CrowdStrike Falcon",
            "Validate host activity in Elastic",
            "Determine whether behavior is expected or suspicious",
        ]

    return [
        "Review supporting summary, triage, IR, and decision artifacts",
        "Validate whether activity is expected or suspicious",
        "Escalate if additional telemetry supports malicious activity",
    ]


def build_evidence(decision: Dict[str, Any]) -> List[str]:
    evidence = []
    hunt = decision.get("hunt")

    if decision.get("source") == "crowdstrike":
        evidence.extend([
            "crowdstrike_alerts.json",
            "crowdstrike_alerts_triage.json",
            "crowdstrike_alerts_ir.json",
            "crowdstrike_alerts_decision.json",
        ])
    else:
        if hunt:
            evidence.extend([
                f"{hunt}_summary.json",
                f"{hunt}_triage.json",
                f"{hunt}_ir.json",
                f"{hunt}_decision.json",
            ])

    return evidence


def build_case_id(index: int) -> str:
    return f"VUL-{datetime.now(UTC).strftime('%Y%m%d')}-{index:04d}"


def build_case_from_decision(run_dir: Path, decision: Dict[str, Any], index: int) -> Dict[str, Any]:
    hunt = decision.get("hunt")
    summary = load_hunt_summary(run_dir, hunt) if decision.get("source") != "crowdstrike" else {}
    context = extract_case_context_from_summary(summary) if summary else {}

    hostname = decision.get("hostname") or context.get("primary_host")
    user = decision.get("user") or context.get("primary_user")

    return {
        "case_id": build_case_id(index),
        "created_at": now_utc(),
        "updated_at": now_utc(),
        "status": "new",
        "priority": decision.get("severity", "medium"),
        "source": decision.get("source", "vultron"),
        "hunt": hunt,
        "alert_id": decision.get("alert_id"),
        "title": build_case_title(decision, context),
        "summary": build_case_summary(decision, context),
        "decision": decision.get("decision"),
        "severity": decision.get("severity"),
        "hostname": hostname,
        "user": user,
        "display_name": decision.get("display_name"),
        "context": context,
        "rationale": decision.get("rationale", []),
        "recommended_actions": build_recommended_actions(decision, context),
        "evidence": build_evidence(decision),
    }


def collect_decisions(run_dir: Path) -> List[Dict[str, Any]]:
    decisions: List[Dict[str, Any]] = []

    for path in sorted(run_dir.glob("*_decision.json")):
        if path.name == "crowdstrike_decision_summary.json":
            continue

        data = load_json(path)

        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    decisions.append(item)
        elif isinstance(data, dict):
            decisions.append(data)

    return decisions


def main() -> None:
    run_dir = RUN_DIR
    if not run_dir.exists():
        raise FileNotFoundError(f"Run directory not found: {run_dir}")

    decisions = collect_decisions(run_dir)

    case_candidates = [d for d in decisions if should_create_case(d)]
    case_candidates.sort(
        key=lambda d: severity_rank(d.get("severity", "unknown")),
        reverse=True
    )

    cases = [
        build_case_from_decision(run_dir, decision, idx + 1)
        for idx, decision in enumerate(case_candidates)
    ]

    summary = {
        "generated_at": now_utc(),
        "run_dir": str(run_dir),
        "decisions_reviewed": len(decisions),
        "cases_created": len(cases),
        "cases_by_priority": {
            "critical": sum(1 for c in cases if c["priority"] == "critical"),
            "high": sum(1 for c in cases if c["priority"] == "high"),
            "medium": sum(1 for c in cases if c["priority"] == "medium"),
            "low": sum(1 for c in cases if c["priority"] == "low"),
        },
    }

    write_json(run_dir / "cases.json", cases)
    write_json(run_dir / "cases_summary.json", summary)

    print(f"Cases written: {run_dir / 'cases.json'}")
    print(f"Case summary written: {run_dir / 'cases_summary.json'}")
    print(f"Cases created: {len(cases)}")


if __name__ == "__main__":
    main()
