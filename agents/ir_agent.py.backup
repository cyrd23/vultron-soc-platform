#!/usr/bin/env python3
import json
import os
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = Path.home() / "soc"
REPORTS_DIR = Path(os.environ.get("VULTRON_RUN_DIR", BASE / "reports"))

ELASTIC_URL = os.environ["ELASTIC_URL"]
ELASTIC_API_KEY = os.environ["ELASTIC_API_KEY"]

HEADERS = {
    "Authorization": f"ApiKey {ELASTIC_API_KEY}",
    "Content-Type": "application/json",
}


def load_json(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
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


def safe_quote(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def summarize(result, limit=10):
    return {
        "documents_found": result.get("documents_found", 0),
        "columns": [c["name"] for c in result.get("columns", [])],
        "sample_values": result.get("values", [])[:limit],
    }


def summarize_ioc_activity(result):
    """
    Build an operational summary for IOC activity.
    Works best when the query returns row-level event data with:
      - source.ip
      - destination.ip
      - data_stream.dataset
      - event.action
    """
    columns = [c["name"] for c in result.get("columns", [])]
    values = result.get("values", [])

    summary = {
        "total_events": 0,
        "blocked_events": 0,
        "allowed_or_other_events": 0,
        "unique_source_ips": set(),
        "unique_destination_ips": set(),
        "datasets_observed": set(),
        "actions_observed": set(),
    }

    for row in values:
        record = dict(zip(columns, row))
        summary["total_events"] += 1

        action = record.get("event.action")
        dataset = record.get("data_stream.dataset")
        src_ip = record.get("source.ip")
        dst_ip = record.get("destination.ip")

        if dataset not in (None, ""):
            summary["datasets_observed"].add(str(dataset))

        if action not in (None, ""):
            summary["actions_observed"].add(str(action))

        if src_ip not in (None, ""):
            summary["unique_source_ips"].add(str(src_ip))

        if dst_ip not in (None, ""):
            summary["unique_destination_ips"].add(str(dst_ip))

        if str(action).lower() == "deny":
            summary["blocked_events"] += 1
        else:
            summary["allowed_or_other_events"] += 1

    return {
        "total_events": summary["total_events"],
        "blocked_events": summary["blocked_events"],
        "allowed_or_other_events": summary["allowed_or_other_events"],
        "unique_source_ip_count": len(summary["unique_source_ips"]),
        "unique_destination_ip_count": len(summary["unique_destination_ips"]),
        "datasets_observed": sorted(list(summary["datasets_observed"])),
        "actions_observed": sorted(list(summary["actions_observed"])),
    }


# -------------------------------------------------
# Existing workflows
# -------------------------------------------------

def investigate_password_spray(summary):
    ips = summary.get("entities", {}).get("ips", [])

    if not ips:
        return {
            "hunt": "password_spray",
            "ir_verdict": "no_entities",
            "notes": ["No IPs available for follow-on investigation"]
        }

    ip_filters = " OR ".join([f'source.ip == "{safe_quote(ip)}"' for ip in ips[:10]])

    query = f"""
FROM logs-azure.signinlogs*
| WHERE event.outcome == "success" AND ({ip_filters})
| KEEP @timestamp, user.name, source.ip, geo.country_name
| SORT @timestamp DESC
| LIMIT 50
""".strip()

    result = run_query(query)
    findings = result.get("documents_found", 0)

    verdict = "no_follow_on_success" if findings == 0 else "follow_on_success_found"
    notes = ["Checked for successful sign-ins from suspicious spray IPs"]

    return {
        "hunt": "password_spray",
        "ir_verdict": verdict,
        "notes": notes,
        "follow_on_success_count": findings,
        "summary": summarize(result),
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
        [f'user.name == "{safe_quote(u)}"' for u in users[:10]]
    )

    query = f"""
FROM logs-o365.audit*
| WHERE ({user_filters})
| KEEP @timestamp, user.name, event.action, source.ip
| SORT @timestamp DESC
| LIMIT 100
""".strip()

    result = run_query(query)
    findings = result.get("documents_found", 0)

    verdict = "follow_on_o365_activity_found" if findings > 0 else "no_follow_on_o365_activity"
    notes = ["Checked for O365 activity involving users from OAuth consent hunt"]

    return {
        "hunt": "oauth_consent_abuse",
        "ir_verdict": verdict,
        "notes": notes,
        "follow_on_activity_count": findings,
        "summary": summarize(result),
    }


# -------------------------------------------------
# IOC workflows
# -------------------------------------------------

def investigate_malicious_ip_matches(summary):
    ips = summary.get("entities", {}).get("ips", [])

    if not ips:
        return {
            "hunt": "malicious_ip_matches",
            "ir_verdict": "no_entities",
            "notes": ["No IPs available for IOC follow-on investigation"]
        }

    ioc_filters = " OR ".join(
        [f'(source.ip == "{safe_quote(ip)}" OR destination.ip == "{safe_quote(ip)}" OR related.ip == "{safe_quote(ip)}")'
         for ip in ips[:25]]
    )

    # Row-level query for operational interpretation
    row_query = f"""
FROM logs-*
| WHERE ({ioc_filters})
| KEEP @timestamp, source.ip, destination.ip, related.ip, destination.port, host.name, data_stream.dataset, event.action
| SORT @timestamp DESC
| LIMIT 500
""".strip()

    row_result = run_query(row_query)
    ioc_activity_summary = summarize_ioc_activity(row_result)

    # Aggregated query for breadth/context
    agg_query = f"""
FROM logs-*
| WHERE ({ioc_filters})
| STATS total = COUNT(),
        datasets = VALUES(data_stream.dataset),
        actions = VALUES(event.action)
| LIMIT 1
""".strip()

    result = run_query(agg_query)
    findings = result.get("documents_found", 0)
    values = result.get("values", [])

    notes = ["Checked for breadth of telemetry overlap for malicious IOC IPs"]

    if findings == 0 or not values:
        verdict = "no_follow_on_ioc_activity"
    else:
        datasets = []
        actions = []
        columns = [c["name"] for c in result.get("columns", [])]
        row = dict(zip(columns, values[0]))

        datasets = row.get("datasets", []) or []
        actions = row.get("actions", []) or []

        if any(ds in datasets for ds in ["azure.signinlogs", "o365.audit"]):
            verdict = "identity_or_cloud_overlap_found"
            notes.append("IOC IP activity overlaps with identity or cloud telemetry")
        elif any("fortinet" in ds or "zeek" in ds or "crowdstrike.fdr" in ds or "cisco_umbrella" in ds for ds in datasets):
            verdict = "network_overlap_found"
            notes.append("IOC IP activity overlaps primarily with network telemetry")
        else:
            verdict = "ioc_activity_found"
            notes.append("IOC IP activity found, but context needs analyst review")

        lowered_actions = [str(a).lower() for a in actions]

        if "deny" in lowered_actions:
            notes.append("Some matching activity appears denied or blocked")

        if "userloginfailed" in lowered_actions:
            notes.append("Failed login activity observed involving matched IOC IPs")

        if "sign-in activity" in lowered_actions:
            notes.append("Authentication-related activity observed involving matched IOC IPs")

        if (
            ioc_activity_summary["blocked_events"] > 0
            and ioc_activity_summary["allowed_or_other_events"] == 0
        ):
            notes.append("Observed IOC activity appears fully blocked in sampled row-level events")

    return {
        "hunt": "malicious_ip_matches",
        "ir_verdict": verdict,
        "notes": notes,
        "ioc_activity_summary": ioc_activity_summary,
        "summary": summarize(result),
        "row_level_summary": summarize(row_result),
    }


def investigate_malicious_domain_matches(summary):
    domains = summary.get("entities", {}).get("domains", [])

    if not domains:
        return {
            "hunt": "malicious_domain_matches",
            "ir_verdict": "no_entities",
            "notes": ["No domains available for IOC follow-on investigation"]
        }

    domain_filters = " OR ".join(
        [f'dns.question.name == "{safe_quote(d)}"' for d in domains[:25]]
    )

    query = f"""
FROM logs-zeek.dns*
| WHERE ({domain_filters})
| STATS total = COUNT(),
        src_ips = VALUES(source.ip),
        queried_domains = VALUES(dns.question.name)
| LIMIT 1
""".strip()

    result = run_query(query)
    findings = result.get("documents_found", 0)
    values = result.get("values", [])

    notes = ["Checked DNS telemetry for repeated malicious-domain resolution activity"]

    if findings == 0 or not values:
        verdict = "no_follow_on_dns_activity"
    else:
        columns = [c["name"] for c in result.get("columns", [])]
        row = dict(zip(columns, values[0]))

        total = row.get("total", 0)
        src_ips = row.get("src_ips", []) or []

        if total >= 10 or len(src_ips) >= 2:
            verdict = "repeated_dns_resolution_found"
            notes.append("Repeated or multi-host malicious-domain resolution observed")
        else:
            verdict = "limited_dns_resolution_found"
            notes.append("Limited malicious-domain resolution observed")

    return {
        "hunt": "malicious_domain_matches",
        "ir_verdict": verdict,
        "notes": notes,
        "summary": summarize(result),
    }


def investigate_malicious_domain_matches_umbrella(summary):
    domains = summary.get("entities", {}).get("domains", [])

    if not domains:
        return {
            "hunt": "malicious_domain_matches_umbrella",
            "ir_verdict": "no_entities",
            "notes": ["No Umbrella domains available for follow-on investigation"]
        }

    domain_filters = " OR ".join(
        [f'dns.question.name == "{safe_quote(d)}" OR dns.question.registered_domain == "{safe_quote(d)}" OR related.hosts == "{safe_quote(d)}" OR cisco.umbrella.fqdns == "{safe_quote(d)}"'
         for d in domains[:25]]
    )

    query = f"""
FROM logs-cisco_umbrella.log*
| WHERE ({domain_filters})
| STATS total = COUNT(),
        src_ips = VALUES(source.ip),
        actions = VALUES(event.action)
| LIMIT 1
""".strip()

    result = run_query(query)
    findings = result.get("documents_found", 0)
    values = result.get("values", [])

    notes = ["Checked Cisco Umbrella telemetry for follow-on malicious-domain activity"]

    if findings == 0 or not values:
        verdict = "no_follow_on_umbrella_activity"
    else:
        columns = [c["name"] for c in result.get("columns", [])]
        row = dict(zip(columns, values[0]))
        total = row.get("total", 0)
        src_ips = row.get("src_ips", []) or []
        actions = [str(a).lower() for a in (row.get("actions", []) or [])]

        if "dns-request-allowed" in actions:
            verdict = "umbrella_allowed_activity_found"
            notes.append("Umbrella shows allowed traffic to matched domains")
        elif total > 0:
            verdict = "umbrella_activity_found"
            notes.append("Umbrella telemetry shows matched domain activity")

        if len(src_ips) >= 2:
            notes.append("Multiple source IPs observed in Umbrella activity")

    return {
        "hunt": "malicious_domain_matches_umbrella",
        "ir_verdict": verdict,
        "notes": notes,
        "summary": summarize(result),
    }


def investigate_malicious_ip_port_matches(summary):
    raw_path = REPORTS_DIR / "malicious_ip_port_matches_raw.json"

    if not raw_path.exists():
        return {
            "hunt": "malicious_ip_port_matches",
            "ir_verdict": "no_raw_context",
            "notes": ["Raw pack result not found for IP:port investigation"]
        }

    raw = load_json(raw_path)
    values = raw.get("values", [])
    columns = [c["name"] for c in raw.get("columns", [])]

    if not values:
        return {
            "hunt": "malicious_ip_port_matches",
            "ir_verdict": "no_follow_on_ip_port_activity",
            "notes": ["No IP:port hits available for follow-on investigation"]
        }

    ip_port_pairs = []
    for row in values[:50]:
        row_map = dict(zip(columns, row))
        ip = row_map.get("destination.ip")
        port = row_map.get("destination.port")
        if ip and port is not None:
            pair = (str(ip), int(port))
            if pair not in ip_port_pairs:
                ip_port_pairs.append(pair)

    if not ip_port_pairs:
        return {
            "hunt": "malicious_ip_port_matches",
            "ir_verdict": "no_entities",
            "notes": ["No destination IP:port pairs available for follow-on investigation"]
        }

    clauses = [
        f'(destination.ip == "{safe_quote(ip)}" AND destination.port == {port})'
        for ip, port in ip_port_pairs[:25]
    ]

    row_query = f"""
FROM logs-*
| WHERE {" OR ".join(clauses)}
| KEEP @timestamp, source.ip, destination.ip, destination.port, host.name, data_stream.dataset, event.action
| SORT @timestamp DESC
| LIMIT 500
""".strip()

    row_result = run_query(row_query)
    ioc_activity_summary = summarize_ioc_activity(row_result)

    query = f"""
FROM logs-*
| WHERE {" OR ".join(clauses)}
| STATS total = COUNT(),
        datasets = VALUES(data_stream.dataset),
        actions = VALUES(event.action)
| LIMIT 1
""".strip()

    result = run_query(query)
    findings = result.get("documents_found", 0)
    values = result.get("values", [])

    notes = ["Checked repeat activity for matched malicious IP:port pairs"]

    if findings == 0 or not values:
        verdict = "no_follow_on_ip_port_activity"
    else:
        columns = [c["name"] for c in result.get("columns", [])]
        row = dict(zip(columns, values[0]))
        datasets = row.get("datasets", []) or []

        if datasets:
            verdict = "ip_port_activity_found"
            notes.append("Matched malicious IP:port combinations appear in telemetry context")
        else:
            verdict = "limited_ip_port_context"

        if (
            ioc_activity_summary["blocked_events"] > 0
            and ioc_activity_summary["allowed_or_other_events"] == 0
        ):
            notes.append("Observed IP:port activity appears fully blocked in sampled row-level events")

    return {
        "hunt": "malicious_ip_port_matches",
        "ir_verdict": verdict,
        "notes": notes,
        "ioc_activity_summary": ioc_activity_summary,
        "summary": summarize(result),
        "row_level_summary": summarize(row_result),
    }


def investigate_internal_host_to_ioc(summary):
    hosts = summary.get("entities", {}).get("hosts", [])
    ips = summary.get("entities", {}).get("ips", [])

    notes = ["Checked CrowdStrike FDR for internal hosts contacting known malicious infrastructure"]

    if not hosts and not ips:
        return {
            "hunt": "internal_host_to_ioc",
            "ir_verdict": "no_entities",
            "notes": ["No host or IOC context available from compromise detection hunt"]
        }

    raw_path = REPORTS_DIR / "internal_host_to_ioc_raw.json"
    if not raw_path.exists():
        return {
            "hunt": "internal_host_to_ioc",
            "ir_verdict": "no_raw_context",
            "notes": ["Raw pack result not found for internal host to IOC investigation"]
        }

    raw = load_json(raw_path)
    row_summary = summarize(raw)

    if raw.get("documents_found", 0) == 0:
        return {
            "hunt": "internal_host_to_ioc",
            "ir_verdict": "no_internal_endpoint_to_ioc_activity",
            "notes": notes + ["No endpoint-to-IOC connections found in raw FDR results"],
            "summary": row_summary,
        }

    values = raw.get("values", [])
    columns = [c["name"] for c in raw.get("columns", [])]

    host_set = set()
    proc_set = set()
    cmds = []

    for row in values[:50]:
        row_map = dict(zip(columns, row))
        h = row_map.get("host.name") or row_map.get("host.hostname")
        p = row_map.get("process.name")
        c = row_map.get("process.command_line")

        if h:
            host_set.add(str(h))
        if p:
            proc_set.add(str(p))
        if c and len(cmds) < 10:
            cmds.append(str(c))

    verdict = "internal_endpoint_to_ioc_activity_found"
    notes.append(f"Observed host count: {len(host_set)}")
    notes.append(f"Observed process count: {len(proc_set)}")

    if proc_set:
        notes.append("Process-aware endpoint telemetry is available for matched IOC connections")

    return {
        "hunt": "internal_host_to_ioc",
        "ir_verdict": verdict,
        "notes": notes,
        "observed_hosts": sorted(list(host_set)),
        "observed_processes": sorted(list(proc_set)),
        "sample_command_lines": cmds,
        "summary": row_summary,
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

        elif hunt == "malicious_ip_matches":
            ir_result = investigate_malicious_ip_matches(summary)

        elif hunt == "malicious_domain_matches":
            ir_result = investigate_malicious_domain_matches(summary)

        elif hunt == "malicious_domain_matches_umbrella":
            ir_result = investigate_malicious_domain_matches_umbrella(summary)

        elif hunt == "malicious_ip_port_matches":
            ir_result = investigate_malicious_ip_port_matches(summary)

        elif hunt == "internal_host_to_ioc":
            ir_result = investigate_internal_host_to_ioc(summary)

        else:
            ir_result = {
                "hunt": hunt,
                "ir_verdict": "not_implemented",
                "notes": ["No IR workflow implemented yet for this hunt"]
            }

        out_file = REPORTS_DIR / f"{hunt}_ir.json"
        out_file.write_text(json.dumps(ir_result, indent=2), encoding="utf-8")
        print(f"IR saved: {out_file}")


if __name__ == "__main__":
    main()
