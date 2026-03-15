#!/usr/bin/env python3
import json
import os
from datetime import datetime, timedelta, UTC
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

WINDOW_MINUTES_BEFORE = 5
WINDOW_MINUTES_AFTER = 5


def load_json(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, data):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def run_query(query_text: str):
    payload = {"query": query_text}
    r = requests.post(
        f"{ELASTIC_URL}/_query",
        headers=HEADERS,
        json=payload,
        verify=False,
        timeout=120,
    )
    if not r.ok:
        print("Elastic timeline query failed:")
        print(r.text)
        r.raise_for_status()
    return r.json()


def parse_ts(value: str):
    if not value:
        return None
    # Handles Z timestamps
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def format_ts(dt: datetime):
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def quote(value: str):
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def result_rows(result: dict):
    cols = [c["name"] for c in result.get("columns", [])]
    rows = []
    for row in result.get("values", []):
        rows.append(dict(zip(cols, row)))
    return rows


def extract_first_event_time_from_raw(raw_path: Path):
    if not raw_path.exists():
        return None

    raw = load_json(raw_path)
    cols = [c["name"] for c in raw.get("columns", [])]
    values = raw.get("values", [])

    ts_idx = None
    for i, c in enumerate(cols):
        if c == "@timestamp":
            ts_idx = i
            break

    if ts_idx is None or not values:
        return None

    timestamps = [parse_ts(v[ts_idx]) for v in values if len(v) > ts_idx and v[ts_idx]]
    timestamps = [t for t in timestamps if t]
    if not timestamps:
        return None

    return min(timestamps)


def extract_context_from_raw(raw_path: Path):
    """
    Pull likely pivots from raw hunt output:
    host.name, host.hostname, user.name, process.*, file.*, source/destination IPs
    """
    if not raw_path.exists():
        return {}

    raw = load_json(raw_path)
    rows = result_rows(raw)
    if not rows:
        return {}

    context = {
        "host_names": set(),
        "user_names": set(),
        "process_names": set(),
        "process_command_lines": set(),
        "file_paths": set(),
        "file_hashes": set(),
        "source_ips": set(),
        "destination_ips": set(),
        "event_time": None,
    }

    timestamps = []

    for row in rows[:20]:
        for field in ("host.name", "host.hostname"):
            if row.get(field):
                context["host_names"].add(str(row[field]))

        if row.get("user.name"):
            context["user_names"].add(str(row["user.name"]))

        if row.get("process.name"):
            context["process_names"].add(str(row["process.name"]))

        if row.get("process.command_line"):
            context["process_command_lines"].add(str(row["process.command_line"]))

        for field in ("file.path", "TargetFileName", "file.name"):
            if row.get(field):
                context["file_paths"].add(str(row[field]))

        for field in ("file.hash.sha256", "file.hash.md5", "SHA256HashData", "MD5HashData"):
            if row.get(field):
                context["file_hashes"].add(str(row[field]))

        if row.get("source.ip"):
            context["source_ips"].add(str(row["source.ip"]))

        if row.get("destination.ip"):
            context["destination_ips"].add(str(row["destination.ip"]))

        if row.get("@timestamp"):
            ts = parse_ts(str(row["@timestamp"]))
            if ts:
                timestamps.append(ts)

    if timestamps:
        context["event_time"] = min(timestamps)

    # Convert sets to sorted lists
    return {k: (sorted(list(v)) if isinstance(v, set) else v) for k, v in context.items()}


def build_time_bounds(event_time: datetime | None):
    if not event_time:
        event_time = datetime.now(UTC)
    start = event_time - timedelta(minutes=WINDOW_MINUTES_BEFORE)
    end = event_time + timedelta(minutes=WINDOW_MINUTES_AFTER)
    return format_ts(start), format_ts(end)


def build_where_clause(context: dict):
    clauses = []

    host_names = context.get("host_names", [])[:3]
    user_names = context.get("user_names", [])[:3]
    process_names = context.get("process_names", [])[:3]
    file_paths = context.get("file_paths", [])[:3]
    file_hashes = context.get("file_hashes", [])[:3]
    source_ips = context.get("source_ips", [])[:3]
    destination_ips = context.get("destination_ips", [])[:3]

    if host_names:
        host_clause = " OR ".join(
            [f'host.name == "{quote(h)}" OR host.hostname == "{quote(h)}"' for h in host_names]
        )
        clauses.append(f"({host_clause})")

    if user_names:
        user_clause = " OR ".join([f'user.name == "{quote(u)}"' for u in user_names])
        clauses.append(f"({user_clause})")

    if process_names:
        proc_clause = " OR ".join([f'process.name == "{quote(p)}"' for p in process_names])
        clauses.append(f"({proc_clause})")

    if file_paths:
        file_clause = " OR ".join([f'file.path == "{quote(fp)}"' for fp in file_paths])
        clauses.append(f"({file_clause})")

    if file_hashes:
        hash_clause = " OR ".join(
            [f'file.hash.sha256 == "{quote(h)}" OR file.hash.md5 == "{quote(h)}"' for h in file_hashes]
        )
        clauses.append(f"({hash_clause})")

    if source_ips:
        src_clause = " OR ".join([f'source.ip == "{quote(ip)}"' for ip in source_ips])
        clauses.append(f"({src_clause})")

    if destination_ips:
        dst_clause = " OR ".join([f'destination.ip == "{quote(ip)}"' for ip in destination_ips])
        clauses.append(f"({dst_clause})")

    if not clauses:
        return None

    return " OR ".join(clauses)


def build_timeline_query(context: dict):
    start_ts, end_ts = build_time_bounds(context.get("event_time"))
    where_clause = build_where_clause(context)

    if not where_clause:
        return None

    return f"""
FROM logs-crowdstrike.fdr*, logs-zeek.conn*, logs-zeek.dns*, logs-cisco_umbrella.log*, logs-fortinet_fortigate.log*, logs-azure.signinlogs*, logs-azure.auditlogs*, logs-o365.audit*
| WHERE @timestamp >= TO_DATETIME("{start_ts}") AND @timestamp <= TO_DATETIME("{end_ts}")
| WHERE {where_clause}
| KEEP @timestamp,
       data_stream.dataset,
       event.dataset,
       event.action,
       event.kind,
       event.type,
       host.name,
       host.hostname,
       user.name,
       process.name,
       process.executable,
       process.command_line,
       source.ip,
       source.port,
       destination.ip,
       destination.port,
       destination.geo.country_name,
       dns.question.name,
       url.full,
       url.domain,
       file.name,
       file.path,
       file.hash.sha256,
       file.hash.md5
| SORT @timestamp ASC
| LIMIT 500
""".strip()


def build_markdown(name: str, context: dict, rows: list[dict], out_path: Path):
    lines = []
    lines.append(f"# Timeline: {name}")
    lines.append("")
    if context.get("event_time"):
        lines.append(f"Anchor event time: {format_ts(context['event_time'])}")
        lines.append("")

    lines.append("## Context pivots")
    lines.append("")
    for key in ("host_names", "user_names", "process_names", "file_paths", "file_hashes", "source_ips", "destination_ips"):
        value = context.get(key, [])
        if value:
            lines.append(f"- {key}: {', '.join(value[:5])}")
    lines.append("")

    lines.append("## Timeline")
    lines.append("")
    if not rows:
        lines.append("- No timeline events found in window.")
    else:
        for row in rows[:100]:
            ts = row.get("@timestamp", "unknown-time")
            dataset = row.get("data_stream.dataset") or row.get("event.dataset") or "unknown-dataset"
            action = row.get("event.action") or row.get("event.kind") or row.get("event.type") or "event"
            details = []

            for field in (
                "host.name",
                "user.name",
                "process.name",
                "process.command_line",
                "source.ip",
                "destination.ip",
                "destination.port",
                "dns.question.name",
                "url.domain",
                "file.path",
                "file.hash.sha256",
            ):
                if row.get(field):
                    details.append(f"{field}={row[field]}")

            lines.append(f"- {ts} | {dataset} | {action}")
            if details:
                lines.append(f"  - {' | '.join(details[:6])}")

    out_path.write_text("\n".join(lines), encoding="utf-8")


def process_hunt_raw(raw_path: Path):
    pack_name = raw_path.name.replace("_raw.json", "")
    context = extract_context_from_raw(raw_path)

    if not context.get("event_time"):
        context["event_time"] = extract_first_event_time_from_raw(raw_path)

    query = build_timeline_query(context)
    if not query:
        print(f"Skipping timeline for {pack_name}: no usable pivots found")
        return

    result = run_query(query)
    rows = result_rows(result)

    json_out = REPORTS_DIR / f"{pack_name}_timeline.json"
    md_out = REPORTS_DIR / f"{pack_name}_timeline.md"

    save_json(json_out, {
        "name": pack_name,
        "context": {
            **context,
            "event_time": format_ts(context["event_time"]) if context.get("event_time") else None,
        },
        "event_count": len(rows),
        "events": rows,
    })
    build_markdown(pack_name, context, rows, md_out)

    print(f"Timeline saved: {json_out}")
    print(f"Timeline note : {md_out}")


def process_crowdstrike_alerts():
    alerts_path = REPORTS_DIR / "crowdstrike_alerts.json"
    if not alerts_path.exists():
        return

    data = load_json(alerts_path)
    if not isinstance(data, list):
        return

    for alert in data[:50]:
        if not isinstance(alert, dict):
            continue

        alert_id = alert.get("alert_id") or alert.get("id") or "unknown_alert"
        host = alert.get("host_name") or alert.get("hostname")
        user = alert.get("username") or alert.get("user_name")
        process_name = alert.get("process_name")
        cmd = alert.get("command_line")
        file_hash = alert.get("sha256")
        event_time = parse_ts(alert.get("created_timestamp") or alert.get("timestamp") or "")

        context = {
            "host_names": [host] if host else [],
            "user_names": [user] if user else [],
            "process_names": [process_name] if process_name else [],
            "process_command_lines": [cmd] if cmd else [],
            "file_paths": [],
            "file_hashes": [file_hash] if file_hash else [],
            "source_ips": [],
            "destination_ips": [],
            "event_time": event_time or datetime.now(UTC),
        }

        query = build_timeline_query(context)
        if not query:
            continue

        result = run_query(query)
        rows = result_rows(result)

        json_out = REPORTS_DIR / f"crowdstrike_alert_{alert_id}_timeline.json"
        md_out = REPORTS_DIR / f"crowdstrike_alert_{alert_id}_timeline.md"

        save_json(json_out, {
            "name": f"crowdstrike_alert_{alert_id}",
            "source": "crowdstrike",
            "alert_id": alert_id,
            "context": {
                **context,
                "event_time": format_ts(context["event_time"]) if context.get("event_time") else None,
            },
            "event_count": len(rows),
            "events": rows,
        })
        build_markdown(f"crowdstrike_alert_{alert_id}", context, rows, md_out)

        print(f"Timeline saved: {json_out}")
        print(f"Timeline note : {md_out}")


def main():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    raw_files = sorted(REPORTS_DIR.glob("*_raw.json"))
    for raw_path in raw_files:
        # Skip connector JSON blobs that are not hunt raw outputs
        if raw_path.name == "crowdstrike_alerts.json":
            continue
        process_hunt_raw(raw_path)

    process_crowdstrike_alerts()


if __name__ == "__main__":
    main()
