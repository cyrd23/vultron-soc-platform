#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path

import requests
import yaml
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = Path.home() / "soc"
PACKS_DIR = BASE / "packs" / "threat_hunt_pack_library"
REPORTS_DIR = Path(os.environ.get("VULTRON_RUN_DIR", BASE / "reports"))

ELASTIC_URL = os.environ["ELASTIC_URL"]
ELASTIC_API_KEY = os.environ["ELASTIC_API_KEY"]

HEADERS = {
    "Authorization": f"ApiKey {ELASTIC_API_KEY}",
    "Content-Type": "application/json",
}

ENTITY_HINTS = {
    "users": [
        "user.name",
        "azure.auditlogs.properties.initiated_by.user.userPrincipalName",
        "azure.auditlogs.properties.initiated_by.user.displayName",
    ],
    "ips": [
        "source.ip",
        "client.ip",
        "related.ip",
        "destination.ip",
    ],
    "apps": [
        "azure.auditlogs.properties.initiated_by.app.displayName",
        "azure.auditlogs.properties.initiated_by.app.servicePrincipalName",
        "azure.auditlogs.operation_name",
        "event.action",
    ],
    "hosts": [
        "host.name",
        "observer.hostname",
        "host.hostname",
    ],
    "domains": [
        "dns.question.name",
        "dns.question.registered_domain",
        "destination.domain",
        "url.domain",
        "related.hosts",
        "cisco.umbrella.fqdns",
    ],
}

IOC_SOURCE_PATTERNS = {
    "intel/operational/latest_operational": {
        "dir": BASE / "intel" / "operational",
        "pattern": "*_operational_iocs.json",
    },
    "intel/iocs/latest_structured": {
        "dir": BASE / "intel" / "iocs",
        "pattern": "*_structured_iocs.json",
    },
    "intel/iocs/latest_rss": {
        "dir": BASE / "intel" / "iocs",
        "pattern": "*_rss_iocs.json",
    },
}


def discover_packs():
    packs = []
    for category_dir in PACKS_DIR.iterdir():
        if not category_dir.is_dir():
            continue

        for pack_dir in category_dir.iterdir():
            if not pack_dir.is_dir():
                continue

            pack_yaml = pack_dir / "pack.yaml"
            query_file = pack_dir / "query.esql"

            if pack_yaml.exists():
                packs.append({
                    "category": category_dir.name,
                    "name": pack_dir.name,
                    "path": pack_dir,
                    "pack_yaml": pack_yaml,
                    "query_file": query_file if query_file.exists() else None,
                })

    return sorted(packs, key=lambda x: (x["category"], x["name"]))


def load_pack_metadata(pack_yaml):
    with open(pack_yaml, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


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


def extract_entities(columns, values):
    entities = {k: set() for k in ENTITY_HINTS.keys()}
    col_names = [c["name"] for c in columns]

    for row in values:
        row_map = dict(zip(col_names, row))
        for entity_type, field_candidates in ENTITY_HINTS.items():
            for field in field_candidates:
                if field in row_map and row_map[field] not in (None, "", []):
                    value = row_map[field]
                    if isinstance(value, list):
                        for item in value:
                            if item not in (None, ""):
                                entities[entity_type].add(str(item))
                    else:
                        entities[entity_type].add(str(value))

    return {k: sorted(v)[:25] for k, v in entities.items() if v}


def summarize_result(meta, result):
    findings = len(result.get("values", []))
    status = "clean" if findings == 0 else "suspicious"

    columns = result.get("columns", [])
    values = result.get("values", [])
    entities = extract_entities(columns, values)

    return {
        "hunt": meta.get("name"),
        "category": meta.get("category"),
        "status": status,
        "findings": findings,
        "severity": meta.get("severity", "unknown"),
        "columns": [c["name"] for c in columns],
        "entities": entities,
        "sample_values": values[:5],
    }


def save_report(pack_name, result, summary):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    raw_file = REPORTS_DIR / f"{pack_name}_raw.json"
    summary_file = REPORTS_DIR / f"{pack_name}_summary.json"

    raw_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    summary_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    return raw_file, summary_file


def list_packs():
    for pack in discover_packs():
        print(f"{pack['category']}/{pack['name']}")


def load_latest_iocs(input_source: str):
    source_cfg = IOC_SOURCE_PATTERNS.get(input_source)
    if not source_cfg:
        raise ValueError(f"Unsupported input_source: {input_source}")

    source_dir = source_cfg["dir"]
    pattern = source_cfg["pattern"]

    files = sorted(source_dir.glob(pattern))
    if not files:
        return {}

    latest = files[-1]
    with open(latest, "r", encoding="utf-8") as f:
        data = json.load(f)

    if "iocs" in data and isinstance(data["iocs"], list):
        normalized = {
            "ips": [],
            "domains": [],
            "urls": [],
            "hashes": [],
            "ip_ports": [],
            "ioc_objects": data["iocs"],
            "source_file": latest.name,
        }

        seen_ips = set()
        seen_domains = set()
        seen_urls = set()
        seen_hashes = set()
        seen_ip_ports = set()

        for ioc in data["iocs"]:
            ioc_type = ioc.get("type")
            value = ioc.get("value")

            if ioc_type == "ip" and value and value not in seen_ips:
                seen_ips.add(value)
                normalized["ips"].append(value)

            elif ioc_type == "domain" and value and value not in seen_domains:
                seen_domains.add(value)
                normalized["domains"].append(value)

            elif ioc_type == "url" and value and value not in seen_urls:
                seen_urls.add(value)
                normalized["urls"].append(value)

            elif ioc_type == "hash" and value and value not in seen_hashes:
                seen_hashes.add(value)
                normalized["hashes"].append(value)

            elif ioc_type == "ip_port":
                ip = ioc.get("ip")
                port = ioc.get("port")
                if ip and port is not None:
                    key = (ip, int(port))
                    if key not in seen_ip_ports:
                        seen_ip_ports.add(key)
                        normalized["ip_ports"].append({"ip": ip, "port": int(port)})

        return normalized

    data["source_file"] = latest.name
    return data


def quote_esql_values(values):
    escaped = []
    for v in values:
        s = str(v).replace("\\", "\\\\").replace('"', '\\"')
        escaped.append(f'"{s}"')
    return ",".join(escaped)


def build_ioc_list(iocs, input_type):
    if input_type == "ip_list":
        values = iocs.get("ips", [])
    elif input_type == "domain_list":
        values = iocs.get("domains", [])
    elif input_type == "url_list":
        values = iocs.get("urls", [])
    else:
        values = []

    if not values:
        return None

    return quote_esql_values(values[:500])


def build_ip_port_clause(iocs):
    ip_ports = iocs.get("ip_ports", [])
    if not ip_ports:
        return None

    clauses = []
    for item in ip_ports[:300]:
        ip = str(item["ip"]).replace("\\", "\\\\").replace('"', '\\"')
        port = int(item["port"])
        clauses.append(f'(destination.ip == "{ip}" AND destination.port == {port})')

    return " OR ".join(clauses) if clauses else None


def build_query_for_pack(meta, pack):
    input_type = meta.get("input_type")
    input_source = meta.get("input_source")
    query_template = meta.get("query_template")

    if input_type and input_source and query_template:
        iocs = load_latest_iocs(input_source)

        if input_type == "ip_port_list":
            clause = build_ip_port_clause(iocs)
            if not clause:
                return None, "No IOC ip:port values available"
            query_text = query_template.replace("{ip_port_clause}", clause)
            return query_text, None

        ioc_list = build_ioc_list(iocs, input_type)
        if not ioc_list:
            return None, f"No IOC values available for input_type={input_type}"

        query_text = query_template.replace("{ioc_list}", ioc_list)
        return query_text, None

    if query_template and not input_type and not input_source:
        return query_template.strip(), None

    if pack["query_file"] and pack["query_file"].exists():
        return pack["query_file"].read_text(encoding="utf-8").strip(), None

    return None, "No query source found for pack"


def run_pack(pack_name):
    matches = [p for p in discover_packs() if p["name"] == pack_name]
    if not matches:
        raise SystemExit(f"Pack not found: {pack_name}")

    pack = matches[0]
    meta = load_pack_metadata(pack["pack_yaml"])

    query_text, error = build_query_for_pack(meta, pack)
    if error:
        print(f"Running pack: {meta.get('name', pack_name)}")
        print(f"Skipping pack: {error}")
        return

    print(f"Running pack: {meta['name']}")
    result = run_query(query_text)
    summary = summarize_result(meta, result)
    raw_file, summary_file = save_report(meta["name"], result, summary)

    print(f"{meta['name']} .......... {summary['status']} ({summary['findings']} findings)")

    if result.get("columns") and result.get("values"):
        cols = [c["name"] for c in result["columns"]]

        print("\nSample Findings:")
        for i, row in enumerate(result["values"][:3], 1):
            print(f"\n--- Finding {i} ---")
            for k, v in zip(cols, row):
                print(f"{k}: {v}")

    if summary.get("entities"):
        print("\nEntities:")
        print(json.dumps(summary["entities"], indent=2))

    print(f"\nSummary saved: {summary_file}")
    print(f"Raw saved:     {raw_file}")


def run_category(category):
    packs = [p for p in discover_packs() if p["category"] == category]
    if not packs:
        raise SystemExit(f"No packs found in category: {category}")

    print(f"Running {len(packs)} pack(s) in category: {category}\n")
    for pack in packs:
        run_pack(pack["name"])


def run_all():
    packs = discover_packs()
    print(f"Running {len(packs)} hunt packs...\n")
    for pack in packs:
        run_pack(pack["name"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--list-packs", action="store_true")
    parser.add_argument("--pack")
    parser.add_argument("--category")
    parser.add_argument("--run-all", action="store_true")
    args = parser.parse_args()

    if args.list_packs:
        list_packs()
    elif args.pack:
        run_pack(args.pack)
    elif args.category:
        run_category(args.category)
    elif args.run_all:
        run_all()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
