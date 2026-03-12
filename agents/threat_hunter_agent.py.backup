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
    ],
    "domains": [
        "dns.question.name",
        "destination.domain",
        "url.domain",
    ],
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
            if pack_yaml.exists() and query_file.exists():
                packs.append({
                    "category": category_dir.name,
                    "name": pack_dir.name,
                    "path": pack_dir,
                    "pack_yaml": pack_yaml,
                    "query_file": query_file,
                })
    return sorted(packs, key=lambda x: (x["category"], x["name"]))

def load_pack_metadata(pack_yaml):
    with open(pack_yaml, "r") as f:
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

    raw_file.write_text(json.dumps(result, indent=2))
    summary_file.write_text(json.dumps(summary, indent=2))

    return raw_file, summary_file

def list_packs():
    for pack in discover_packs():
        print(f"{pack['category']}/{pack['name']}")

def run_pack(pack_name):
    matches = [p for p in discover_packs() if p["name"] == pack_name]
    if not matches:
        raise SystemExit(f"Pack not found: {pack_name}")

    pack = matches[0]
    meta = load_pack_metadata(pack["pack_yaml"])
    query_text = pack["query_file"].read_text().strip()

    print(f"Running pack: {meta['name']}")
    result = run_query(query_text)
    summary = summarize_result(meta, result)
    raw_file, summary_file = save_report(meta["name"], result, summary)

    print(f"{meta['name']} .......... {summary['status']} ({summary['findings']} findings)")
    if summary.get("entities"):
        print(f"Entities: {json.dumps(summary['entities'], indent=2)}")
    print(f"Summary saved: {summary_file}")
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
