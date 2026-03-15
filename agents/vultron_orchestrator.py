#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
from collections import Counter
from datetime import datetime, UTC
from pathlib import Path

BASE = Path.home() / "soc"
AGENTS = BASE / "agents"
CONNECTORS = BASE / "connectors"
RUNS_DIR = BASE / "runs"


def run_step(name, cmd, env):
    print(f"\n=== Running: {name} ===")
    print("Command:", " ".join(cmd))
    result = subprocess.run(cmd, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"Step failed: {name}")


def load_json(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_run_summary(run_dir: Path):
    summary_files = sorted(run_dir.glob("*_summary.json"))
    triage_files = sorted(run_dir.glob("*_triage.json"))
    ir_files = sorted(run_dir.glob("*_ir.json"))
    decision_files = sorted(run_dir.glob("*_decision.json"))
    timeline_files = sorted(run_dir.glob("*_timeline.json"))

    hunt_status_counts = Counter()
    hunt_category_counts = Counter()
    triage_verdict_counts = Counter()
    ir_verdict_counts = Counter()
    decision_counts = Counter()
    severity_counts = Counter()

    suspicious_hunts = []
    coordinator_decisions = []

    crowdstrike_summary = {}
    crowdstrike_alerts = []

    crowdstrike_summary_file = run_dir / "crowdstrike_alerts_summary.json"
    crowdstrike_alerts_file = run_dir / "crowdstrike_alerts.json"

    if crowdstrike_summary_file.exists():
        crowdstrike_summary = load_json(crowdstrike_summary_file)

    if crowdstrike_alerts_file.exists():
        crowdstrike_alerts = load_json(crowdstrike_alerts_file)

    for path in summary_files:
        data = load_json(path)

        if path.name in {
            "crowdstrike_alerts_summary.json",
            "crowdstrike_triage_summary.json",
            "crowdstrike_ir_summary.json",
            "crowdstrike_decision_summary.json",
        }:
            continue

        if not isinstance(data, dict):
            continue

        hunt = data.get("hunt", path.name.replace("_summary.json", ""))
        status = data.get("status", "unknown")
        category = data.get("category", "unknown")

        hunt_status_counts[status] += 1
        hunt_category_counts[category] += 1

        if status == "suspicious":
            suspicious_hunts.append({
                "hunt": hunt,
                "category": category,
                "findings": data.get("findings", 0),
                "severity": data.get("severity", "unknown"),
            })

    for path in triage_files:
        data = load_json(path)

        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    triage_verdict_counts[item.get("verdict", "unknown")] += 1
        elif isinstance(data, dict):
            triage_verdict_counts[data.get("verdict", "unknown")] += 1

    for path in ir_files:
        data = load_json(path)

        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    ir_verdict_counts[item.get("ir_verdict", "unknown")] += 1
        elif isinstance(data, dict):
            ir_verdict_counts[data.get("ir_verdict", "unknown")] += 1

    for path in decision_files:
        data = load_json(path)

        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue

                decision = item.get("decision", "unknown")
                severity = item.get("severity", "unknown")

                decision_counts[decision] += 1
                severity_counts[severity] += 1

                coordinator_decisions.append({
                    "hunt": item.get("hunt"),
                    "decision": decision,
                    "severity": severity,
                    "rationale": item.get("rationale", []),
                    "source": item.get("source"),
                    "alert_id": item.get("alert_id"),
                })

        elif isinstance(data, dict):
            decision = data.get("decision", "unknown")
            severity = data.get("severity", "unknown")

            decision_counts[decision] += 1
            severity_counts[severity] += 1

            coordinator_decisions.append({
                "hunt": data.get("hunt"),
                "decision": decision,
                "severity": severity,
                "rationale": data.get("rationale", []),
                "source": data.get("source"),
                "alert_id": data.get("alert_id"),
            })

    crowdstrike_classification_counts = Counter()
    crowdstrike_severity_counts = Counter()

    for alert in crowdstrike_alerts:
        if not isinstance(alert, dict):
            continue
        classification = alert.get("lab_context", {}).get("classification", "unknown")
        severity_name = alert.get("severity_name", "Unknown")
        crowdstrike_classification_counts[classification] += 1
        crowdstrike_severity_counts[severity_name] += 1

    output = {
        "generated_at": datetime.now(UTC).isoformat(),
        "run_dir": str(run_dir),
        "file_counts": {
            "summaries": len(summary_files),
            "triage": len(triage_files),
            "ir": len(ir_files),
            "decisions": len(decision_files),
            "timelines": len(timeline_files),
            "crowdstrike_alerts": len(crowdstrike_alerts),
        },
        "hunt_status_counts": dict(hunt_status_counts),
        "hunt_category_counts": dict(hunt_category_counts),
        "triage_verdict_counts": dict(triage_verdict_counts),
        "ir_verdict_counts": dict(ir_verdict_counts),
        "decision_counts": dict(decision_counts),
        "severity_counts": dict(severity_counts),
        "crowdstrike": {
            "summary": crowdstrike_summary,
            "classification_counts": dict(crowdstrike_classification_counts),
            "severity_counts": dict(crowdstrike_severity_counts),
        },
        "suspicious_hunts": sorted(
            suspicious_hunts,
            key=lambda x: (x["severity"], x["findings"]),
            reverse=True
        ),
        "coordinator_decisions": coordinator_decisions,
    }

    out_file = run_dir / "vultron_run_summary.json"
    out_file.write_text(json.dumps(output, indent=2), encoding="utf-8")

    print("\n=== Run summary written ===")
    print(out_file)

    return output, out_file


def build_executive_markdown(run_dir: Path, summary: dict):
    decision_counts = summary.get("decision_counts", {})
    severity_counts = summary.get("severity_counts", {})
    suspicious_hunts = summary.get("suspicious_hunts", [])
    coordinator_decisions = summary.get("coordinator_decisions", [])
    crowdstrike = summary.get("crowdstrike", {})
    crowdstrike_summary = crowdstrike.get("summary", {})
    crowdstrike_classification_counts = crowdstrike.get("classification_counts", {})
    crowdstrike_severity_counts = crowdstrike.get("severity_counts", {})

    lines = []
    lines.append("# Vultron Executive Summary")
    lines.append("")
    lines.append(f"Generated: {summary.get('generated_at')}")
    lines.append(f"Run directory: `{summary.get('run_dir')}`")
    lines.append("")

    lines.append("## Overview")
    lines.append("")
    lines.append(f"- Hunt summaries: {summary.get('file_counts', {}).get('summaries', 0)}")
    lines.append(f"- Triage files: {summary.get('file_counts', {}).get('triage', 0)}")
    lines.append(f"- IR files: {summary.get('file_counts', {}).get('ir', 0)}")
    lines.append(f"- Timeline files: {summary.get('file_counts', {}).get('timelines', 0)}")
    lines.append(f"- Coordinator decisions: {summary.get('file_counts', {}).get('decisions', 0)}")
    lines.append(f"- CrowdStrike alerts ingested: {summary.get('file_counts', {}).get('crowdstrike_alerts', 0)}")
    lines.append("")

    if crowdstrike_summary:
        lines.append("## CrowdStrike Intake")
        lines.append("")
        lines.append(f"- Alert IDs found: {crowdstrike_summary.get('alert_ids_found', 0)}")
        lines.append(f"- Raw alert objects: {crowdstrike_summary.get('raw_alert_objects', 0)}")
        lines.append(f"- Alerts after filtering: {crowdstrike_summary.get('alerts_after_filtering', 0)}")
        lines.append(f"- New alerts after dedupe: {crowdstrike_summary.get('new_alerts_after_dedupe', 0)}")
        lines.append("")
        lines.append("### CrowdStrike Classifications")
        lines.append("")
        if crowdstrike_classification_counts:
            for k, v in crowdstrike_classification_counts.items():
                lines.append(f"- {k}: {v}")
        else:
            lines.append("- No CrowdStrike classifications available")
        lines.append("")
        lines.append("### CrowdStrike Severity Distribution")
        lines.append("")
        if crowdstrike_severity_counts:
            for k, v in crowdstrike_severity_counts.items():
                lines.append(f"- {k}: {v}")
        else:
            lines.append("- No CrowdStrike severity values available")
        lines.append("")

    lines.append("## Hunt Status")
    lines.append("")
    for k, v in summary.get("hunt_status_counts", {}).items():
        lines.append(f"- {k}: {v}")
    lines.append("")

    lines.append("## Decisions")
    lines.append("")
    if decision_counts:
        for k, v in decision_counts.items():
            lines.append(f"- {k}: {v}")
    else:
        lines.append("- No coordinator decisions generated")
    lines.append("")

    lines.append("## Severity Distribution")
    lines.append("")
    if severity_counts:
        for k, v in severity_counts.items():
            lines.append(f"- {k}: {v}")
    else:
        lines.append("- No severity values present")
    lines.append("")

    lines.append("## Top Suspicious Hunts")
    lines.append("")
    if suspicious_hunts:
        for item in suspicious_hunts[:10]:
            lines.append(
                f"- `{item['hunt']}` "
                f"(category: {item['category']}, findings: {item['findings']}, severity: {item['severity']})"
            )
    else:
        lines.append("- No suspicious hunts recorded")
    lines.append("")

    lines.append("## Coordinator Highlights")
    lines.append("")
    if coordinator_decisions:
        for item in coordinator_decisions[:10]:
            label = item.get("hunt") or "unknown"
            if item.get("source") == "crowdstrike" and item.get("alert_id"):
                label = f"{label} ({item.get('alert_id')})"

            lines.append(
                f"- `{label}` → **{item.get('decision')}** "
                f"(severity: {item.get('severity')})"
            )
            rationale = item.get("rationale", [])
            for r in rationale[:3]:
                lines.append(f"  - {r}")
    else:
        lines.append("- No coordinator decisions available")
    lines.append("")

    lines.append("## Bottom Line")
    lines.append("")
    if crowdstrike_summary.get("new_alerts_after_dedupe", 0) > 0:
        lines.append(
            "- CrowdStrike alerts were successfully ingested into this Vultron run and are available for downstream triage, timeline reconstruction, and coordination."
        )
    elif "blocked_inbound_hostile_traffic" in decision_counts:
        lines.append(
            "- Threat intelligence overlap was observed, but activity was classified as blocked inbound hostile traffic rather than confirmed compromise."
        )
    elif "potential_compromised_host" in decision_counts:
        lines.append(
            "- At least one hunt indicates a potential compromised host and should be escalated immediately."
        )
    elif decision_counts:
        lines.append(
            "- Vultron identified findings that require analyst review; see coordinator highlights above for prioritization."
        )
    else:
        lines.append(
            "- No high-priority decisions were generated during this run."
        )
    lines.append("")

    out_file = run_dir / "vultron_executive_summary.md"
    out_file.write_text("\n".join(lines), encoding="utf-8")

    print("\n=== Executive summary written ===")
    print(out_file)

    return out_file


def main():
    parser = argparse.ArgumentParser(description="Run the Vultron SOC pipeline")
    parser.add_argument(
        "--category",
        action="append",
        help="Run only specified hunt category. Repeat for multiple categories.",
    )
    parser.add_argument(
        "--skip-intel",
        action="store_true",
        help="Skip intel ingestion/enrichment stages and only run hunting/analysis.",
    )
    parser.add_argument(
        "--skip-crowdstrike",
        action="store_true",
        help="Skip CrowdStrike alert ingestion stage.",
    )
    parser.add_argument(
        "--skip-timeline",
        action="store_true",
        help="Skip timeline reconstruction stage.",
    )
    args = parser.parse_args()

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_dir = RUNS_DIR / f"vultron_run_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["VULTRON_RUN_DIR"] = str(run_dir)

    print(f"Run directory: {run_dir}")

    steps = []

    if not args.skip_intel:
        steps.extend([
            ("Intel research", ["python", str(AGENTS / "intel_research_agent.py")]),
            ("RSS IOC extraction", ["python", str(AGENTS / "ioc_extractor_agent.py")]),
            ("Structured IOC ingestion", ["python", str(AGENTS / "structured_ioc_ingestor_agent.py")]),
            ("IOC reputation scoring", ["python", str(AGENTS / "ioc_reputation_agent.py")]),
            ("Operational IOC filtering", ["python", str(AGENTS / "ioc_operational_filter_agent.py")]),
        ])

    if not args.skip_crowdstrike:
        steps.append((
            "CrowdStrike alert ingestion",
            ["python", str(CONNECTORS / "crowdstrike_detections.py")],
        ))

    if args.category:
        for category in args.category:
            steps.append((
                f"Threat hunting ({category})",
                ["python", str(AGENTS / "threat_hunter_agent.py"), "--category", category],
            ))
    else:
        steps.append((
            "Threat hunting (all categories)",
            ["python", str(AGENTS / "threat_hunter_agent.py"), "--run-all"],
        ))

    steps.extend([
        ("Triage", ["python", str(AGENTS / "triage_agent.py")]),
        ("Incident response analysis", ["python", str(AGENTS / "ir_agent.py")]),
    ])

    if not args.skip_timeline:
        steps.append((
            "Timeline builder",
            ["python", str(AGENTS / "timeline_builder.py")],
        ))

    steps.extend([
        ("Coordinator decisions", ["python", str(AGENTS / "coordinator_agent.py")]),
        ("Case engine", ["python", str(BASE / "cases" / "case_engine.py")]),
    ])

    for name, cmd in steps:
        run_step(name, cmd, env)

    summary, summary_file = build_run_summary(run_dir)
    markdown_file = build_executive_markdown(run_dir, summary)

    print("\n=== Vultron run complete ===")
    print(f"Artifacts saved to: {run_dir}")
    print(f"Run summary JSON: {summary_file}")
    print(f"Executive summary MD: {markdown_file}")


if __name__ == "__main__":
    main()
