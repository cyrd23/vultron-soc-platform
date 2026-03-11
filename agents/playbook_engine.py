#!/usr/bin/env python3
import json
from pathlib import Path
import os

import yaml

BASE = Path.home() / "soc"
#REPORTS_DIR = BASE / "reports"
REPORTS_DIR = Path(os.environ.get("VULTRON_RUN_DIR", BASE / "reports"))
PLAYBOOKS_DIR = BASE / "playbooks"


def load_json(file_path):
    with open(file_path, "r") as f:
        return json.load(f)


def load_yaml(file_path):
    with open(file_path, "r") as f:
        return yaml.safe_load(f)


def build_execution_plan(summary, coordinator, playbook):
    return {
        "hunt": summary.get("hunt"),
        "playbook": playbook.get("name"),
        "description": playbook.get("description"),
        "approval_required": playbook.get("approval_required", True),
        "status": "pending_approval",
        "severity": coordinator.get("severity"),
        "coordinator_verdict": coordinator.get("coordinator_verdict"),
        "recommended_actions": coordinator.get("recommended_actions", []),
        "entities": summary.get("entities", {}),
        "playbook_steps": playbook.get("actions", []),
    }


def main():
    coordinator_files = sorted(REPORTS_DIR.glob("*_coordinator.json"))

    if not coordinator_files:
        print("No coordinator files found.")
        return

    for coordinator_path in coordinator_files:
        coordinator = load_json(coordinator_path)
        hunt = coordinator.get("hunt")
        playbook_name = coordinator.get("playbook_recommendation")

        if not playbook_name:
            continue

        summary_path = REPORTS_DIR / f"{hunt}_summary.json"
        if not summary_path.exists():
            print(f"Skipping {hunt}: summary file not found")
            continue

        summary = load_json(summary_path)

        playbook_path = PLAYBOOKS_DIR / f"{playbook_name}.yaml"
        if not playbook_path.exists():
            print(f"Playbook not found: {playbook_path}")
            continue

        playbook = load_yaml(playbook_path)
        execution_plan = build_execution_plan(summary, coordinator, playbook)

        out_file = REPORTS_DIR / f"{hunt}_playbook_execution.json"
        out_file.write_text(json.dumps(execution_plan, indent=2))
        print(f"Playbook execution saved: {out_file}")


if __name__ == "__main__":
    main()
