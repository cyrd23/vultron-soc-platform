#!/usr/bin/env python3
import argparse
import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path

BASE = Path.home() / "soc"
AGENTS_DIR = BASE / "agents"
REPORTS_DIR = BASE / "reports"

PIPELINE = [
    ("Intel Agent", AGENTS_DIR / "intel_agent.py"),
    ("Triage Agent", AGENTS_DIR / "triage_agent.py"),
    ("IR Agent", AGENTS_DIR / "ir_agent.py"),
    ("Coordinator Agent", AGENTS_DIR / "coordinator_agent.py"),
    ("Playbook Engine", AGENTS_DIR / "playbook_engine.py"),
    ("Detection Engineering Agent", AGENTS_DIR / "detection_engineering_agent.py"),
]


def run_step(name, script_path, env, extra_args=None):

    if not script_path.exists():
        raise FileNotFoundError(f"{name} not found: {script_path}")

    cmd = [sys.executable, str(script_path)]

    if extra_args:
        cmd.extend(extra_args)

    print(f"\n=== Running {name} ===")
    print("Command:", " ".join(cmd))

    result = subprocess.run(cmd, env=env)

    if result.returncode != 0:
        raise RuntimeError(f"{name} failed with exit code {result.returncode}")


def main():

    parser = argparse.ArgumentParser(description="Run the Vultron SOC pipeline")

    parser.add_argument("--category")
    parser.add_argument("--pack")

    parser.add_argument("--skip-detection", action="store_true")
    parser.add_argument("--skip-playbooks", action="store_true")

    args = parser.parse_args()

    try:

        # Generate Run ID
        run_id = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

        run_dir = REPORTS_DIR / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        print("\n===================================")
        print(" Vultron Run ID:", run_id)
        print(" Output Dir:", run_dir)
        print("===================================\n")

        env = os.environ.copy()
        env["VULTRON_RUN_DIR"] = str(run_dir)

        # Step 1 — Hunts

        hunt_args = []

        if args.pack:
            hunt_args = ["--pack", args.pack]

        elif args.category:
            hunt_args = ["--category", args.category]

        else:
            hunt_args = ["--run-all"]

        run_step(
            "Threat Hunter",
            AGENTS_DIR / "threat_hunter_agent.py",
            env,
            hunt_args,
        )

        # Remaining agents

        run_step("Intel Agent", AGENTS_DIR / "intel_agent.py", env)
        run_step("Triage Agent", AGENTS_DIR / "triage_agent.py", env)
        run_step("IR Agent", AGENTS_DIR / "ir_agent.py", env)
        run_step("Coordinator Agent", AGENTS_DIR / "coordinator_agent.py", env)

        if not args.skip_playbooks:
            run_step("Playbook Engine", AGENTS_DIR / "playbook_engine.py", env)

        if not args.skip_detection:
            run_step(
                "Detection Engineering Agent",
                AGENTS_DIR / "detection_engineering_agent.py",
                env,
            )

        print("\nVultron pipeline completed successfully.")

    except Exception as e:

        print("\nPipeline failed:", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
