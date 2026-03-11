# Vultron Architecture

## Overview

Vultron is a modular SOC automation platform built on top of Elastic SIEM. It is designed to automate threat hunting, enrichment, triage, investigation, response planning, and detection engineering while maintaining analyst oversight and investigation traceability.

The platform uses a multi-agent pipeline and stores investigation artifacts by Run ID so that each execution is auditable and reproducible.

---

## Core Design Principles

- Modular agents with clear responsibilities
- Deterministic detection and hunting logic first
- Human approval for response actions
- Run-based artifact preservation
- Detection engineering as a feedback loop
- Future-ready design for AI-assisted and agentic workflows

---

## High-Level Pipeline

```text
Elastic SIEM Telemetry
        ↓
Threat Hunt Agent
        ↓
Intel Enrichment Agent
        ↓
Triage Agent
        ↓
IR Investigation Agent
        ↓
Coordinator Agent
        ↓
Playbook Engine
        ↓
Detection Engineering Agent

Each stage reads structured artifacts from the previous stage and writes new artifacts into a run-specific report directory.

Telemetry Sources

Vultron currently uses telemetry from the following sources:

Azure Sign-in Logs

Azure Audit Logs

O365 Audit Logs

CrowdStrike FDR

Cisco Umbrella

Fortinet FortiGate

Zeek

Suricata

Tenable

These sources are queried through Elastic SIEM using ESQL and normalized dataset mappings.

Core Components
1. Threat Hunt Agent

The Threat Hunt Agent executes hunt packs stored in the threat hunt pack library.

Responsibilities:

discover hunt packs dynamically

load pack metadata

execute ESQL hunt queries

save raw and summary output

extract entities such as users, IPs, apps, hosts, and domains

Inputs:

packs/threat_hunt_pack_library/**/pack.yaml

packs/threat_hunt_pack_library/**/query.esql

Outputs:

*_raw.json

*_summary.json

Example use cases:

password spray

OAuth consent abuse

impossible travel

2. Intel Enrichment Agent

The Intel Agent reads hunt summaries and enriches entities.

Responsibilities:

read extracted entities

prepare enrichment output for IPs, users, apps, domains, and hosts

serve as the handoff point for future integrations with:

VirusTotal

OTX

IPInfo

URLVoid

Inputs:

*_summary.json

Outputs:

*_intel.json

3. Triage Agent

The Triage Agent performs initial classification of hunt findings.

Responsibilities:

evaluate findings count and entity context

classify hunt results as:

clean

benign

needs_review

suspicious

Inputs:

*_summary.json

*_intel.json

Outputs:

*_triage.json

4. IR Investigation Agent

The IR Agent performs deeper follow-on investigation on hunts that triage marks as worth pursuing.

Responsibilities:

check for evidence of follow-on activity

validate whether suspicious findings led to compromise or impact

Current workflows:

password spray → checks for successful sign-ins after spray activity

OAuth consent abuse → checks for downstream O365 activity

Inputs:

*_summary.json

*_triage.json

Outputs:

*_ir.json

5. Coordinator Agent

The Coordinator Agent is the decision engine for the platform.

Responsibilities:

combine summary, triage, and IR outputs

determine case severity

assign coordinator verdict

recommend next actions

recommend playbooks

recommend detection engineering follow-up

Inputs:

*_summary.json

*_triage.json

*_ir.json

Outputs:

*_coordinator.json

Example decisions:

close

monitor

review

escalate

6. Playbook Engine

The Playbook Engine turns coordinator decisions into structured response plans.

Responsibilities:

load playbook definitions

create execution plans

preserve analyst approval gating

Current playbook examples:

identity_compromise.yaml

password_spray_response.yaml

Inputs:

*_summary.json

*_coordinator.json

playbooks/*.yaml

Outputs:

*_playbook_execution.json

Important note:

playbooks currently generate response plans only

they do not automatically execute containment actions

7. Detection Engineering Agent

The Detection Engineering Agent turns repeated hunt findings into durable detections.

Responsibilities:

generate Sigma detection candidates

generate Elastic ESQL detection candidates

close the hunt-to-detection feedback loop

Inputs:

*_coordinator.json

Outputs:

detections/sigma/*.yml

detections/elastic/*.esql

8. Vultron Orchestrator

The master orchestrator runs the full pipeline from a single command.

Responsibilities:

generate Run ID

create run output directory

execute agents in sequence

support full, category-based, or pack-based execution

Example:

python agents/vultron_orchestrator.py

Optional usage:

python agents/vultron_orchestrator.py --category identity
python agents/vultron_orchestrator.py --pack password_spray
Investigation Artifact Model

Each pipeline run generates a Run ID, for example:

20260310T214501Z

Artifacts are stored in:

reports/<run_id>/

Example:

reports/20260310T214501Z/
├── password_spray_raw.json
├── password_spray_summary.json
├── password_spray_intel.json
├── password_spray_triage.json
├── password_spray_ir.json
├── password_spray_coordinator.json
├── password_spray_playbook_execution.json
├── oauth_consent_abuse_raw.json
├── oauth_consent_abuse_summary.json
├── oauth_consent_abuse_intel.json
├── oauth_consent_abuse_triage.json
├── oauth_consent_abuse_ir.json
├── oauth_consent_abuse_coordinator.json
└── oauth_consent_abuse_playbook_execution.json

This model supports:

auditability

incident reconstruction

historical comparison

case management integration

Threat Hunt Pack Model

Threat hunt packs are organized by category.

Example layout:

packs/threat_hunt_pack_library/
├── identity/
│   ├── password_spray/
│   │   ├── pack.yaml
│   │   ├── query.esql
│   │   ├── notes.md
│   │   └── detection_candidate.md
│   ├── impossible_travel/
│   └── oauth_consent_abuse/
├── dns/
├── endpoint/
├── exposure/
├── lateral_movement/
├── network/
└── compound/

Each pack contains:

metadata

query logic

hunt notes

detection follow-up notes

Directory Structure
~/soc
├── .venv/
├── agents/
│   ├── threat_hunter_agent.py
│   ├── intel_agent.py
│   ├── triage_agent.py
│   ├── ir_agent.py
│   ├── coordinator_agent.py
│   ├── playbook_engine.py
│   ├── detection_engineering_agent.py
│   └── vultron_orchestrator.py
├── configs/
│   ├── elastic.env
│   ├── datasets.yaml
│   └── settings.yaml
├── detections/
│   ├── elastic/
│   └── sigma/
├── packs/
│   └── threat_hunt_pack_library/
├── playbooks/
├── reports/
├── schemas/
│   ├── field_inventory.json
│   └── field_requirements.yaml
├── scripts/
├── tests/
├── docs/
│   ├── ARCHITECTURE.md
│   └── ROADMAP.md
├── README.md
└── run_soc.sh
Dataset Configuration

Dataset mappings are maintained in:

configs/datasets.yaml

Example mappings:

fortigate: logs-fortinet_fortigate.log*
umbrella: logs-cisco_umbrella.log*
azure_signin: logs-azure.signinlogs*
azure_audit: logs-azure.auditlogs*
o365: logs-o365.audit*
crowdstrike_fdr: logs-crowdstrike.fdr*
tenable_vulnerability: logs-tenable_io.vulnerability*
zeek_connection: logs-zeek.connection*
zeek_dns: logs-zeek.dns*
zeek_http: logs-zeek.http*
zeek_ssl: logs-zeek.ssl*

This prevents hardcoded dataset assumptions in hunt logic.

Security and Governance Controls
Human Approval

Response actions are not automatically executed. The platform generates recommended response plans that require analyst approval.

Run Traceability

Every run produces preserved artifacts under a unique Run ID.

Modular Isolation

Each agent has a bounded responsibility and writes structured outputs for downstream consumption.

Deterministic Logic

Primary hunt and detection logic is deterministic and explainable.

Secret Separation

Secrets are stored outside version control and excluded through .gitignore.

Current State

The current platform supports:

working hunt execution

entity extraction

intelligence enrichment handoff

automated triage

initial IR investigation

coordinator decision logic

playbook planning

detection candidate generation

orchestrated pipeline execution

run-based artifact storage

Future Architecture Expansion
Vultron Operations Portal

A web front end for:

pipeline execution

run review

investigation workspace

AI analyst interface

playbook approvals

Expanded Hunt Library

Additional hunt packs across:

DNS

endpoint

lateral movement

exposure

cloud abuse

Attack Path Correlation

Multi-stage chain detection such as:

password spray → successful login → OAuth grant → SharePoint activity

AI Investigation Analyst

Natural-language question answering and investigation summaries.

Agentic Workflow Layer

Dynamic hunt selection, branching logic, and investigation hypothesis generation.

Enterprise Integrations

ServiceNow, Slack, Teams, SOAR, and threat intelligence platform integrations.

Strategic End State

Vultron evolves into a cyber fusion platform capable of:

automated hunting

structured investigation

analyst-guided response

continuous detection engineering

AI-assisted investigation

full audit traceability
