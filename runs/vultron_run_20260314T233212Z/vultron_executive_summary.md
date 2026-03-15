# Vultron Executive Summary

Generated: 2026-03-14T23:33:02.155725+00:00
Run directory: `/home/reg/soc/runs/vultron_run_20260314T233212Z`

## Overview

- Hunt summaries: 46
- Triage files: 42
- IR files: 32
- Coordinator decisions: 42
- CrowdStrike alerts ingested: 93

## CrowdStrike Intake

- Alert IDs found: 100
- Raw alert objects: 100
- Alerts after filtering: 93
- New alerts after dedupe: 93

### CrowdStrike Classifications

- expected_lab_activity: 85
- needs_triage: 8

### CrowdStrike Severity Distribution

- Informational: 36
- Low: 8
- High: 35
- Medium: 12
- Critical: 2

## Hunt Status

- suspicious: 31
- unknown: 1
- clean: 10

## Decisions

- needs_review: 28
- suppress_expected_lab_activity: 85
- escalate_crowdstrike_high_severity_alert: 5
- investigate_crowdstrike_medium_alert: 3
- benign: 10
- blocked_inbound_hostile_traffic: 1
- needs_oauth_review: 1
- escalate_possible_account_compromise: 1

## Severity Distribution

- medium: 32
- low: 96
- high: 6

## Top Suspicious Hunts

- `malicious_ip_matches` (category: intel_ioc, findings: 200, severity: unknown)
- `dga_like_behavior` (category: dns, findings: 100, severity: medium)
- `newly_observed_domains` (category: dns, findings: 100, severity: medium)
- `rare_domain_access` (category: dns, findings: 100, severity: medium)
- `password_spray` (category: identity, findings: 11, severity: medium)
- `abnormal_admin_behavior` (category: lateral_movement, findings: 100, severity: high)
- `dns_c2_beaconing` (category: construction_threats, findings: 100, severity: high)
- `dns_tunneling` (category: dns, findings: 100, severity: high)
- `external_scanning_to_vulnerable_asset` (category: exposure, findings: 100, severity: high)
- `internal_rdp` (category: lateral_movement, findings: 100, severity: high)

## Coordinator Highlights

- `abnormal_admin_behavior` → **needs_review** (severity: medium)
  - No specific coordinator rule matched; manual analyst review recommended
  - Unhandled hunt type; manual review recommended
  - No IR workflow implemented yet for this hunt
- `credential_dumping` → **needs_review** (severity: medium)
  - No specific coordinator rule matched; manual analyst review recommended
  - Unhandled hunt type; manual review recommended
  - No IR workflow implemented yet for this hunt
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:8127156727-10417-4478736)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:8127156727-10417-4278032)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:4515910051-4748-3986448)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:9a83a8075e294430b6a73302b5b4a0fd:510256351096-10311-5536272)` → **escalate_crowdstrike_high_severity_alert** (severity: high)
  - High severity CrowdStrike alert has supporting host telemetry in Elastic
  - Reviewed CrowdStrike alert: BypassUACPrivEsc
  - High severity CrowdStrike alert with supporting host telemetry found in Elastic
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:ca8f0e489d374816b962fb078131fb4a:127314022248-337-6270992)` → **investigate_crowdstrike_medium_alert** (severity: medium)
  - Medium severity CrowdStrike alert has supporting telemetry and requires investigation
  - Reviewed CrowdStrike alert: CommandLineStomping
  - Medium severity CrowdStrike alert with supporting host telemetry found in Elastic
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:11865244389-10159-8321040)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:10662981550-10417-7802128)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:10372706814-10417-6661392)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators

## Bottom Line

- CrowdStrike alerts were successfully ingested into this Vultron run and are available for downstream triage and coordination.
