# Vultron Executive Summary

Generated: 2026-03-14T23:45:37.373720+00:00
Run directory: `/home/reg/soc/runs/vultron_run_20260314T234446Z`

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

- Medium: 12
- Informational: 36
- High: 35
- Low: 8
- Critical: 2

## Hunt Status

- suspicious: 31
- unknown: 1
- clean: 10

## Decisions

- needs_review: 28
- suppress_expected_lab_activity: 85
- investigate_crowdstrike_medium_alert: 3
- escalate_crowdstrike_high_severity_alert: 5
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
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:4515910051-10127-6969104)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:8846444048-10417-4660496)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:ca8f0e489d374816b962fb078131fb4a:127314022248-337-6270992)` → **investigate_crowdstrike_medium_alert** (severity: medium)
  - Medium severity CrowdStrike alert has supporting telemetry and requires investigation
  - Reviewed CrowdStrike alert: CommandLineStomping
  - Medium severity CrowdStrike alert with supporting host telemetry found in Elastic
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:11896024689-10417-8384784)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:11866272953-10127-8325392)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:10662981550-10417-8298256)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:9522098887-5738-6963984)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:9522098887-5733-6910480)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators

## Bottom Line

- CrowdStrike alerts were successfully ingested into this Vultron run and are available for downstream triage and coordination.
