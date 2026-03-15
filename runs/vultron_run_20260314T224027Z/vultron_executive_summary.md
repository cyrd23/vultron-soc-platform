# Vultron Executive Summary

Generated: 2026-03-14T22:41:20.096236+00:00
Run directory: `/home/reg/soc/runs/vultron_run_20260314T224027Z`

## Overview

- Hunt summaries: 45
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

- needs_triage: 8
- expected_lab_activity: 85

### CrowdStrike Severity Distribution

- High: 35
- Informational: 36
- Medium: 12
- Low: 8
- Critical: 2

## Hunt Status

- suspicious: 31
- clean: 10

## Decisions

- needs_review: 28
- escalate_crowdstrike_high_severity_alert: 5
- suppress_expected_lab_activity: 85
- investigate_crowdstrike_medium_alert: 3
- benign: 10
- blocked_inbound_hostile_traffic: 1
- needs_oauth_review: 1
- escalate_possible_account_compromise: 1

## Severity Distribution

- medium: 32
- high: 6
- low: 96

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
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:454c248f82bd4974a8576eb033799770:1954357939752-56-4023824)` → **escalate_crowdstrike_high_severity_alert** (severity: high)
  - High severity CrowdStrike alert has supporting host telemetry in Elastic
  - Reviewed CrowdStrike alert: HashDumpSAMUntrusted
  - High severity CrowdStrike alert with supporting host telemetry found in Elastic
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:10662981550-10417-8256784)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:9522098887-5733-6910480)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:9522098887-10417-6841360)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:4515910051-5733-3985936)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:11959720516-10417-8721936)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:9899057346-10417-6141968)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators
- `crowdstrike_alert (de6ca60e4fc74a3ea437a95e2b73c484:ind:f960a98702f34ecc8fa1cea7108981b9:9684356190-5738-5987600)` → **suppress_expected_lab_activity** (severity: low)
  - CrowdStrike alert was classified as expected lab/test activity
  - Connector classified this alert as expected lab/test activity
  - Matched Atomic Red Team / test activity indicators

## Bottom Line

- CrowdStrike alerts were successfully ingested into this Vultron run and are available for downstream triage and coordination.
