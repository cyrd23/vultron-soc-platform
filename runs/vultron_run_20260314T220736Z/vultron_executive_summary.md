# Vultron Executive Summary

Generated: 2026-03-14T22:08:25.854912+00:00
Run directory: `/home/reg/soc/runs/vultron_run_20260314T220736Z`

## Overview

- Hunt summaries: 41
- Triage files: 41
- IR files: 31
- Coordinator decisions: 41

## Hunt Status

- suspicious: 31
- clean: 10

## Decisions

- needs_review: 28
- benign: 10
- blocked_inbound_hostile_traffic: 1
- needs_oauth_review: 1
- escalate_possible_account_compromise: 1

## Severity Distribution

- medium: 29
- low: 11
- high: 1

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
- `dga_like_behavior` → **needs_review** (severity: medium)
  - No specific coordinator rule matched; manual analyst review recommended
  - Unhandled hunt type; manual review recommended
  - No IR workflow implemented yet for this hunt
- `dns_c2_beaconing` → **needs_review** (severity: medium)
  - No specific coordinator rule matched; manual analyst review recommended
  - Unhandled hunt type; manual review recommended
  - No IR workflow implemented yet for this hunt
- `dns_tunneling` → **needs_review** (severity: medium)
  - No specific coordinator rule matched; manual analyst review recommended
  - Unhandled hunt type; manual review recommended
  - No IR workflow implemented yet for this hunt
- `encoded_command_execution` → **needs_review** (severity: medium)
  - No specific coordinator rule matched; manual analyst review recommended
  - Unhandled hunt type; manual review recommended
  - No IR workflow implemented yet for this hunt
- `encoded_powershell` → **needs_review** (severity: medium)
  - No specific coordinator rule matched; manual analyst review recommended
  - Unhandled hunt type; manual review recommended
  - No IR workflow implemented yet for this hunt
- `external_scanning_to_vulnerable_asset` → **needs_review** (severity: medium)
  - No specific coordinator rule matched; manual analyst review recommended
  - Unhandled hunt type; manual review recommended
  - No IR workflow implemented yet for this hunt
- `impossible_travel` → **benign** (severity: low)
  - Triage found no suspicious activity
- `internal_host_to_ioc` → **benign** (severity: low)
  - Triage found no suspicious activity

## Bottom Line

- Threat intelligence overlap was observed, but activity was classified as blocked inbound hostile traffic rather than confirmed compromise.
