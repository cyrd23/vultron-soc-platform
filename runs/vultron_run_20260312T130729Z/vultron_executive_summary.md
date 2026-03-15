# Vultron Executive Summary

Generated: 2026-03-12T13:07:39.324807+00:00
Run directory: `/home/reg/soc/runs/vultron_run_20260312T130729Z`

## Overview

- Hunt summaries: 5
- Triage files: 5
- IR files: 1
- Coordinator decisions: 5

## Hunt Status

- clean: 4
- suspicious: 1

## Decisions

- benign: 4
- blocked_inbound_hostile_traffic: 1

## Severity Distribution

- low: 5

## Top Suspicious Hunts

- `malicious_ip_matches` (category: intel_ioc, findings: 200, severity: unknown)

## Coordinator Highlights

- `internal_host_to_ioc` → **benign** (severity: low)
  - Triage found no suspicious activity
- `malicious_domain_matches` → **benign** (severity: low)
  - Triage found no suspicious activity
- `malicious_domain_matches_umbrella` → **benign** (severity: low)
  - Triage found no suspicious activity
- `malicious_ip_matches` → **blocked_inbound_hostile_traffic** (severity: low)
  - Threat-intel IOC IPs were observed only in denied network events
  - Fortinet blocked the activity at the edge
  - No endpoint evidence of internal hosts contacting IOC infrastructure
- `malicious_ip_port_matches` → **benign** (severity: low)
  - Triage found no suspicious activity

## Bottom Line

- Threat intelligence overlap was observed, but activity was classified as blocked inbound hostile traffic rather than confirmed compromise.
