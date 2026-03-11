#!/usr/bin/env python3
import json
from pathlib import Path

BASE = Path.home() / "soc"
REPORTS_DIR = BASE / "reports"
DETECTIONS_DIR = BASE / "detections"
SIGMA_DIR = DETECTIONS_DIR / "sigma"
ELASTIC_DIR = DETECTIONS_DIR / "elastic"


def load_json(file_path):
    with open(file_path, "r") as f:
        return json.load(f)


def build_password_spray_sigma():
    return """title: Password Spray Activity
id: password-spray-001
status: experimental
description: Detects multiple failed sign-ins from a single IP against multiple users.
logsource:
  product: azure
  service: signinlogs
detection:
  selection:
    event.outcome: failure
  condition: selection
falsepositives:
  - Enterprise NAT or proxy infrastructure
  - Misconfigured services generating repeated failures
level: medium
"""


def build_password_spray_elastic():
    return """FROM logs-azure.signinlogs*
| WHERE event.outcome == "failure"
| STATS failures = COUNT(), users = COUNT_DISTINCT(user.name) BY source.ip
| WHERE failures >= 10 AND users >= 5
| SORT failures DESC
"""


def build_oauth_sigma():
    return """title: Suspicious OAuth Consent or Permission Grant Activity
id: oauth-consent-abuse-001
status: experimental
description: Detects OAuth consent, delegated permission grants, and application-related Azure audit activity.
logsource:
  product: azure
  service: auditlogs
detection:
  selection:
    event.action|contains:
      - Consent
      - grant
      - application
  condition: selection
falsepositives:
  - Expected enterprise application onboarding
  - Administrator-approved app integrations
level: high
"""


def build_oauth_elastic():
    return """FROM logs-azure.auditlogs*
| WHERE event.action IS NOT NULL OR azure.auditlogs.properties.activity_display_name IS NOT NULL
| WHERE event.action LIKE "*consent*"
    OR event.action LIKE "*grant*"
    OR event.action LIKE "*application*"
    OR azure.auditlogs.properties.activity_display_name LIKE "*consent*"
    OR azure.auditlogs.properties.activity_display_name LIKE "*grant*"
    OR azure.auditlogs.properties.activity_display_name LIKE "*application*"
| KEEP @timestamp,
       event.action,
       event.outcome,
       source.ip,
       client.ip,
       azure.auditlogs.properties.activity_display_name,
       azure.auditlogs.properties.initiated_by.user.userPrincipalName,
       azure.auditlogs.properties.initiated_by.user.displayName,
       azure.auditlogs.properties.initiated_by.app.displayName,
       azure.auditlogs.properties.initiated_by.app.servicePrincipalName,
       azure.auditlogs.operation_name
| SORT @timestamp DESC
| LIMIT 100
"""


def generate_detection(hunt):
    if hunt == "password_spray":
        return build_password_spray_sigma(), build_password_spray_elastic()
    if hunt == "oauth_consent_abuse":
        return build_oauth_sigma(), build_oauth_elastic()
    return None, None


def main():
    SIGMA_DIR.mkdir(parents=True, exist_ok=True)
    ELASTIC_DIR.mkdir(parents=True, exist_ok=True)

    coordinator_files = sorted(REPORTS_DIR.glob("*_coordinator.json"))

    if not coordinator_files:
        print("No coordinator files found.")
        return

    for coordinator_path in coordinator_files:
        coordinator = load_json(coordinator_path)
        hunt = coordinator.get("hunt")

        if not coordinator.get("detection_recommendation", False):
            continue

        sigma_content, elastic_content = generate_detection(hunt)

        if not sigma_content or not elastic_content:
            print(f"No detection template implemented for hunt: {hunt}")
            continue

        sigma_file = SIGMA_DIR / f"{hunt}.yml"
        elastic_file = ELASTIC_DIR / f"{hunt}.esql"

        sigma_file.write_text(sigma_content)
        elastic_file.write_text(elastic_content)

        print(f"Detection candidates created for {hunt}")
        print(f"  Sigma:   {sigma_file}")
        print(f"  Elastic: {elastic_file}")


if __name__ == "__main__":
    main()
