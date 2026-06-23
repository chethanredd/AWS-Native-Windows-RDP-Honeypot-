# AWS-Native Windows RDP Honeypot SOC Lab

A self-built honeypot and detection pipeline on AWS that exposes a Windows Server RDP endpoint to the public internet, captures real brute-force login attempts via CloudWatch, enriches attacker IPs with geolocation data, and visualizes the results on a live attack map dashboard.

## Overview

This project deploys a deliberately vulnerable Windows Server instance with RDP open to `0.0.0.0/0`, then builds a full detection and analysis pipeline around the resulting attack traffic — entirely using AWS-native services (no third-party SIEM).

**Goal:** observe, capture, and analyze real-world opportunistic internet scanning and credential brute-forcing against an exposed RDP service, and present the findings the way a SOC analyst would.

## Architecture

```
Internet
   │
   ▼
Security Group (RDP 3389 open to 0.0.0.0/0)
   │
   ▼
EC2 — Windows Server 2022
   │  (Windows Security Event Log, audited for Logon Success/Failure)
   ▼
CloudWatch Agent (IAM role-based auth, no embedded credentials)
   │
   ▼
CloudWatch Logs  →  Log group: /honeypot/security-events
   │
   ▼
CloudWatch Logs Insights
   │  (extracts EventID 4625 — failed logon — parses SourceIP, TargetUserName)
   ▼
Local Flask backend (boto3 + GeoIP enrichment)
   │
   ▼
Custom Leaflet.js Attack Dashboard (live map, leaderboard, username frequency)
```

## AWS Services Used

| Service | Purpose |
|---|---|
| EC2 (Windows Server 2022) | The honeypot itself |
| Security Groups | Deliberately permissive inbound rule (RDP from anywhere) |
| IAM | Scoped role for the EC2 instance to ship logs (no static credentials on the box) |
| CloudWatch Logs | Centralized collection of Windows Security Event Log |
| CloudWatch Logs Insights | Query engine for extracting and aggregating failed-logon events |
| S3 | Storage for periodic log exports |

GuardDuty and QuickSight were evaluated but were not available on this AWS account's plan tier, so detection logic was built entirely on CloudWatch Logs Insights, and visualization was built as a custom dashboard instead.

## Detection Logic

The core signal is **Windows Event ID 4625** (failed logon), captured via the Windows Security Event Log and shipped through the CloudWatch agent in XML format (preserves structured fields like `IpAddress` and `TargetUserName` that JSON rendering would lose).

Three Logs Insights queries power the dashboard:

**Attacker leaderboard** (IP + attempt count):
```
fields @timestamp, @message
| filter @message like /EventID>4625/
| parse @message /<Data Name='IpAddress'>(?<SourceIP>[\d\.]+)<\/Data>/
| filter SourceIP not like /-/ and SourceIP not like /^$/
| stats count(*) as AttackCount by SourceIP
| sort AttackCount desc
```

**Username frequency** (which accounts attackers tried):
```
fields @timestamp, @message
| filter @message like /EventID>4625/
| parse @message /<Data Name='TargetUserName'>(?<AccountName>[^<]+)<\/Data>/
| filter AccountName not like /-/ and AccountName not like /^\$/
| stats count(*) as Attempts by AccountName
| sort Attempts desc
```

**Combined detail** (IP + account + count) — used during validation, same pattern as above with both `parse` clauses chained.

## Dashboard

A custom dark-mode SOC dashboard (HTML/JS, Leaflet.js + CARTO dark tiles) displays:

- A live world map with attacker locations sized by attack volume
- An attacker leaderboard (IP, country code, attempt count)
- A username-frequency panel
- Summary stats: total failed logons, unique attacker IPs, countries observed, top username attempted

Data is pulled live from a small local Flask backend (`server.py`), which uses `boto3` and the analyst's own AWS CLI credentials to run the Insights queries directly and enrich results with free IP geolocation data — no credentials are ever exposed to the browser, and no CSV export/upload step is required during normal use.

## Findings

Within the observation window, the honeypot logged **37 failed RDP logon attempts from 4 unique IP addresses across 3 countries** (India, Russia, United States — the India entry includes validated test traffic from the analyst's own connection used to confirm the pipeline end-to-end).

Usernames attempted included case variations of `Administrator` (`Administrator`, `ADMINISTRATOR`) alongside common generic accounts (`ADM`, `root`, `Admin`) — consistent with automated credential-stuffing/brute-force tooling rather than targeted human attempts.

## Build Notes / Troubleshooting Encountered

A few real issues came up during the build, worth documenting since they're realistic SOC/cloud-ops debugging scenarios:

1. **Region mismatch** — resources were inadvertently created in `eu-north-1` (Stockholm) while checking CloudWatch in a different region in the console, producing a false "no logs ingested" signal. Resolved by confirming the actual instance region via instance metadata (`/latest/meta-data/placement/region`) rather than assuming the console's selected region matched.
2. **CloudWatch agent silently stopped** — a malformed multi-line PowerShell paste caused the agent's restart command to fail silently, leaving it in a `stopped` state while still reporting healthy in passive checks. Diagnosed by checking `amazon-cloudwatch-agent-ctl.ps1 -a status` directly rather than trusting prior assumptions, and confirmed root cause via the agent's own log file.
3. **Account-tier service gating** — GuardDuty and QuickSight were both blocked on this AWS account's free/credits-based plan tier, requiring a pivot to CloudWatch Logs Insights for detection and a custom Leaflet.js dashboard for visualization instead of native AWS analytics tooling.

## Stack

- **Cloud:** AWS (EC2, CloudWatch Logs/Insights, IAM, S3)
- **Honeypot OS:** Windows Server 2022
- **Backend:** Python (Flask, boto3, requests)
- **Frontend:** HTML/CSS/JS, Leaflet.js, PapaParse
- **GeoIP enrichment:** ip-api.com (free tier)

## Disclaimer

This lab was deployed for a fixed, limited observation window on infrastructure explicitly provisioned for this purpose, with no production data or systems involved. The exposed RDP service ran a default, non-privileged configuration with no legitimate credentials accessible to attackers. The instance was torn down at the end of the observation period.
