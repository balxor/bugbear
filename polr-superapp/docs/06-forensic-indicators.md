# Forensic Indicators

Author: Kenshin Himura - DTrust

## Overview

This repository includes defensive artifacts for identification, review, and telemetry-focused detection engineering.

## Included artifacts

| Artifact | Path |
|---|---|
| IOC JSON | `artifacts/forensics/IOCs.json` |
| STIX 2.1 bundle | `artifacts/forensics/STIX_BUNDLE.json` |
| Sigma rules | `artifacts/forensics/SIGMA_RULES.yml` |
| YARA rules | `artifacts/forensics/YARA_RULES.yar` |

## Main indicators

| Indicator type | Notes |
|---|---|
| Package name | `com.uptodown` |
| APK SHA256 | `863f05e8c42a2fbf870388bba81383c05469a387f1e6e92707198fe89cd38c5e` |
| Tracker host | `t.uptodown.app` |
| Upload host | `u.uptodown.app` |
| Main API host | `www.uptodown.app` |
| Download host | `dw.uptodown.com` |
| Tracker endpoint | `/eapi/v2/tracker/device` |
| App inventory endpoint | `/eapi/androidtracker/device-apps-installed` |
| Usage endpoint | `/eapi/user-data/native-app-usage` |

## Detection engineering notes

- Use host, endpoint, and package indicators as review pivots, not as standalone maliciousness indicators.
- Expect false positives where the application is legitimately installed and used.
- Treat the included Sigma and YARA rules as starting points for lab validation.
- Adjust severity and allowlists to match the local environment.
