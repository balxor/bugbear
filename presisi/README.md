# Uptodown App Store v7.32 Research Notes

Author: Kenshin Himura - DTrust

This repository contains reverse engineering notes for Uptodown App Store v7.32. The material focuses on static analysis, application components, network behavior, local storage, telemetry paths, and forensic indicators.

The repository is written for security researchers, mobile analysts, SOC analysts, and privacy engineers. The scope is documentation and defensive analysis. Runtime bypass scripts, memory dumping scripts, interception tooling, and other operational lab material are not included in this public package.

## Target

| Field | Value |
|---|---|
| Application | Uptodown App Store |
| Version | 7.32 |
| Package | com.uptodown |
| Version code | 732 |
| Min SDK | 23 |
| Target SDK | 35 |
| Main activity | `com.uptodown.activities.MainActivity` |

## Summary

The reviewed APK implements broad telemetry collection across device metadata, installed application inventory, usage statistics, account activity, event logging, crash reporting, and advertising or consent related services.

The analysis did not identify a classic backdoor pattern in the reviewed native libraries. The main security and privacy considerations are the breadth of telemetry collection, persistent background execution paths, installed application inventory collection, and multiple analytics or tracker destinations.

## Repository layout

```text
.
├── docs/                  Research reports in GitHub-ready Markdown
├── artifacts/api/          Endpoint and domain listings
├── artifacts/behavioral/   Behavioral signatures and data flow notes
├── artifacts/components/   Android package components and class listings
├── artifacts/database/     SQLite table and schema artifacts
├── artifacts/forensics/    IOC, YARA, Sigma, and STIX artifacts
└── artifacts/native/       Native code notes
```

## Main reports

- [Executive summary](docs/01-executive-summary.md)
- [Network analysis](docs/02-network-analysis.md)
- [Behavioral analysis](docs/03-behavioral-analysis.md)
- [Database and storage analysis](docs/04-database-storage-analysis.md)
- [Native code analysis](docs/05-native-code-analysis.md)
- [Forensic indicators](docs/06-forensic-indicators.md)
- [Publication notes](docs/07-publication-notes.md)

## Publication scope

Included:

- Static analysis notes
- Endpoint and domain inventory
- Android component inventory
- Local database and schema inventory
- Behavioral indicators
- IOC, YARA, Sigma, and STIX artifacts

Excluded from the public package:

- Runtime bypass scripts
- SSL interception scripts
- Memory dumping scripts
- Tracker modification scripts
- Full raw string dumps
- Full raw grep output from the reverse engineering workspace

## Responsible use

Use this repository for defensive research, privacy review, detection engineering, and internal security validation. Do not use the material to access systems, accounts, services, or data without authorization.
