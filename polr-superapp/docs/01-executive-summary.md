# Executive Summary

Author: Kenshin Himura - DTrust

## Target

| Field | Value |
|---|---|
| Application | Uptodown App Store |
| Version | 7.32 |
| Package name | `com.uptodown` |
| Version code | 732 |
| Min SDK | 23 |
| Target SDK | 35 |
| Main activity | `com.uptodown.activities.MainActivity` |

## Scope

The analysis reviewed the APK structure, Android manifest data, DEX strings, package components, native libraries, local database artifacts, API endpoints, telemetry paths, and forensic indicators.

## Key findings

1. The application contains a broad telemetry surface covering device metadata, installed application inventory, usage statistics, account-related activity, event logs, crash data, and advertising or consent related services.
2. The network design separates the main API, tracker API, upload API, and download CDN across different Uptodown-controlled hosts.
3. The package requests permissions relevant to package management, installed application visibility, storage, microphone access, account integration, notifications, and usage statistics.
4. The application uses WorkManager, receivers, services, and local storage to support background execution and delayed synchronization.
5. The reviewed native libraries are small. The custom native library exposes JNI functions related to API key retrieval. No native backdoor pattern was observed in the reviewed native library artifacts.
6. The analyzed code contains anti-analysis checks such as debugger state checks, emulator or VM property checks, root-related file checks, and obfuscation artifacts.

## Assessment

The reviewed sample is best described as a telemetry-heavy commercial Android application. The main research value is in documenting collection scope, network destinations, local persistence, and forensic indicators.

This report avoids exploit instructions and runtime bypass procedures. The public repository is intended for defensive review, privacy analysis, and detection engineering.

## High-level data flow

```text
Application runtime -> local stores -> Uptodown API and tracker hosts
Application runtime -> Firebase and Google services -> analytics, crash, and messaging workflows
Application runtime -> InMobi CMP services -> consent and advertising related workflows
```

## Primary technical areas

| Area | Finding |
|---|---|
| Package structure | 4 DEX files, 64 activities, 15 services, 11 receivers, 4 providers |
| Permissions | 32 permissions, including package visibility, package install/delete, usage stats, microphone, and storage related permissions |
| Network | 137+ API endpoints and 77 URLs were cataloged from static artifacts |
| Local storage | 47 database tables were identified across application, Firebase, and WorkManager storage |
| Behavioral indicators | 3,496 tracking-related strings, 692 trigger-related strings, and 1,544 lifecycle-related strings were cataloged |
| Native code | 3 native libraries across 4 architectures, with a custom Uptodown JNI library for API key retrieval |
| Forensics | JSON IOC set, STIX bundle, Sigma rules, and YARA rules are included in `artifacts/forensics/` |
