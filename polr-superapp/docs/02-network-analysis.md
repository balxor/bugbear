# Network Analysis

Author: Kenshin Himura - DTrust

## Overview

The network surface is organized around Uptodown API hosts, tracker hosts, upload hosts, download infrastructure, and third-party telemetry or consent services.

## Primary hosts

| Host | Role |
|---|---|
| `www.uptodown.app:443` | Main application API |
| `t.uptodown.app:443` | Tracker API |
| `u.uptodown.app:443` | Upload API |
| `dw.uptodown.com` | Download CDN |

## Third-party services

| Domain | Observed role |
|---|---|
| `app-measurement.com` | Google analytics measurement |
| `firebaseinstallations.googleapis.com` | Firebase installation identifier workflow |
| `firebase-settings.crashlytics.com` | Crashlytics configuration |
| `api.cmp.inmobi.com` | InMobi CMP workflow |
| `api.country.is` | Country or geo lookup |
| `pagead2.googlesyndication.com` | Google advertising service |
| `www.googleapis.com` | Google API integration |

## Key endpoints

```text
/eapi/v2/tracker/device
/eapi/androidtracker/device-apps-installed
/eapi/user-data/native-app-usage
/eapi/v3/device/daily-stats
/eapi/v3/device/fcm-token
/eapi/logs/event
/eapi/logs/error
```

## Observed data paths

```text
Device metadata -> tracker API
Installed application inventory -> tracker API
Native app usage data -> user-data API
Daily device statistics -> device API
FCM token -> device API
Event logs -> logs API
Error logs -> logs API
Consent state -> InMobi CMP services
Crash data -> Firebase Crashlytics
Analytics events -> Google measurement services
```

## Notes

- The app uses HTTPS for API communication.
- The static review did not identify a dedicated certificate pinning implementation in the extracted report set.
- Endpoint names indicate collection of device state, installed application inventory, usage data, daily statistics, event logs, and error logs.
- The public repository includes endpoint and domain inventories under `artifacts/api/`.
