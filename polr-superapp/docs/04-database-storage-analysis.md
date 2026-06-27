# Database and Storage Analysis

Author: Kenshin Himura - DTrust

## Overview

The local storage review identified SQLite table definitions and storage artifacts used by the application, Firebase components, and WorkManager.

## Table inventory

| Category | Count | Notes |
|---|---:|---|
| Uptodown custom tables | 12 | Application, download, device state, and usage related data |
| Firebase analytics tables | 17 | Analytics and measurement storage |
| WorkManager tables | 8 | Background task scheduling and state |
| Other tables | 10 | Supporting library or application storage |
| Total | 47 | Based on extracted schema artifacts |

## Notable storage areas

```text
Application catalog state
Download state
Device state
Data usage records
Analytics events
WorkManager job state
SharedPreferences values
Cache and temporary data
```

## Security and privacy relevance

- Local databases may contain device status, application metadata, download records, and analytics state.
- WorkManager tables show background task state and scheduling metadata.
- Firebase related tables indicate local buffering for analytics and measurement workflows.
- Local storage can support delayed upload when the network is unavailable.

## Artifacts

- `artifacts/database/create_tables.txt`
- `artifacts/database/schemas.txt`
- `artifacts/database/table_names.txt`
- `artifacts/database/table_schemas.txt`
- `artifacts/database/table_summary.txt`

Large raw grep output was not included in the public package. It can be retained in a private lab archive if full reproducibility is required.
