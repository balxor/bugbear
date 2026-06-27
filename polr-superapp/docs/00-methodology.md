# Methodology

Author: Kenshin Himura - DTrust

## Analysis phases

1. APK extraction and manifest review
2. DEX string extraction and package component inventory
3. API endpoint and domain extraction
4. Native library inventory and JNI function review
5. SQLite schema and local storage review
6. Behavioral string clustering
7. IOC, YARA, Sigma, and STIX artifact preparation
8. Public documentation sanitization

## Review boundaries

This repository documents observed static artifacts and derived analysis notes. It does not include runtime bypass instructions, live traffic capture, credential extraction, or memory dumping procedures.

## Reproducibility notes

The public package keeps curated output artifacts and summary reports. Large raw extraction files are better retained in a private archive if a reviewer needs byte-level reproducibility.
