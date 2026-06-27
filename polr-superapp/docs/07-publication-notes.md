# Publication Notes

Author: Kenshin Himura - DTrust

## Public package policy

This package is designed for GitHub publication as defensive research documentation. It intentionally excludes operational tooling that could be used to bypass runtime checks, intercept traffic, dump memory, or modify telemetry behavior.

## Excluded material

The following material from the original workspace was not included in this public package:

```text
exploitation/
exploitation/frida_scripts/
behavioral/raw_findings.txt
database/raw_findings.txt
network/raw_findings.txt
strings/classes*_strings.txt
```

## Reason for exclusion

The excluded runtime material contains operational steps and scripts for instrumentation, traffic interception, memory extraction, and runtime behavior modification. That material is appropriate for a private lab archive, not for a public documentation repository.

Raw string dumps and raw grep output were excluded to keep the repository focused, readable, and reviewable. Curated endpoint, schema, IOC, YARA, Sigma, and STIX artifacts remain included.

## Language and style policy

- English only
- Direct technical writing
- No rhetorical framing
- No marketing language
- No unsupported certainty language
- No runtime bypass instructions
- No exploit execution steps
- No private keys, tokens, APK binaries, or packet captures
