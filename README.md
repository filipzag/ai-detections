# AI Detections

Detection rules created and managed by AI Detection Engineering pipeline.

## Rules

### Endpoint Rules

| Rule Name | MITRE Technique | Severity | Type | Data Source |
|---|---|---|---|---|
| [APT28 Linux Ingress Tool Transfer](rules/endpoint/apt28_linux_ingress_tool_transfer.toml) | T1105 — Ingress Tool Transfer | medium | eql | Elastic Defend |
| [APT28 Linux Network Sniffing](rules/endpoint/apt28_linux_network_sniffing.toml) | T1040 — Network Sniffing | medium | eql | Elastic Defend |
| [APT28 Linux Rootkit Kernel Module Loading](rules/endpoint/apt28_linux_rootkit_kernel_module_loading.toml) | T1014 — Rootkit | high | eql | Elastic Defend |
| [APT28 Linux Timestomping via Touch Command](rules/endpoint/apt28_linux_timestomping_touch.toml) | T1070.006 — Timestomp | medium | eql | Elastic Defend |
| [APT28 Linux Web Shell Process Spawned](rules/endpoint/apt28_linux_webshell_process_spawned.toml) | T1505.003 — Web Shell | high | eql | Elastic Defend |
| [EC2 IMDS High Frequency Access](rules/endpoint/ec2_imds_high_frequency_access.toml) | T1552.005 — Cloud Instance Metadata API | high | threshold | Elastic Defend |
| [EC2 IMDS Suspicious Process Access](rules/endpoint/ec2_imds_suspicious_process_access.toml) | T1552.005 — Cloud Instance Metadata API | medium | eql | Elastic Defend |

## APT28 Linux Coverage Map

| MITRE Technique | Status | Rule |
|---|---|---|
| T1014 — Rootkit | :white_check_mark: Covered | apt28_linux_rootkit_kernel_module_loading |
| T1040 — Network Sniffing | :white_check_mark: Covered | apt28_linux_network_sniffing |
| T1070.006 — Timestomp | :white_check_mark: Covered | apt28_linux_timestomping_touch |
| T1105 — Ingress Tool Transfer | :white_check_mark: Covered | apt28_linux_ingress_tool_transfer |
| T1505.003 — Web Shell | :white_check_mark: Covered | apt28_linux_webshell_process_spawned |
| T1003 — OS Credential Dumping | :x: Gap | — |
| T1057 — Process Discovery | :x: Gap | — |
| T1070.004 — File Deletion | :x: Gap | — |
| T1083 — File and Directory Discovery | :x: Gap | — |
| T1140 — Deobfuscate/Decode Files | :x: Gap | — |
| T1560.001 — Archive via Utility | :x: Gap | — |
| T1564.001 — Hidden Files and Directories | :x: Gap | — |

## Validation

All rules are validated against Atomic Red Team tests before deployment. See individual rule notes for triage and investigation guidance.
