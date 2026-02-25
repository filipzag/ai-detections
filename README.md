# AI Detections

Custom detection rules engineered by AI Detection Engineering agents, validated against MITRE ATT&CK and deployed to Elastic Security.

## Rules

| Rule Name | Technique ID | Technique Name | Tactics | Type | OS | Data Source |
|-----------|-------------|----------------|---------|------|----|-------------|
| APT28 Linux Timestomping via Touch | T1070.006 | Timestomping | Defense Evasion | EQL | Linux | Elastic Defend |
| APT28 Linux Rootkit Kernel Module Loading | T1547.006 | Kernel Modules and Extensions | Persistence, Privilege Escalation | EQL | Linux | Elastic Defend |
| TeamTNT Container Execution via Kubectl | T1610 | Deploy Container | Execution | EQL | Linux | Elastic Defend |
| TeamTNT Packed Binary Execution | T1027.002 | Software Packing | Defense Evasion | EQL | Linux | Elastic Defend |
| TeamTNT Service Discovery via Network Scanning | T1046 | Network Service Discovery | Discovery | EQL | Linux | Elastic Defend |
| APT38 Suspicious Cron Job Execution from Staging Directory | T1053.003 | Cron | Persistence, Execution | EQL Sequence | Linux | Elastic Defend |

## Structure

```
rules/
├── aws/          # AWS cloud detection rules
├── endpoint/     # Endpoint detection rules (Linux, Windows, macOS)
└── integrations/ # Integration-specific detection rules
```
