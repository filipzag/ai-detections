# AI Detection Engineering - Custom Detection Rules

This repository contains custom detection rules for Elastic Security, developed using AI-assisted detection engineering workflows.

## Rules Index

### APT28 (Fancy Bear / Forest Blizzard) - Linux Detection Coverage

These rules address detection gaps for APT28 (MITRE G0007) targeting Linux systems, with a focus on the Drovorub malware capabilities.

| Rule Name | MITRE ID | Severity | Type | File |
|-----------|----------|----------|------|------|
| Linux Kernel Module Rootkit Loading via Unusual Parent | T1014 | High | EQL | [apt28_linux_rootkit_kernel_module_loading.toml](rules/endpoint/apt28_linux_rootkit_kernel_module_loading.toml) |
| Linux Web Shell - Suspicious Process Spawned by Web Server | T1505.003 | High | EQL (sequence) | [apt28_linux_webshell_process_spawned.toml](rules/endpoint/apt28_linux_webshell_process_spawned.toml) |
| Linux Network Sniffing via Packet Capture Tools | T1040 | Medium | EQL | [apt28_linux_network_sniffing.toml](rules/endpoint/apt28_linux_network_sniffing.toml) |
| Linux Ingress Tool Transfer to Suspicious Directory | T1105 | Medium | EQL (sequence) | [apt28_linux_ingress_tool_transfer.toml](rules/endpoint/apt28_linux_ingress_tool_transfer.toml) |

### Rule Details

#### T1014 - Linux Kernel Module Rootkit Loading via Unusual Parent
- **Threat Context:** APT28's Drovorub malware uses insmod/modprobe to load a kernel module rootkit that hides processes, files, and network connections.
- **Data Source:** `logs-endpoint.events.process-default`
- **ART Tests:** `dfb50072-e45a-4c75-a17e-a484809c8553` (insmod), `75483ef8-f10f-444a-bf02-62eb0e48db6f` (modprobe)
- **Noise Exclusions:** systemd, dracut, depmod, kmod, systemd-modules-load

#### T1505.003 - Linux Web Shell - Suspicious Process Spawned by Web Server
- **Threat Context:** APT28 deploys web shells on compromised Linux web servers for persistent remote access and command execution.
- **Data Source:** `logs-endpoint.events.process-default`
- **Detection Logic:** Sequence - web server spawns shell interpreter, followed by recon/tool execution within 30s
- **Noise Exclusions:** Legitimate CGI scripts may need path-based exclusions

#### T1040 - Linux Network Sniffing via Packet Capture Tools
- **Threat Context:** APT28 uses network sniffing tools to capture credentials and sensitive data traversing the network.
- **Data Source:** `logs-endpoint.events.process-default`
- **ART Tests:** `7fe741f7-b265-4951-a7c7-320889083b3e` (tcpdump/tshark)
- **Noise Exclusions:** systemd, monit, nagios, zabbix monitoring

#### T1105 - Linux Ingress Tool Transfer to Suspicious Directory
- **Threat Context:** APT28 downloads second-stage payloads via curl/wget to staging directories (/tmp, /dev/shm, /var/tmp).
- **Data Source:** `logs-endpoint.events.process-default`
- **Detection Logic:** Sequence - download to suspicious path, followed by execution/chmod within 1m
- **Noise Exclusions:** Package managers (apt, yum, dnf, pip) may need exclusions

## Data Sources Required

| Data Stream | Purpose |
|---|---|
| `logs-endpoint.events.process-default` | Process creation, execution, and command line monitoring |
| `logs-endpoint.events.file-default` | File creation, modification, and deletion events |
| `logs-endpoint.events.network-default` | Network connection and DNS events |

## References

- [NSA/FBI Advisory - Russian GRU Drovorub Malware (Aug 2020)](https://media.defense.gov/2020/Aug/13/2002476465/-1/-1/0/CSA_DROVORUB_RUSSIAN_GRU_MALWARE_AUG_2020.PDF)
- [MITRE ATT&CK - APT28 (G0007)](https://attack.mitre.org/groups/G0007/)
