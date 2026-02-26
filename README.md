# AI Detections

Custom detection rules created by AI Detection Engineering.

## Rules

| Rule Name | MITRE Technique | Severity | OS | Path |
|-----------|----------------|----------|-----|------|
| APT28 Linux Ingress Tool Transfer | T1105 | High | Linux | `rules/endpoint/apt28_linux_ingress_tool_transfer.toml` |
| APT28 Linux Network Sniffing | T1040 | High | Linux | `rules/endpoint/apt28_linux_network_sniffing.toml` |
| APT28 Linux Rootkit Kernel Module Loading | T1547.006 | High | Linux | `rules/endpoint/apt28_linux_rootkit_kernel_module_loading.toml` |
| APT28 Linux Timestomping via Touch | T1070.006 | High | Linux | `rules/endpoint/apt28_linux_timestomping_touch.toml` |
| APT28 Linux Web Shell Process Spawned | T1505.003 | High | Linux | `rules/endpoint/apt28_linux_webshell_process_spawned.toml` |
| APT38 Linux Cron Persistence Sequence | T1053.003 | High | Linux | `rules/endpoint/apt38_linux_cron_persistence_sequence.toml` |
| EC2 IMDS High Frequency Access | T1552.005 | Medium | Linux | `rules/endpoint/ec2_imds_high_frequency_access.toml` |
| EC2 IMDS Suspicious Process Access | T1552.005 | Medium | Linux | `rules/endpoint/ec2_imds_suspicious_process_access.toml` |
| Linux Privilege Escalation via LD_PRELOAD Hijacking | T1574.006 | High | Linux | `rules/endpoint/linux/linux_priv_esc_ld_preload_hijacking.json` |
| Linux Privilege Escalation via Sudoers NOPASSWD Modification | T1548.003 | High | Linux | `rules/endpoint/linux/linux_priv_esc_sudoers_nopasswd_modification.json` |
| Linux Privilege Escalation via SUID/SGID Bit Set | T1548.001 | High | Linux | `rules/endpoint/linux/linux_priv_esc_suid_sgid_bit_set.json` |
| Potential SUID/SGID Exploitation | T1548.001 | High | Linux | `rules/endpoint/linux/privilege_escalation_potential_suid_sgid_exploitation.toml` |
| Potential SUID/SGID Proxy Execution | T1548.001 | Medium | Linux | `rules/endpoint/linux/privilege_escalation_potential_suid_sgid_proxy_execution.toml` |
| SUID/SGID Bit Set via chmod | T1548.001 | Medium | Linux | `rules/endpoint/linux/privilege_escalation_setuid_setgid_bit_set_via_chmod.toml` |
| Sudoers NOPASSWD Modification | T1548.003 | High | Linux | `rules/endpoint/linux/privilege_escalation_sudoers_nopasswd_modification.toml` |
| **APT39 Linux Systemd Service Persistence** | **T1543.002** | **High** | **Linux** | `rules/linux/persistence_apt39_systemd_service.toml` |
