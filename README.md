# AI-Generated Detection Rules

This repository contains production-ready detection rules for security monitoring and threat detection, generated and validated using Elastic AI Assistant.

## Repository Structure

```
ai-detections/
├── rules/
│   ├── aws/              # AWS CloudTrail-based detections
│   └── endpoint/         # Endpoint-based detections
└── README.md
```

## Detection Rules

### EC2 Pivot to AWS Attack Detection

Four detection rules covering EC2 instance credential theft and abuse:

#### Endpoint-Based Detections

1. **Suspicious Process Accessing EC2 Instance Metadata Service**
   - **File:** `rules/endpoint/ec2_imds_suspicious_process_access.toml`
   - **Severity:** High
   - **MITRE ATT&CK:** T1552.005
   - **Description:** Detects unusual processes accessing IMDS at 169.254.169.254
   - **Use Case:** Identifies SSRF exploitation and credential theft attempts

2. **High-Frequency IMDS Access from Single Process**
   - **File:** `rules/endpoint/ec2_imds_high_frequency_access.toml`
   - **Severity:** High
   - **MITRE ATT&CK:** T1552.005, T1059
   - **Description:** Detects rapid credential harvesting attempts (5+ connections in 5 minutes)
   - **Use Case:** Catches automated exploitation tools and scripts

#### CloudTrail-Based Detections

3. **EC2 Instance Role Credential Abuse for IAM Privilege Escalation**
   - **File:** `rules/aws/ec2_instance_role_credential_abuse.toml`
   - **Severity:** Critical
   - **MITRE ATT&CK:** T1552.005, T1078.004
   - **Description:** Detects stolen EC2 credentials used for IAM modifications
   - **Use Case:** Identifies privilege escalation after credential theft

4. **EC2 Instance Role Used for AWS Reconnaissance Activity**
   - **File:** `rules/aws/ec2_instance_role_reconnaissance.toml`
   - **Severity:** High
   - **MITRE ATT&CK:** T1078.004, T1087, T1580
   - **Description:** Detects post-compromise enumeration activities
   - **Use Case:** Catches attackers mapping the AWS environment

## Deployment

### Prerequisites

- Elastic Security 8.x or higher
- AWS CloudTrail integration configured
- Elastic Defend (endpoint agent) deployed on EC2 instances
- Data streams:
  - `logs-aws.cloudtrail-*`
  - `logs-endpoint.events.network-*`

### Installation

1. **Clone this repository:**
   ```bash
   git clone https://github.com/filipzag/ai-detections.git
   cd ai-detections
   ```

2. **Import TOML files into Elastic Security:**
   - Navigate to **Security → Rules → Detection rules (SIEM)**
   - Click **"Import"** and select the TOML files
   - Or use the Elastic Detection Rules CLI:
     ```bash
     detection-rules import-rules -d rules/
     ```

3. **Enable rules in detection-only mode initially:**
   - Set all rules to detection-only for 1-2 weeks
   - Monitor for false positives
   - Document legitimate automation patterns

4. **Tune exclusions as needed:**
   - Add trusted processes and roles to exclusion lists
   - Adjust time windows based on your environment

5. **Enable alerting in production:**
   - Configure appropriate severity levels
   - Set up notification channels
   - Create incident response playbooks

## Testing

### Manual Attack Simulation

Test the endpoint-based detections:

```bash
# SSH into EC2 instance
ssh ec2-user@<instance-ip>

# Simulate credential theft from IMDS
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
ROLE_NAME=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME
```

### Expected Alerts

- **Endpoint rules** should trigger within seconds of IMDS access
- **CloudTrail rules** trigger when stolen credentials are used for AWS API calls
- Check **Security → Alerts** in Kibana for triggered detections

### Validation Results

✅ All queries validated against live data  
✅ Field mappings confirmed in target indices  
✅ EQL syntax tested and corrected  
✅ Queries execute without errors  

## Tuning

### Common Exclusions

Add these to reduce false positives:

```eql
# Endpoint rules - exclude trusted processes
and not process.name in ("your-monitoring-tool", "your-backup-agent")
and not process.executable like "/opt/your-app/*"

# CloudTrail rules - exclude trusted automation
and not aws.cloudtrail.user_identity.arn like "*TrustedAutomationRole*"
and not aws.cloudtrail.user_identity.arn like "*TerraformRole*"
```

### Adjusting Time Windows

- **High-frequency detection:** Change `maxspan=5m` to `maxspan=10m` if legitimate tools trigger alerts
- **IAM abuse detection:** Adjust `maxspan=1h` based on your automation patterns
- **Reconnaissance detection:** Modify `maxspan=30m` for slower attack scenarios

## Mitigation & Hardening

### 1. Enforce IMDSv2 (Prevents SSRF Attacks)

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxxxx \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

### 2. Restrict IMDS Access with iptables

```bash
# Block IMDS access from non-root users
iptables -A OUTPUT -m owner ! --uid-owner 0 -d 169.254.169.254 -j DROP
```

### 3. Implement Least Privilege IAM Policies

Minimize permissions granted to EC2 instance roles:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::specific-bucket/*"
    }
  ]
}
```

### 4. Use VPC Endpoints

Restrict AWS API calls to private networks, preventing credential exfiltration.

### 5. Enable AWS GuardDuty

Provides behavioral anomaly detection for AWS accounts.

## Detection Coverage

| Attack Stage | Detection Layer | Coverage |
|-------------|----------------|----------|
| **Credential Theft** | Endpoint | Process-based IMDS access monitoring |
| **Automated Harvesting** | Endpoint | High-frequency connection detection |
| **Privilege Escalation** | CloudTrail | IAM modification tracking |
| **Reconnaissance** | CloudTrail | Resource enumeration detection |

## MITRE ATT&CK Mapping

- **T1552.005** - Unsecured Credentials: Cloud Instance Metadata API
- **T1078.004** - Valid Accounts: Cloud Accounts
- **T1087** - Account Discovery
- **T1580** - Cloud Infrastructure Discovery
- **T1059** - Command and Scripting Interpreter

## References

- [MITRE ATT&CK T1552.005 - Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005/)
- [AWS IMDSv2 Security Best Practices](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [Elastic Security Labs - Detecting AWS Credential Access](https://www.elastic.co/security-labs/detecting-aws-credential-access)
- [Capital One Breach Analysis - SSRF to IMDS](https://krebsonsecurity.com/2019/07/capital-one-data-theft-impacts-106m-people/)

## Contributing

To add new detection rules:

1. Create a new branch
2. Add TOML files following the existing structure
3. Validate queries against your test environment
4. Submit a pull request with validation results

## License

Elastic License v2

## Author

Generated and validated by Elastic AI Assistant

---

**Last Updated:** 2026-02-17  
**Detection Rules:** 4  
**Status:** Production Ready ✅
