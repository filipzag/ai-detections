# Custom Atomic Red Team Tests

This directory contains custom Atomic Red Team tests for validating detection rules in the ai-detections repository.

## Overview

These atomic tests are designed to validate the EC2 pivot to AWS detection rules by simulating real-world attack techniques.

## Test Coverage

### T1552.005 - Unsecured Credentials: Cloud Instance Metadata API

**Location:** `T1552.005/T1552.005.yaml`

#### Tests Included:

1. **EC2 IMDS Credential Theft via curl**
   - Simulates basic credential theft using curl
   - Validates endpoint detection rule: "Suspicious Process Accessing EC2 Instance Metadata Service"
   - Platform: Linux, macOS

2. **EC2 IMDS Credential Theft via Python**
   - Simulates credential theft using Python requests/urllib
   - Validates endpoint detection for scripting languages
   - Platform: Linux, macOS

3. **High-Frequency IMDS Credential Harvesting**
   - Simulates rapid repeated IMDS access (6 queries in ~12 seconds)
   - Validates sequence detection rule: "High-Frequency IMDS Access from Single Process"
   - Platform: Linux, macOS

4. **EC2 IMDS Access via wget**
   - Simulates credential theft using wget
   - Validates detection coverage for alternative HTTP clients
   - Platform: Linux, macOS

### T1078.004 - Valid Accounts: Cloud Accounts

**Location:** `T1078.004/T1078.004.yaml`

#### Tests Included:

1. **AWS IAM Privilege Escalation via Stolen EC2 Credentials**
   - Simulates IAM user creation and policy attachment
   - Validates CloudTrail detection rule: "EC2 Instance Role Credential Abuse for IAM Privilege Escalation"
   - Platform: Linux, macOS
   - **WARNING:** Performs actual AWS API calls

2. **AWS Reconnaissance via Stolen EC2 Credentials**
   - Simulates multi-service reconnaissance (EC2, S3, RDS, Secrets Manager, IAM)
   - Validates CloudTrail detection rule: "EC2 Instance Role Used for AWS Reconnaissance Activity"
   - Platform: Linux, macOS
   - **WARNING:** Performs actual AWS API calls

## Prerequisites

### For IMDS Tests (T1552.005)

- Must run on an AWS EC2 instance
- EC2 instance must have an IAM role attached
- curl, wget, or python3 installed (depending on test)

### For AWS API Tests (T1078.004)

- Must run on an AWS EC2 instance with IAM role
- AWS CLI installed and configured
- IAM role must have permissions for tested actions
- **Isolated test environment recommended**

## Running Tests

### Using Atomic Red Team Executor

```bash
# Install Atomic Red Team
git clone https://github.com/redcanaryco/invoke-atomicredteam.git
cd invoke-atomicredteam
Import-Module ./Invoke-AtomicRedTeam.psd1

# Run specific test
Invoke-AtomicTest T1552.005 -TestNumbers 1

# Run all tests for a technique
Invoke-AtomicTest T1552.005

# Run with cleanup
Invoke-AtomicTest T1552.005 -TestNumbers 1 -Cleanup
```

### Manual Execution

#### Test 1: Basic IMDS Credential Theft

```bash
# SSH into EC2 instance
ssh ec2-user@<instance-ip>

# Run the test
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
ROLE_NAME=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME
```

#### Test 2: High-Frequency Harvesting

```bash
# Run rapid queries
for i in {1..6}; do
  curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ > /dev/null
  sleep 2
done
```

#### Test 3: AWS Reconnaissance

```bash
# Enumerate AWS resources
aws ec2 describe-instances
aws ec2 describe-security-groups
aws s3 ls
aws rds describe-db-clusters
aws secretsmanager list-secrets
```

## Expected Detection Results

### Endpoint Detections (Elastic Defend)

| Test | Detection Rule | Expected Alert Time |
|------|---------------|--------------------|
| IMDS Theft (curl) | Suspicious Process Accessing IMDS | < 10 seconds |
| IMDS Theft (Python) | Suspicious Process Accessing IMDS | < 10 seconds |
| High-Frequency Harvesting | High-Frequency IMDS Access | < 5 minutes |
| IMDS Theft (wget) | Suspicious Process Accessing IMDS | < 10 seconds |

### CloudTrail Detections

| Test | Detection Rule | Expected Alert Time |
|------|---------------|--------------------|
| IAM Privilege Escalation | EC2 Instance Role Credential Abuse | < 1 hour |
| AWS Reconnaissance | EC2 Instance Role Reconnaissance | < 30 minutes |

## Validation Checklist

After running tests, verify:

- [ ] Endpoint alerts appear in Security → Alerts
- [ ] CloudTrail alerts appear in Security → Alerts
- [ ] Alert severity matches rule configuration
- [ ] Alert contains correct MITRE ATT&CK mapping
- [ ] Alert includes process/user context
- [ ] No false negatives (all tests detected)
- [ ] Cleanup commands executed successfully

## Safety Considerations

### IMDS Tests (T1552.005)

- ✅ **Safe**: Read-only operations
- ✅ **Safe**: No system modifications
- ✅ **Safe**: No credential exfiltration
- ⚠️ **Note**: Will trigger security alerts (expected)

### AWS API Tests (T1078.004)

- ⚠️ **Caution**: Creates real AWS resources
- ⚠️ **Caution**: Requires cleanup to avoid costs
- ⚠️ **Caution**: May trigger AWS GuardDuty alerts
- 🚨 **Warning**: Only run in isolated test environments
- 🚨 **Warning**: Ensure IAM permissions are limited

## Troubleshooting

### IMDS Not Accessible

```bash
# Check if running on EC2
curl -s -m 2 http://169.254.169.254/latest/meta-data/instance-id

# Check if IMDSv2 is enforced
aws ec2 describe-instances --instance-ids $(curl -s http://169.254.169.254/latest/meta-data/instance-id) --query 'Reservations[0].Instances[0].MetadataOptions'
```

### AWS CLI Errors

```bash
# Verify AWS CLI is configured
aws sts get-caller-identity

# Check IAM role permissions
aws iam get-role --role-name <role-name>
```

### Detection Not Triggering

1. Verify Elastic Defend agent is running
2. Check detection rule is enabled
3. Verify index patterns match your data streams
4. Review rule execution logs in Kibana
5. Ensure time windows haven't expired

## Contributing

To add new atomic tests:

1. Follow the Atomic Red Team YAML schema
2. Include comprehensive descriptions
3. Map to MITRE ATT&CK techniques
4. Provide cleanup commands
5. Test in isolated environment
6. Document expected detection results

## References

- [Atomic Red Team Framework](https://github.com/redcanaryco/atomic-red-team)
- [MITRE ATT&CK T1552.005](https://attack.mitre.org/techniques/T1552/005/)
- [MITRE ATT&CK T1078.004](https://attack.mitre.org/techniques/T1078/004/)
- [AWS IMDS Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- [Elastic Detection Rules](https://www.elastic.co/guide/en/security/current/detection-engine-overview.html)

## License

MIT License - See repository root for details

---

**Last Updated:** 2026-02-17  
**Atomic Tests:** 6  
**Techniques Covered:** 2 (T1552.005, T1078.004)  
**Status:** Production Ready ✅
