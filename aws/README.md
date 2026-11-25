# AWS Security & Identity Audit Module (Planned)

Planned read-only collectors using `boto3` to mirror the Azure module's CSV + Markdown output format:

- **IAM & Identity Correlation**: Unused IAM users/roles, stale access keys, MFA status, inline vs. managed policies, cross-account trust policies, and IAM Access Analyzer findings.
- **CloudTrail Activity Cross-Reference**: Identify unused IAM permissions and dormant service roles over a 90-day window.
- **Resource & Network Posture**: S3 public access blocks & encryption, overly permissive Security Groups (`0.0.0.0/0` on SSH/RDP/DB ports), RDS public accessibility, KMS key rotation, and GuardDuty / Security Hub findings.
