# GCP Security & Identity Audit Module (Planned)

Planned read-only collectors using `google-cloud-*` SDKs to mirror the Azure module's CSV + Markdown output format:

- **IAM & Service Account Hygiene**: Over-privileged `Owner`/`Editor` bindings, external/personal Gmail accounts in IAM, unused service accounts, and user-managed service account keys.
- **Cloud Audit Logs Correlation**: Cross-reference IAM policy bindings against 90-day Admin Activity & Data Access logs.
- **Resource & Network Posture**: Publicly exposed GCS buckets, VPC firewall rules allowing `0.0.0.0/0` on sensitive ports, Cloud SQL public IPs, and Security Command Center (SCC) findings.
