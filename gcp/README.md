# GCP Security Audit

Strictly read-only GCP security audit using Application Default Credentials (`gcloud auth application-default login`), exporting CSVs and `SECURITY_AUDIT_REPORT.md` (no JSON).

```powershell
pip install -r requirements.txt
gcloud auth application-default login
python audit_gcp_security.py
# Or audit specific projects:
python audit_gcp_security.py --project my-prod-project my-dev-project
```
