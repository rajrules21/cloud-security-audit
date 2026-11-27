# AWS Security Audit

Strictly read-only AWS security audit exporting CSVs and `SECURITY_AUDIT_REPORT.md` (no JSON).

```powershell
pip install -r requirements.txt
python audit_aws_security.py
# Or specify an AWS CLI profile / regions:
python audit_aws_security.py --profile my-readonly-profile --region us-east-1 eu-west-1
```
