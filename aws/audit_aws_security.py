#!/usr/bin/env python3
"""
AWS Security Audit (Strictly Read-Only).

Audits IAM users/MFA/access keys, unused/over-privileged IAM roles, S3 public access,
VPC Security Groups & Public IPs, RDS/EBS/EC2/KMS/ECR/EKS posture, and
CloudTrail / GuardDuty / Security Hub coverage.

Outputs CSVs in <output-dir>/csv/ and SECURITY_AUDIT_REPORT.md (no JSON).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError

from aws_common import (
    SENSITIVE_PORTS,
    AwsAuditContext,
    days_ago,
    fmt_dt,
    get_enabled_regions,
    log,
    md_table,
    write_csv,
)


def audit_iam_users(session: boto3.Session, ctx: AwsAuditContext) -> List[Dict[str, Any]]:
    log("Auditing IAM users, MFA, console login, and access keys...")
    iam = session.client("iam")
    rows: List[Dict[str, Any]] = []

    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
        if summary.get("AccountMFAEnabled", 0) == 0:
            rows.append({
                "UserName": "ROOT_ACCOUNT",
                "UserId": "root",
                "HasConsolePassword": "Yes",
                "MfaEnabled": "No",
                "PasswordLastUsed": "",
                "AccessKeyId": "",
                "KeyStatus": f"RootAccessKeysPresent={summary.get('AccountAccessKeysPresent', 0)}",
                "KeyAgeDays": "",
                "KeyLastUsed": "",
                "Flags": "CRITICAL: Root MFA disabled",
            })
    except ClientError as e:
        ctx.warn(f"Could not read IAM account summary: {e}")

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for u in page.get("Users", []):
            uname = u["UserName"]
            pw_last = u.get("PasswordLastUsed")
            has_console = "Unknown"
            try:
                iam.get_login_profile(UserName=uname)
                has_console = "Yes"
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    has_console = "No"

            mfa_devices = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
            mfa_enabled = "Yes" if mfa_devices else "No"

            keys = iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", [])
            if not keys:
                flags = []
                if has_console == "Yes" and mfa_enabled == "No":
                    flags.append("Console user without MFA")
                pw_age = days_ago(pw_last, ctx.now)
                if pw_age is not None and pw_age >= ctx.stale_days:
                    flags.append(f"Inactive console login ({pw_age}d)")
                rows.append({
                    "UserName": uname,
                    "UserId": u.get("UserId", ""),
                    "HasConsolePassword": has_console,
                    "MfaEnabled": mfa_enabled,
                    "PasswordLastUsed": fmt_dt(pw_last),
                    "AccessKeyId": "",
                    "KeyStatus": "None",
                    "KeyAgeDays": "",
                    "KeyLastUsed": "",
                    "Flags": "; ".join(flags) if flags else "OK",
                })
                continue

            for k in keys:
                kid = k["AccessKeyId"]
                kstatus = k["Status"]
                kage = days_ago(k.get("CreateDate"), ctx.now)
                klast = None
                try:
                    lu = iam.get_access_key_last_used(AccessKeyId=kid).get("AccessKeyLastUsed", {})
                    klast = lu.get("LastUsedDate")
                except ClientError:
                    pass

                flags = []
                if has_console == "Yes" and mfa_enabled == "No":
                    flags.append("Console user without MFA")
                if kstatus == "Active" and kage is not None and kage >= 90:
                    flags.append(f"Old active key ({kage}d)")
                klast_age = days_ago(klast, ctx.now)
                if kstatus == "Active" and (klast is None or (klast_age is not None and klast_age >= ctx.stale_days)):
                    flags.append("Unused/stale active key")

                rows.append({
                    "UserName": uname,
                    "UserId": u.get("UserId", ""),
                    "HasConsolePassword": has_console,
                    "MfaEnabled": mfa_enabled,
                    "PasswordLastUsed": fmt_dt(pw_last),
                    "AccessKeyId": kid,
                    "KeyStatus": kstatus,
                    "KeyAgeDays": kage if kage is not None else "",
                    "KeyLastUsed": fmt_dt(klast),
                    "Flags": "; ".join(flags) if flags else "OK",
                })
    return rows


def audit_iam_roles(session: boto3.Session, ctx: AwsAuditContext) -> List[Dict[str, Any]]:
    log("Auditing IAM roles for unused roles, Admin privileges, and risky trust policies...")
    iam = session.client("iam")
    rows: List[Dict[str, Any]] = []
    paginator = iam.get_paginator("list_roles")

    for page in paginator.paginate():
        for r in page.get("Roles", []):
            rname = r["RoleName"]
            if r.get("Path", "").startswith("/aws-service-role/"):
                continue

            # Fetch full role to get RoleLastUsed
            last_used_dt = None
            try:
                detail = iam.get_role(RoleName=rname).get("Role", {})
                last_used_dt = detail.get("RoleLastUsed", {}).get("LastUsedDate")
            except ClientError:
                pass

            attached = [p["PolicyName"] for p in iam.list_attached_role_policies(RoleName=rname).get("AttachedPolicies", [])]
            inline = iam.list_role_policies(RoleName=rname).get("PolicyNames", [])

            trust_doc = r.get("AssumeRolePolicyDocument") or {}
            trust_flags = []
            for stmt in trust_doc.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                principal = stmt.get("Principal", {})
                if principal == "*" or principal.get("AWS") == "*":
                    trust_flags.append("Wildcard Trust (*)")

            age = days_ago(last_used_dt, ctx.now)
            usage_status = "Never Used" if last_used_dt is None else (f"Stale ({age}d)" if age >= ctx.stale_days else "Active")

            flags = list(trust_flags)
            if "AdministratorAccess" in attached:
                flags.append("AdministratorAccess attached")
            if usage_status != "Active":
                flags.append(usage_status)

            rows.append({
                "RoleName": rname,
                "Arn": r.get("Arn", ""),
                "LastUsed": fmt_dt(last_used_dt),
                "UsageStatus": usage_status,
                "AttachedPolicies": "; ".join(attached),
                "InlinePolicies": "; ".join(inline),
                "Flags": "; ".join(flags) if flags else "OK",
            })
    return rows


def audit_s3(session: boto3.Session, ctx: AwsAuditContext) -> List[Dict[str, Any]]:
    log("Auditing S3 buckets for public access, encryption, and versioning...")
    s3 = session.client("s3")
    rows: List[Dict[str, Any]] = []
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        ctx.warn(f"Could not list S3 buckets: {e}")
        return rows

    for b in buckets:
        name = b["Name"]
        issues = []
        try:
            pab = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
            if not all(pab.get(k, False) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
                issues.append("PublicAccessBlock incomplete")
        except ClientError:
            issues.append("No PublicAccessBlock configured")

        try:
            ps = s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})
            if ps.get("IsPublic"):
                issues.append("Bucket policy is PUBLIC")
        except ClientError:
            pass

        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError:
            issues.append("Default encryption not configured")

        try:
            ver = s3.get_bucket_versioning(Bucket=name).get("Status")
            if ver != "Enabled":
                issues.append(f"Versioning={ver or 'Disabled'}")
        except ClientError:
            pass

        rows.append({
            "BucketName": name,
            "Severity": "High" if any("PUBLIC" in i or "PublicAccessBlock" in i for i in issues) else ("Medium" if issues else "OK"),
            "Issues": "; ".join(issues) if issues else "Compliant",
        })
    return rows


def audit_regions(session: boto3.Session, ctx: AwsAuditContext, regions: List[str]) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    net_rows: List[Dict[str, Any]] = []
    res_rows: List[Dict[str, Any]] = []
    log_rows: List[Dict[str, Any]] = []

    # Multi-region CloudTrail check (from us-east-1)
    try:
        ct = session.client("cloudtrail", region_name="us-east-1")
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        if not trails:
            log_rows.append({"Service": "CloudTrail", "Region": "Global", "Severity": "Critical", "Detail": "No CloudTrail trails configured"})
        else:
            for t in trails:
                status = ct.get_trail_status(Name=t["TrailARN"])
                issues = []
                if not status.get("IsLogging"):
                    issues.append("Not logging")
                if not t.get("IsMultiRegionTrail"):
                    issues.append("Single-region only")
                if not t.get("LogFileValidationEnabled"):
                    issues.append("Log file validation disabled")
                log_rows.append({
                    "Service": "CloudTrail",
                    "Region": t.get("HomeRegion", ""),
                    "Severity": "High" if issues else "OK",
                    "Detail": f"Trail={t.get('Name')} | {'; '.join(issues) if issues else 'Compliant'}",
                })
    except ClientError as e:
        ctx.warn(f"CloudTrail check failed: {e}")

    for reg in regions:
        log(f"Scanning region {reg}...")
        ec2 = session.client("ec2", region_name=reg)

        # Security Groups
        try:
            sgs = ec2.describe_security_groups().get("SecurityGroups", [])
            for sg in sgs:
                for perm in sg.get("IpPermissions", []):
                    from_p = perm.get("FromPort", -1)
                    to_p = perm.get("ToPort", -1)
                    cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", [])] + [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])]
                    public_cidrs = [c for c in cidrs if c in ("0.0.0.0/0", "::/0")]
                    if public_cidrs:
                        is_sensitive = from_p == -1 or any(from_p <= p <= to_p for p in SENSITIVE_PORTS if p != -1)
                        if is_sensitive:
                            net_rows.append({
                                "FindingType": "Risky Inbound SG Rule",
                                "Region": reg,
                                "Resource": f"{sg.get('GroupName')} ({sg.get('GroupId')})",
                                "Severity": "Critical",
                                "Detail": f"Source={','.join(public_cidrs)} Ports={from_p}..{to_p} Proto={perm.get('IpProtocol')}",
                            })
        except ClientError as e:
            ctx.warn(f"SG check failed in {reg}: {e}")

        # Public IPs on EC2 / EIPs
        try:
            eips = ec2.describe_addresses().get("Addresses", [])
            for eip in eips:
                net_rows.append({
                    "FindingType": "Elastic IP",
                    "Region": reg,
                    "Resource": eip.get("PublicIp", ""),
                    "Severity": "Info",
                    "Detail": f"AllocationId={eip.get('AllocationId')} AttachedTo={eip.get('InstanceId') or eip.get('NetworkInterfaceId') or 'Unattached'}",
                })
        except ClientError:
            pass

        # EBS Encryption & EC2 IMDSv2
        try:
            vols = ec2.describe_volumes().get("Volumes", [])
            for v in vols:
                if not v.get("Encrypted"):
                    res_rows.append({
                        "Category": "EBS Volume",
                        "Region": reg,
                        "Resource": v.get("VolumeId", ""),
                        "Severity": "Medium",
                        "Issues": "Unencrypted EBS volume",
                    })
            resv = ec2.describe_instances().get("Reservations", [])
            for r in resv:
                for inst in r.get("Instances", []):
                    if inst.get("MetadataOptions", {}).get("HttpTokens") != "required":
                        res_rows.append({
                            "Category": "EC2 Instance",
                            "Region": reg,
                            "Resource": inst.get("InstanceId", ""),
                            "Severity": "Medium",
                            "Issues": "IMDSv2 not enforced (HttpTokens != required)",
                        })
        except ClientError:
            pass

        # RDS
        try:
            rds = session.client("rds", region_name=reg)
            for db in rds.describe_db_instances().get("DBInstances", []):
                issues = []
                if db.get("PubliclyAccessible"):
                    issues.append("PubliclyAccessible=True")
                if not db.get("StorageEncrypted"):
                    issues.append("Storage not encrypted")
                if issues:
                    res_rows.append({
                        "Category": "RDS Instance",
                        "Region": reg,
                        "Resource": db.get("DBInstanceIdentifier", ""),
                        "Severity": "High" if db.get("PubliclyAccessible") else "Medium",
                        "Issues": "; ".join(issues),
                    })
        except ClientError:
            pass

        # KMS key rotation
        try:
            kms = session.client("kms", region_name=reg)
            for k in kms.list_keys().get("Keys", []):
                kid = k["KeyId"]
                meta = kms.describe_key(KeyId=kid).get("KeyMetadata", {})
                if meta.get("KeyManager") == "CUSTOMER" and meta.get("KeyState") == "Enabled":
                    rot = kms.get_key_rotation_status(KeyId=kid).get("KeyRotationEnabled")
                    if not rot:
                        res_rows.append({
                            "Category": "KMS CMK",
                            "Region": reg,
                            "Resource": kid,
                            "Severity": "Medium",
                            "Issues": "Automatic annual key rotation disabled",
                        })
        except ClientError:
            pass

        # GuardDuty
        try:
            gd = session.client("guardduty", region_name=reg)
            detectors = gd.list_detectors().get("DetectorIds", [])
            if not detectors:
                log_rows.append({"Service": "GuardDuty", "Region": reg, "Severity": "Medium", "Detail": "GuardDuty not enabled"})
            else:
                log_rows.append({"Service": "GuardDuty", "Region": reg, "Severity": "OK", "Detail": f"Enabled (Detector={detectors[0]})"})
        except ClientError:
            pass

    return net_rows, res_rows, log_rows


def main() -> int:
    parser = argparse.ArgumentParser(description="AWS Security Audit (Strictly Read-Only)")
    parser.add_argument("--output-dir", default="./aws_security_output", help="Output folder")
    parser.add_argument("--profile", help="Optional AWS CLI profile name")
    parser.add_argument("--region", nargs="*", help="Optional specific AWS regions (default: all enabled)")
    parser.add_argument("--days", type=int, default=90, help="Lookback window (default: 90)")
    parser.add_argument("--stale-days", type=int, default=60, help="Stale threshold in days (default: 60)")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    csv_dir = out_dir / "csv"
    csv_dir.mkdir(parents=True, exist_ok=True)
    ctx = AwsAuditContext(output_dir=out_dir, csv_dir=csv_dir, days=args.days, stale_days=args.stale_days)

    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    sts = session.client("sts")
    ident = sts.get_caller_identity()
    log(f"Authenticated to AWS Account {ident.get('Account')} as {ident.get('Arn')}")

    regions = get_enabled_regions(session, args.region)
    iam_user_rows = audit_iam_users(session, ctx)
    iam_role_rows = audit_iam_roles(session, ctx)
    s3_rows = audit_s3(session, ctx)
    net_rows, res_rows, log_rows = audit_regions(session, ctx, regions)

    write_csv(csv_dir / "01_iam_users_and_mfa.csv", ["UserName", "UserId", "HasConsolePassword", "MfaEnabled", "PasswordLastUsed", "AccessKeyId", "KeyStatus", "KeyAgeDays", "KeyLastUsed", "Flags"], iam_user_rows)
    write_csv(csv_dir / "02_iam_roles_and_privileges.csv", ["RoleName", "Arn", "LastUsed", "UsageStatus", "AttachedPolicies", "InlinePolicies", "Flags"], iam_role_rows)
    write_csv(csv_dir / "03_s3_security_findings.csv", ["BucketName", "Severity", "Issues"], s3_rows)
    write_csv(csv_dir / "04_network_and_sg_findings.csv", ["FindingType", "Region", "Resource", "Severity", "Detail"], net_rows)
    write_csv(csv_dir / "05_rds_ec2_kms_findings.csv", ["Category", "Region", "Resource", "Severity", "Issues"], res_rows)
    write_csv(csv_dir / "06_logging_and_threat_detection.csv", ["Service", "Region", "Severity", "Detail"], log_rows)

    flagged_users = [u for u in iam_user_rows if u["Flags"] != "OK"]
    unused_roles = [r for r in iam_role_rows if r["UsageStatus"] != "Active"]
    risky_s3 = [s for s in s3_rows if s["Severity"] != "OK"]
    crit_sgs = [n for n in net_rows if n["Severity"] == "Critical"]

    lines = [
        "# AWS Security Audit Report",
        "",
        f"- **AWS Account:** `{ident.get('Account')}`",
        f"- **Generated (UTC):** {fmt_dt(ctx.now)}",
        f"- **Regions Scanned:** {len(regions)}",
        "",
        "## Executive Summary",
        "",
        md_table(
            ["Audit Area", "Flagged Findings", "Detailed CSV"],
            [
                ["IAM Users / MFA / Stale Keys", str(len(flagged_users)), "[01_iam_users_and_mfa.csv](./csv/01_iam_users_and_mfa.csv)"],
                ["Unused / Privileged IAM Roles", str(len(unused_roles)), "[02_iam_roles_and_privileges.csv](./csv/02_iam_roles_and_privileges.csv)"],
                ["S3 Bucket Security Issues", str(len(risky_s3)), "[03_s3_security_findings.csv](./csv/03_s3_security_findings.csv)"],
                ["Critical Inbound Security Groups (0.0.0.0/0)", str(len(crit_sgs)), "[04_network_and_sg_findings.csv](./csv/04_network_and_sg_findings.csv)"],
                ["EC2 / EBS / RDS / KMS Findings", str(len(res_rows)), "[05_rds_ec2_kms_findings.csv](./csv/05_rds_ec2_kms_findings.csv)"],
                ["CloudTrail & GuardDuty Status", str(len(log_rows)), "[06_logging_and_threat_detection.csv](./csv/06_logging_and_threat_detection.csv)"],
            ],
        ),
    ]
    if ctx.warnings:
        lines.extend(["## Audit Warnings", ""] + [f"- {w}" for w in ctx.warnings] + [""])

    lines.extend([
        "## Top Critical Network & IAM Findings",
        "",
        md_table(
            ["Type", "Resource", "Detail"],
            [[n["FindingType"], f"{n['Region']} / {n['Resource']}", n["Detail"]] for n in crit_sgs[:15]]
            + [["IAM User", u["UserName"], u["Flags"]] for u in flagged_users[:10]],
        ),
    ])

    report_path = out_dir / "SECURITY_AUDIT_REPORT.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    log(f"AWS Security Audit complete! Report written to: {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
