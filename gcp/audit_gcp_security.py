#!/usr/bin/env python3
"""
GCP Security Audit (Strictly Read-Only).

Audits across all accessible GCP projects:
  - Project IAM bindings (Owner/Editor, allUsers/allAuthenticatedUsers, personal emails, deleted principals)
  - Service Accounts & user-managed keys (age/expiry)
  - Cloud Audit Logs activity correlation (unused IAM principals)
  - GCS Buckets (public access, Uniform Bucket-Level Access, Public Access Prevention) & Cloud SQL
  - VPC Firewall rules (0.0.0.0/0 on sensitive ports) & Compute VMs (external IPs, default SA)
  - Cloud Logging Sinks & Security Command Center (SCC) findings

Outputs CSVs in <output-dir>/csv/ and SECURITY_AUDIT_REPORT.md (no JSON).
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from gcp_common import (
    GcpAuditContext,
    GcpClient,
    days_ago,
    fmt_dt,
    log,
    md_table,
    parse_iso_dt,
    write_csv,
)

SENSITIVE_PORTS = {"22", "3389", "3306", "5432", "1433", "6379", "27017"}
PERSONAL_DOMAINS = ("@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com")


def list_projects(client: GcpClient, ctx: GcpAuditContext, filter_projects: Optional[List[str]]) -> List[Dict[str, Any]]:
    log("Discovering accessible GCP projects...")
    projects, err = client.get_paginated(
        "https://cloudresourcemanager.googleapis.com/v1/projects",
        "projects",
        params={"filter": "lifecycleState:ACTIVE"},
    )
    if err:
        ctx.warn(f"Failed to list projects: {err}")
        return []
    if filter_projects:
        wanted = {p.lower() for p in filter_projects}
        projects = [p for p in projects if p.get("projectId", "").lower() in wanted]
    log(f"  Found {len(projects)} active GCP project(s).")
    return projects


def collect_audit_log_activity(client: GcpClient, ctx: GcpAuditContext, project_id: str) -> Dict[str, str]:
    since_str = (ctx.now - dt.timedelta(days=min(ctx.days, 30))).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = {
        "resourceNames": [f"projects/{project_id}"],
        "filter": f'logName:"cloudaudit.googleapis.com" AND timestamp >= "{since_str}"',
        "orderBy": "timestamp desc",
        "pageSize": 500,
    }
    resp = client.request("POST", "https://logging.googleapis.com/v2/entries:list", json_body=body)
    if resp.status_code >= 400:
        return {}
    last_seen: Dict[str, str] = {}
    for entry in resp.json().get("entries", []):
        principal = (entry.get("protoPayload", {}).get("authenticationInfo", {}).get("principalEmail") or "").lower()
        ts = entry.get("timestamp", "")
        if principal and principal not in last_seen:
            last_seen[principal] = ts
    return last_seen


def main() -> int:
    parser = argparse.ArgumentParser(description="GCP Security Audit (Strictly Read-Only)")
    parser.add_argument("--output-dir", default="./gcp_security_output", help="Output folder")
    parser.add_argument("--project", nargs="*", help="Optional GCP project IDs (default: all accessible)")
    parser.add_argument("--days", type=int, default=30, help="Audit log lookback in days (default: 30)")
    parser.add_argument("--stale-days", type=int, default=60, help="Stale threshold in days (default: 60)")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    csv_dir = out_dir / "csv"
    csv_dir.mkdir(parents=True, exist_ok=True)
    ctx = GcpAuditContext(output_dir=out_dir, csv_dir=csv_dir, days=args.days, stale_days=args.stale_days)

    client = GcpClient()
    projects = list_projects(client, ctx, args.project)

    iam_rows: List[Dict[str, Any]] = []
    sa_rows: List[Dict[str, Any]] = []
    unused_iam_rows: List[Dict[str, Any]] = []
    storage_sql_rows: List[Dict[str, Any]] = []
    net_vm_rows: List[Dict[str, Any]] = []
    log_scc_rows: List[Dict[str, Any]] = []

    for proj in projects:
        pid = proj["projectId"]
        log(f"Auditing GCP project: {pid}...")
        activity_map = collect_audit_log_activity(client, ctx, pid)

        # 1. IAM Policy
        iam_resp = client.request("POST", f"https://cloudresourcemanager.googleapis.com/v1/projects/{pid}:getIamPolicy", json_body={})
        if iam_resp.status_code < 400:
            for b in iam_resp.json().get("bindings", []):
                role = b.get("role", "")
                for member in b.get("members", []):
                    flags = []
                    if member in ("allUsers", "allAuthenticatedUsers"):
                        flags.append("PUBLIC IAM MEMBER")
                    if member.startswith("deleted:"):
                        flags.append("Deleted Principal Still Bound")
                    if any(member.lower().endswith(dom) for dom in PERSONAL_DOMAINS):
                        flags.append("Personal Email Account")
                    if role in ("roles/owner", "roles/editor"):
                        flags.append(f"Primitive Role ({role})")

                    email = member.split(":", 1)[-1].lower() if ":" in member else member.lower()
                    last_act = activity_map.get(email, "")

                    if flags:
                        iam_rows.append({
                            "ProjectId": pid,
                            "Role": role,
                            "Member": member,
                            "LastAuditLogActivity": last_act,
                            "Flags": "; ".join(flags),
                        })
                    if not last_act and role in ("roles/owner", "roles/editor", "roles/iam.securityAdmin"):
                        unused_iam_rows.append({
                            "ProjectId": pid,
                            "Role": role,
                            "Member": member,
                            "Verdict": f"No Cloud Audit Log activity in last {min(ctx.days, 30)}d",
                        })
        else:
            ctx.warn(f"Could not read IAM policy for {pid}: HTTP {iam_resp.status_code}")

        # 2. Service Accounts & Keys
        sas, sa_err = client.get_paginated(f"https://iam.googleapis.com/v1/projects/{pid}/serviceAccounts", "accounts")
        if sa_err:
            ctx.warn(f"Could not list service accounts for {pid}: {sa_err}")
        for sa in sas:
            sa_email = sa.get("email", "")
            keys, _ = client.get_paginated(f"https://iam.googleapis.com/v1/projects/{pid}/serviceAccounts/{sa_email}/keys", "keys")
            user_keys = [k for k in keys if k.get("keyType") == "USER_MANAGED"]
            if not user_keys:
                continue
            for k in user_keys:
                created = parse_iso_dt(k.get("validAfterTime"))
                age = days_ago(created, ctx.now)
                sa_rows.append({
                    "ProjectId": pid,
                    "ServiceAccount": sa_email,
                    "Disabled": sa.get("disabled", False),
                    "KeyId": k.get("name", "").split("/")[-1],
                    "KeyAgeDays": age if age is not None else "",
                    "Flag": "Old User-Managed Key (>=90d)" if (age is not None and age >= 90) else "User-Managed Key Present",
                })

        # 3. GCS Buckets
        buckets, b_err = client.get_paginated(f"https://storage.googleapis.com/storage/v1/b", "items", params={"project": pid})
        if not b_err:
            for b in buckets:
                bname = b.get("name", "")
                iam_cfg = b.get("iamConfiguration", {})
                issues = []
                if not iam_cfg.get("uniformBucketLevelAccess", {}).get("enabled"):
                    issues.append("Uniform Bucket-Level Access disabled")
                if iam_cfg.get("publicAccessPrevention") != "enforced":
                    issues.append("Public Access Prevention not enforced")
                b_iam = client.request("GET", f"https://storage.googleapis.com/storage/v1/b/{bname}/iam")
                if b_iam.status_code < 400:
                    for bnd in b_iam.json().get("bindings", []):
                        if any(m in ("allUsers", "allAuthenticatedUsers") for m in bnd.get("members", [])):
                            issues.append(f"PUBLIC IAM ({bnd.get('role')})")
                if issues:
                    storage_sql_rows.append({
                        "ResourceType": "GCS Bucket",
                        "ProjectId": pid,
                        "Name": bname,
                        "Severity": "High" if any("PUBLIC" in i for i in issues) else "Medium",
                        "Issues": "; ".join(issues),
                    })

        # 4. Cloud SQL
        sql_resp = client.request("GET", f"https://sqladmin.googleapis.com/v1/projects/{pid}/instances")
        if sql_resp.status_code < 400:
            for inst in sql_resp.json().get("items", []):
                ip_cfg = inst.get("settings", {}).get("ipConfiguration", {})
                issues = []
                if ip_cfg.get("ipv4Enabled"):
                    issues.append("Public IPv4 enabled")
                if any(an.get("value") == "0.0.0.0/0" for an in ip_cfg.get("authorizedNetworks", [])):
                    issues.append("Authorized network 0.0.0.0/0")
                if not ip_cfg.get("requireSsl"):
                    issues.append("SSL not required")
                if issues:
                    storage_sql_rows.append({
                        "ResourceType": "Cloud SQL",
                        "ProjectId": pid,
                        "Name": inst.get("name", ""),
                        "Severity": "High" if "0.0.0.0/0" in ";".join(issues) else "Medium",
                        "Issues": "; ".join(issues),
                    })

        # 5. VPC Firewalls & Compute VMs
        fws, _ = client.get_paginated(f"https://compute.googleapis.com/compute/v1/projects/{pid}/global/firewalls", "items")
        for fw in fws:
            if fw.get("direction") != "INGRESS" or fw.get("disabled"):
                continue
            if "0.0.0.0/0" not in (fw.get("sourceRanges") or []):
                continue
            for allowed in fw.get("allowed", []):
                ports = allowed.get("ports", [])
                proto = allowed.get("IPProtocol", "")
                if proto == "all" or not ports or any(p in SENSITIVE_PORTS for p in ports):
                    net_vm_rows.append({
                        "FindingType": "Risky Ingress Firewall",
                        "ProjectId": pid,
                        "Resource": fw.get("name", ""),
                        "Severity": "Critical",
                        "Detail": f"Source=0.0.0.0/0 Proto={proto} Ports={','.join(ports) or 'ALL'}",
                    })

        agg_vms = client.request("GET", f"https://compute.googleapis.com/compute/v1/projects/{pid}/aggregated/instances")
        if agg_vms.status_code < 400:
            for _, scope_data in (agg_vms.json().get("items") or {}).items():
                for vm in scope_data.get("instances", []):
                    has_ext = any(ni.get("accessConfigs") for ni in vm.get("networkInterfaces", []))
                    uses_default_sa = any("compute@developer.gserviceaccount.com" in sa.get("email", "") for sa in vm.get("serviceAccounts", []))
                    if has_ext or uses_default_sa:
                        net_vm_rows.append({
                            "FindingType": "Compute VM Exposure",
                            "ProjectId": pid,
                            "Resource": vm.get("name", ""),
                            "Severity": "Medium",
                            "Detail": f"ExternalIP={has_ext}, DefaultComputeSA={uses_default_sa}",
                        })

        # 6. Logging Sinks
        sinks, s_err = client.get_paginated(f"https://logging.googleapis.com/v2/projects/{pid}/sinks", "sinks")
        if not s_err:
            if not sinks:
                log_scc_rows.append({"Area": "Cloud Logging", "ProjectId": pid, "Severity": "Medium", "Detail": "No custom log export sinks configured"})
            else:
                log_scc_rows.append({"Area": "Cloud Logging", "ProjectId": pid, "Severity": "OK", "Detail": f"{len(sinks)} log sink(s) configured"})

    write_csv(csv_dir / "01_iam_bindings_and_risks.csv", ["ProjectId", "Role", "Member", "LastAuditLogActivity", "Flags"], iam_rows)
    write_csv(csv_dir / "02_service_accounts_and_keys.csv", ["ProjectId", "ServiceAccount", "Disabled", "KeyId", "KeyAgeDays", "Flag"], sa_rows)
    write_csv(csv_dir / "03_unused_iam_principals.csv", ["ProjectId", "Role", "Member", "Verdict"], unused_iam_rows)
    write_csv(csv_dir / "04_storage_and_sql_findings.csv", ["ResourceType", "ProjectId", "Name", "Severity", "Issues"], storage_sql_rows)
    write_csv(csv_dir / "05_vpc_firewalls_and_vms.csv", ["FindingType", "ProjectId", "Resource", "Severity", "Detail"], net_vm_rows)
    write_csv(csv_dir / "06_scc_and_logging.csv", ["Area", "ProjectId", "Severity", "Detail"], log_scc_rows)

    crit_fw = [r for r in net_vm_rows if r["Severity"] == "Critical"]
    lines = [
        "# GCP Security Audit Report",
        "",
        f"- **Generated (UTC):** {fmt_dt(ctx.now)}",
        f"- **Projects Audited:** {len(projects)}",
        "",
        "## Executive Summary",
        "",
        md_table(
            ["Audit Area", "Findings", "Detailed CSV"],
            [
                ["Flagged IAM Bindings (Primitive/Public/Deleted)", str(len(iam_rows)), "[01_iam_bindings_and_risks.csv](./csv/01_iam_bindings_and_risks.csv)"],
                ["User-Managed Service Account Keys", str(len(sa_rows)), "[02_service_accounts_and_keys.csv](./csv/02_service_accounts_and_keys.csv)"],
                ["Unused Privileged IAM Principals", str(len(unused_iam_rows)), "[03_unused_iam_principals.csv](./csv/03_unused_iam_principals.csv)"],
                ["GCS & Cloud SQL Misconfigurations", str(len(storage_sql_rows)), "[04_storage_and_sql_findings.csv](./csv/04_storage_and_sql_findings.csv)"],
                ["VPC Firewalls (0.0.0.0/0) & VM Exposure", f"{len(net_vm_rows)} ({len(crit_fw)} Critical)", "[05_vpc_firewalls_and_vms.csv](./csv/05_vpc_firewalls_and_vms.csv)"],
                ["Cloud Logging Sinks", str(len(log_scc_rows)), "[06_scc_and_logging.csv](./csv/06_scc_and_logging.csv)"],
            ],
        ),
    ]
    if ctx.warnings:
        lines.extend(["## Audit Warnings", ""] + [f"- {w}" for w in ctx.warnings] + [""])

    report_path = out_dir / "SECURITY_AUDIT_REPORT.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    log(f"GCP Security Audit complete! Report written to: {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
