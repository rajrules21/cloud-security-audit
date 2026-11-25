#!/usr/bin/env python3
"""
Shared utilities, REST clients, CSV helpers, and comparative report builder
for the two-part Azure (audit_azure.py) and Entra ID / M365 (audit_entra.py) audit.
"""

from __future__ import annotations

import base64
import csv
import datetime as dt
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential

ARM_SCOPE = "https://management.azure.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

ARM_BASE = "https://management.azure.com"
GRAPH_V1 = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"

HIGH_PRIVILEGE_ROLES = {
    "owner",
    "contributor",
    "user access administrator",
    "role based access control administrator",
    "co-administrator",
    "service administrator",
}

SENSITIVE_PORTS = {"*", "22", "3389", "5985", "5986", "1433", "3306", "5432", "6379", "27017"}
PUBLIC_SOURCES = {"*", "0.0.0.0/0", "internet", "any"}


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_iso_dt(value: Optional[str]) -> Optional[dt.datetime]:
    if not value:
        return None
    try:
        cleaned = value.replace("Z", "+00:00")
        parsed = dt.datetime.fromisoformat(cleaned)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed
    except ValueError:
        return None


def days_ago(timestamp: Optional[dt.datetime], now: dt.datetime) -> Optional[int]:
    if not timestamp:
        return None
    return max(0, (now - timestamp).days)


def fmt_dt(timestamp: Optional[dt.datetime]) -> str:
    if not timestamp:
        return ""
    return timestamp.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def log(msg: str) -> None:
    print(f"[{dt.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


@dataclass
class AuditContext:
    output_dir: Path
    csv_dir: Path
    days: int
    stale_days: int
    now: dt.datetime = field(default_factory=utc_now)
    warnings: List[str] = field(default_factory=list)

    def warn(self, message: str) -> None:
        log(f"WARNING: {message}")
        self.warnings.append(message)


class AzureClients:
    """Thin, resilient REST client for ARM, Resource Graph, and Microsoft Graph."""

    def __init__(
        self,
        tenant_id: Optional[str] = None,
        interactive: bool = False,
        login_hint: Optional[str] = None,
    ) -> None:
        if interactive:
            kwargs: Dict[str, Any] = {}
            if tenant_id:
                kwargs["tenant_id"] = tenant_id
            if login_hint:
                kwargs["login_hint"] = login_hint
            self.credential = InteractiveBrowserCredential(**kwargs)
        else:
            kwargs = {"exclude_interactive_browser_credential": True}
            if tenant_id:
                kwargs["tenant_id"] = tenant_id
            self.credential = DefaultAzureCredential(**kwargs)

        self.session = requests.Session()
        self._tokens: Dict[str, Tuple[str, float]] = {}
        self._logged_identity: set[str] = set()

    def _log_token_identity(self, scope: str, jwt_token: str) -> None:
        if scope in self._logged_identity:
            return
        self._logged_identity.add(scope)
        try:
            payload_b64 = jwt_token.split(".")[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
            who = claims.get("upn") or claims.get("preferred_username") or claims.get("unique_name") or claims.get("appid") or "unknown"
            tid = claims.get("tid", "unknown")
            log(f"Authenticated for {scope.split('/')[2]} as: {who} (Tenant: {tid})")
        except Exception:
            pass

    def _get_token(self, scope: str) -> str:
        cached = self._tokens.get(scope)
        if cached and cached[1] > time.time() + 120:
            return cached[0]
        token = self.credential.get_token(scope)
        self._tokens[scope] = (token.token, float(token.expires_on))
        self._log_token_identity(scope, token.token)
        return token.token

    def request(
        self,
        method: str,
        url: str,
        scope: str,
        json_body: Optional[Dict[str, Any]] = None,
        timeout: int = 60,
    ) -> requests.Response:
        resp = None
        for attempt in range(5):
            headers = {
                "Authorization": f"Bearer {self._get_token(scope)}",
                "Content-Type": "application/json",
            }
            resp = self.session.request(
                method, url, headers=headers, json=json_body, timeout=timeout
            )
            if resp.status_code in (429, 502, 503, 504):
                retry_after = int(resp.headers.get("Retry-After", str(2 ** (attempt + 1))))
                time.sleep(min(retry_after, 30))
                continue
            return resp
        assert resp is not None
        return resp

    def graph_get_all(
        self, url: str, max_pages: Optional[int] = None
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        items: List[Dict[str, Any]] = []
        next_url: Optional[str] = url
        pages = 0
        while next_url:
            resp = self.request("GET", next_url, GRAPH_SCOPE)
            if resp.status_code >= 400:
                return items, f"HTTP {resp.status_code} on {next_url}: {resp.text[:250]}"
            data = resp.json()
            items.extend(data.get("value", []))
            next_url = data.get("@odata.nextLink")
            pages += 1
            if max_pages and pages >= max_pages:
                break
        return items, None

    def arm_get_all(self, url: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        items: List[Dict[str, Any]] = []
        next_url: Optional[str] = url
        while next_url:
            resp = self.request("GET", next_url, ARM_SCOPE)
            if resp.status_code >= 400:
                return items, f"HTTP {resp.status_code} on {next_url}: {resp.text[:250]}"
            data = resp.json()
            items.extend(data.get("value", []))
            next_url = data.get("nextLink")
        return items, None

    def resource_graph(
        self, query: str, subscription_ids: List[str]
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        if not subscription_ids:
            return [], None
        url = f"{ARM_BASE}/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
        rows: List[Dict[str, Any]] = []
        skip_token: Optional[str] = None
        while True:
            body: Dict[str, Any] = {
                "subscriptions": subscription_ids,
                "query": query,
                "options": {"resultFormat": "objectArray", "$top": 1000},
            }
            if skip_token:
                body["options"]["$skipToken"] = skip_token
            resp = self.request("POST", url, ARM_SCOPE, json_body=body, timeout=90)
            if resp.status_code >= 400:
                return rows, f"HTTP {resp.status_code} Resource Graph: {resp.text[:250]}"
            data = resp.json()
            rows.extend(data.get("data", []))
            skip_token = data.get("$skipToken")
            if not skip_token:
                break
        return rows, None


# ---------------------------------------------------------------------------
# CSV & Markdown Helpers
# ---------------------------------------------------------------------------

def write_csv(path: Path, fieldnames: List[str], rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def md_table(headers: List[str], rows: List[List[str]]) -> str:
    if not rows:
        return "_No findings in this category._\n"
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for r in rows:
        safe = [str(c).replace("|", "\\|").replace("\n", " ") for c in r]
        lines.append("| " + " | ".join(safe) + " |")
    return "\n".join(lines) + "\n"


def append_warnings(ctx: AuditContext) -> None:
    warn_file = ctx.csv_dir / "_audit_warnings.csv"
    existing = read_csv(warn_file)
    rows = existing + [{"Timestamp": fmt_dt(ctx.now), "Warning": w} for w in ctx.warnings]
    write_csv(warn_file, ["Timestamp", "Warning"], rows)


# ---------------------------------------------------------------------------
# Comparative Cross-Reference & Final Report Builder
# ---------------------------------------------------------------------------

def try_build_comparative_report(ctx: AuditContext) -> Optional[Path]:
    """
    If both Azure CSVs and Entra CSVs exist in ctx.csv_dir, perform the
    comparative RBAC <-> Entra ID cross-reference and generate AUDIT_REPORT.md.
    """
    raw_rbac_path = ctx.csv_dir / "_raw_azure_rbac.csv"
    raw_act_path = ctx.csv_dir / "_raw_azure_activity.csv"
    raw_users_path = ctx.csv_dir / "_raw_entra_users_index.csv"
    raw_sps_path = ctx.csv_dir / "_raw_entra_sps_index.csv"

    if not (raw_rbac_path.exists() and raw_users_path.exists()):
        return None

    log("Both Azure and Entra ID datasets found — running comparative cross-reference & building AUDIT_REPORT.md...")

    raw_rbac = read_csv(raw_rbac_path)
    raw_act = read_csv(raw_act_path)
    raw_users = read_csv(raw_users_path)
    raw_deleted = read_csv(ctx.csv_dir / "_raw_entra_deleted_users.csv")
    raw_sps = read_csv(raw_sps_path)
    raw_group_members = read_csv(ctx.csv_dir / "_raw_entra_group_members.csv")

    users_by_id = {u["Id"]: u for u in raw_users if u.get("Id")}
    deleted_by_id = {d["Id"]: d for d in raw_deleted if d.get("Id")}
    sp_by_id = {s["Id"]: s for s in raw_sps if s.get("Id")}

    group_members: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for gm in raw_group_members:
        if gm.get("GroupId"):
            group_members[gm["GroupId"]].append(gm)

    caller_activity: Dict[str, Dict[str, Any]] = {}
    for a in raw_act:
        caller = (a.get("Caller") or "").lower()
        if caller:
            caller_activity[caller] = {
                "last_action": a.get("LastAction", ""),
                "action_count": int(a.get("ActionCount") or 0),
            }

    orphaned_rows: List[Dict[str, Any]] = []
    all_rbac_rows: List[Dict[str, Any]] = []

    for ra in raw_rbac:
        pid = ra.get("PrincipalId", "")
        ptype = ra.get("PrincipalType", "")
        role_name = ra.get("RoleName", "")
        sub_name = ra.get("Subscription", "")
        scope = ra.get("Scope", "")
        is_priv = role_name.lower() in HIGH_PRIVILEGE_ROLES

        identity_status = "Active"
        display_name = ""
        upn_or_appid = ""
        entra_last_signin = ""

        if ptype == "User":
            if pid in users_by_id:
                u = users_by_id[pid]
                display_name = u.get("DisplayName", "")
                upn_or_appid = u.get("UPN", "")
                entra_last_signin = u.get("LastSignIn", "")
                last_si_dt = parse_iso_dt(entra_last_signin)
                si_age = days_ago(last_si_dt, ctx.now)
                if u.get("AccountEnabled") == "False":
                    identity_status = "Disabled User"
                elif u.get("UserType") == "Guest" or "#EXT#" in upn_or_appid:
                    identity_status = "Guest User"
                elif si_age is not None and si_age >= ctx.stale_days:
                    identity_status = f"Inactive User ({si_age}d)"
            elif pid in deleted_by_id:
                d = deleted_by_id[pid]
                display_name = d.get("DisplayName", "")
                upn_or_appid = d.get("UPN", "")
                identity_status = "Soft-Deleted User"
            else:
                identity_status = "Orphaned (Not Found in Entra ID)"

        elif ptype == "ServicePrincipal":
            if pid in sp_by_id:
                sp = sp_by_id[pid]
                display_name = sp.get("DisplayName", "")
                upn_or_appid = sp.get("AppId", "")
                if sp.get("AccountEnabled") == "False":
                    identity_status = "Disabled Service Principal"
            else:
                identity_status = "Orphaned Service Principal"

        elif ptype == "Group":
            display_name = f"Group ({pid})"
            for m in group_members.get(pid, []):
                m_upn = m.get("UPN", "")
                m_status = None
                if m.get("AccountEnabled") == "False":
                    m_status = "Disabled User (via Group)"
                elif m.get("UserType") == "Guest" or "#EXT#" in m_upn:
                    m_status = "Guest User (via Group)"
                if m_status:
                    orphaned_rows.append({
                        "Subscription": sub_name,
                        "Scope": scope,
                        "RoleName": role_name,
                        "PrivilegeTier": "High" if is_priv else "Standard",
                        "AssignmentType": f"Group ({pid})",
                        "PrincipalId": m.get("MemberId", ""),
                        "DisplayName": m.get("DisplayName", ""),
                        "UPN_or_AppId": m_upn,
                        "IdentityStatus": m_status,
                    })
        else:
            identity_status = f"Unknown/Foreign ({ptype})"

        if identity_status != "Active" and ptype != "Group":
            orphaned_rows.append({
                "Subscription": sub_name,
                "Scope": scope,
                "RoleName": role_name,
                "PrivilegeTier": "High" if is_priv else "Standard",
                "AssignmentType": ptype,
                "PrincipalId": pid,
                "DisplayName": display_name,
                "UPN_or_AppId": upn_or_appid,
                "IdentityStatus": identity_status,
            })

        act = caller_activity.get(upn_or_appid.lower()) or caller_activity.get(pid.lower())
        last_az_action = act["last_action"] if act else ""
        az_action_count = act["action_count"] if act else 0

        if act:
            usage_verdict = "Active in Azure"
        elif ptype == "Group":
            usage_verdict = "Group Assignment (Check Member Activity)"
        else:
            usage_verdict = f"Unused in Azure Activity Log (Last {min(ctx.days, 90)}d)"

        all_rbac_rows.append({
            "Subscription": sub_name,
            "Scope": scope,
            "RoleName": role_name,
            "PrivilegeTier": "High" if is_priv else "Standard",
            "PrincipalType": ptype,
            "PrincipalId": pid,
            "DisplayName": display_name,
            "UPN_or_AppId": upn_or_appid,
            "IdentityStatus": identity_status,
            "LastAzureActivity": last_az_action,
            "AzureActionCount": az_action_count,
            "LastEntraSignIn": entra_last_signin,
            "UsageVerdict": usage_verdict,
        })

    write_csv(
        ctx.csv_dir / "01_orphaned_and_disabled_rbac.csv",
        ["Subscription", "Scope", "RoleName", "PrivilegeTier", "AssignmentType", "PrincipalId", "DisplayName", "UPN_or_AppId", "IdentityStatus"],
        orphaned_rows,
    )
    write_csv(
        ctx.csv_dir / "02_unused_and_privileged_rbac.csv",
        ["Subscription", "Scope", "RoleName", "PrivilegeTier", "PrincipalType", "PrincipalId", "DisplayName", "UPN_or_AppId", "IdentityStatus", "LastAzureActivity", "AzureActionCount", "LastEntraSignIn", "UsageVerdict"],
        all_rbac_rows,
    )

    # Load other final CSVs for report summary
    entra_user_rows = read_csv(ctx.csv_dir / "03_entra_inactive_and_mfa_users.csv")
    dir_role_rows = read_csv(ctx.csv_dir / "04_entra_directory_roles.csv")
    entra_app_rows = read_csv(ctx.csv_dir / "05_entra_apps_and_usage.csv")
    ca_rows = read_csv(ctx.csv_dir / "06_conditional_access_policies.csv")
    kv_sa_rows = read_csv(ctx.csv_dir / "07_keyvault_and_storage_findings.csv")
    net_rows = read_csv(ctx.csv_dir / "08_network_exposure_and_nsgs.csv")
    compute_rows = read_csv(ctx.csv_dir / "09_compute_db_and_paas_findings.csv")
    defender_rows = read_csv(ctx.csv_dir / "10_defender_scores_and_assessments.csv")
    subs_rows = read_csv(ctx.csv_dir / "_raw_azure_subscriptions.csv")
    all_warnings = read_csv(ctx.csv_dir / "_audit_warnings.csv")

    unused_rbac = [r for r in all_rbac_rows if "Unused" in r["UsageVerdict"]]
    unused_priv_rbac = [r for r in unused_rbac if r["PrivilegeTier"] == "High"]
    unused_apps = [a for a in entra_app_rows if a.get("UsageStatus") != "Active"]
    risky_nsgs = [n for n in net_rows if n.get("Severity") == "Critical"]
    kv_sa_issues = [k for k in kv_sa_rows if k.get("Severity") != "OK"]
    compute_issues = [c for c in compute_rows if c.get("Severity") != "OK"]
    no_mfa_users = [u for u in entra_user_rows if u.get("MfaRegistered") == "False" and u.get("AccountEnabled") == "True"]

    lines: List[str] = [
        "# Azure & Microsoft Entra ID Security Audit Report",
        "",
        f"- **Generated (UTC):** {fmt_dt(ctx.now)}",
        f"- **Activity / Sign-In Lookback Window:** {ctx.days} days (Stale threshold: {ctx.stale_days} days)",
        f"- **Subscriptions Audited:** {len(subs_rows)}",
        "",
        "## Executive Summary",
        "",
        md_table(
            ["Audit Area", "Key Finding Count", "Detailed CSV"],
            [
                ["Orphaned / Disabled / Guest RBAC Holders", str(len(orphaned_rows)), "[01_orphaned_and_disabled_rbac.csv](./csv/01_orphaned_and_disabled_rbac.csv)"],
                ["Unused RBAC Role Assignments (Total / High-Priv)", f"{len(unused_rbac)} / {len(unused_priv_rbac)}", "[02_unused_and_privileged_rbac.csv](./csv/02_unused_and_privileged_rbac.csv)"],
                ["Entra Users (Disabled, Deleted, Stale, No MFA)", f"{len(entra_user_rows)} flagged ({len(no_mfa_users)} active w/o MFA)", "[03_entra_inactive_and_mfa_users.csv](./csv/03_entra_inactive_and_mfa_users.csv)"],
                ["Privileged Entra ID Directory Role Members", str(len(dir_role_rows)), "[04_entra_directory_roles.csv](./csv/04_entra_directory_roles.csv)"],
                ["Entra Apps Unused or Stale (of Total Audited)", f"{len(unused_apps)} / {len(entra_app_rows)}", "[05_entra_apps_and_usage.csv](./csv/05_entra_apps_and_usage.csv)"],
                ["Conditional Access Policies", str(len(ca_rows)), "[06_conditional_access_policies.csv](./csv/06_conditional_access_policies.csv)"],
                ["Key Vault & Storage Account Findings", str(len(kv_sa_issues)), "[07_keyvault_and_storage_findings.csv](./csv/07_keyvault_and_storage_findings.csv)"],
                ["Critical Inbound NSG Rules (0.0.0.0/0)", str(len(risky_nsgs)), "[08_network_exposure_and_nsgs.csv](./csv/08_network_exposure_and_nsgs.csv)"],
                ["Database / App Service / Container Findings", str(len(compute_issues)), "[09_compute_db_and_paas_findings.csv](./csv/09_compute_db_and_paas_findings.csv)"],
                ["Defender for Cloud & Logging Gaps", str(len(defender_rows)), "[10_defender_scores_and_assessments.csv](./csv/10_defender_scores_and_assessments.csv)"],
            ],
        ),
    ]

    if all_warnings:
        lines.extend(["## Audit Coverage & Permission Warnings", ""])
        for w in all_warnings:
            lines.append(f"- {w.get('Warning', '')}")
        lines.append("")

    lines.extend([
        "## 1. Accounts Not in Company / Disabled / Deleted Holding Azure Roles (Top 25)",
        "",
        "Full dataset: [01_orphaned_and_disabled_rbac.csv](./csv/01_orphaned_and_disabled_rbac.csv)",
        "",
        md_table(
            ["Subscription", "Role", "Display Name", "UPN / AppId", "Status", "Scope"],
            [
                [r["Subscription"], r["RoleName"], r["DisplayName"], r["UPN_or_AppId"], r["IdentityStatus"], r["Scope"]]
                for r in orphaned_rows[:25]
            ],
        ),
        "## 2. Unused High-Privilege RBAC Assignments (Top 25)",
        "",
        "Full dataset: [02_unused_and_privileged_rbac.csv](./csv/02_unused_and_privileged_rbac.csv)",
        "",
        md_table(
            ["Subscription", "Role", "Principal", "Type", "Identity Status", "Last Entra Sign-In"],
            [
                [r["Subscription"], r["RoleName"], r["DisplayName"] or r["UPN_or_AppId"], r["PrincipalType"], r["IdentityStatus"], r["LastEntraSignIn"] or "Unknown"]
                for r in unused_priv_rbac[:25]
            ],
        ),
        "## 3. Entra ID Apps Usage, Active Users & Stale Apps (Top 25)",
        "",
        "Full dataset: [05_entra_apps_and_usage.csv](./csv/05_entra_apps_and_usage.csv)",
        "",
        md_table(
            ["App Name", "Usage Status", "Last Used", "Sign-Ins", "Active Users (Sample)", "Owners"],
            [
                [a.get("DisplayName", ""), a.get("UsageStatus", ""), a.get("LastUsedDate") or "Never / Outside Window", a.get("SignInCount", "0"), a.get("ActiveUsers", "")[:80], a.get("Owners", "")[:60]]
                for a in entra_app_rows[:25]
            ],
        ),
        "## 4. Critical Network Exposure & Key Vault / Storage Findings (Top 25)",
        "",
        "- Network & NSGs: [08_network_exposure_and_nsgs.csv](./csv/08_network_exposure_and_nsgs.csv)",
        "- Key Vault & Storage: [07_keyvault_and_storage_findings.csv](./csv/07_keyvault_and_storage_findings.csv)",
        "",
        md_table(
            ["Category", "Resource", "Severity", "Details / Issues"],
            [
                [n.get("FindingType", ""), n.get("ResourceName", ""), n.get("Severity", ""), n.get("Detail", "")]
                for n in risky_nsgs[:15]
            ] + [
                [k.get("ResourceType", ""), k.get("Name", ""), k.get("Severity", ""), k.get("Issues", "")]
                for k in kv_sa_issues[:10]
            ],
        ),
    ])

    report_path = ctx.output_dir / "AUDIT_REPORT.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path
