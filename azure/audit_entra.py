#!/usr/bin/env python3
"""
Part 2: Microsoft Entra ID / M365 Security Audit (run with your M365/Entra account).

Collects from Microsoft Graph:
  - Entra ID users (active, disabled, guests, signInActivity) & soft-deleted users
  - MFA registration status
  - Entra ID Directory Roles & members
  - Conditional Access policies
  - App Registrations & Enterprise Apps (Service Principals) + Sign-in logs (last used, active user names, calling apps, owners, expiring secrets/certs)
  - Transitive members of any Entra Groups holding Azure RBAC roles (when _raw_azure_rbac.csv exists)

Writes CSVs to <output-dir>/csv/. If Azure CSVs from audit_azure.py are also
present in <output-dir>/csv/, automatically builds the comparative AUDIT_REPORT.md.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set

from audit_common import (
    GRAPH_BETA,
    GRAPH_V1,
    AuditContext,
    AzureClients,
    append_warnings,
    days_ago,
    fmt_dt,
    log,
    parse_iso_dt,
    read_csv,
    try_build_comparative_report,
    write_csv,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Part 2: Microsoft Entra ID / M365 Security Audit")
    parser.add_argument("--output-dir", default="./audit_output", help="Shared output folder (default: ./audit_output)")
    parser.add_argument("--days", type=int, default=90, help="Sign-in lookback window in days (default: 90)")
    parser.add_argument("--stale-days", type=int, default=60, help="Stale threshold in days (default: 60)")
    parser.add_argument("--tenant-id", help="Optional Entra ID tenant ID")
    parser.add_argument("--interactive", action="store_true", help="Use interactive browser sign-in")
    parser.add_argument("--max-signin-pages", type=int, default=20, help="Max Entra sign-in log pages to fetch (default: 20)")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    csv_dir = out_dir / "csv"
    csv_dir.mkdir(parents=True, exist_ok=True)

    ctx = AuditContext(output_dir=out_dir, csv_dir=csv_dir, days=args.days, stale_days=args.stale_days)
    log(f"Starting Part 2 (Entra ID / M365 Audit) -> {out_dir}")
    clients = AzureClients(tenant_id=args.tenant_id, interactive=args.interactive)

    # 1. Users & Soft-Deleted Users
    log("Collecting Entra ID users and soft-deleted users...")
    users_list, err = clients.graph_get_all(
        f"{GRAPH_V1}/users?$select=id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime,signInActivity&$top=999"
    )
    if err and ("403" in err or "400" in err or "signInActivity" in err or "Authentication_MSGraph" in err):
        ctx.warn("Could not read user signInActivity (requires Entra ID P1/P2 + AuditLog.Read.All). Falling back without last-sign-in.")
        users_list, err = clients.graph_get_all(
            f"{GRAPH_V1}/users?$select=id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime&$top=999"
        )
    if err:
        ctx.warn(f"Failed to list Entra ID users: {err}")

    deleted_list, del_err = clients.graph_get_all(
        f"{GRAPH_V1}/directory/deletedItems/microsoft.graph.user?$select=id,displayName,userPrincipalName,deletedDateTime&$top=999"
    )
    if del_err:
        ctx.warn(f"Could not list soft-deleted users: {del_err}")

    # 2. MFA Registration
    log("Collecting MFA registration details...")
    mfa_items, mfa_err = clients.graph_get_all(f"{GRAPH_V1}/reports/authenticationMethods/userRegistrationDetails?$top=999")
    if mfa_err:
        ctx.warn(f"Could not fetch MFA registration details: {mfa_err}")
    mfa_by_id = {m["id"]: m for m in mfa_items if m.get("id")}

    users_index_rows = []
    entra_user_rows = []
    for u in users_list:
        uid = u.get("id", "")
        upn = u.get("userPrincipalName", "")
        signin_info = u.get("signInActivity") or {}
        last_si = parse_iso_dt(signin_info.get("lastSignInDateTime") or signin_info.get("lastNonInteractiveSignInDateTime"))
        si_age = days_ago(last_si, ctx.now)
        mfa_reg = mfa_by_id.get(uid, {}).get("isMfaRegistered")

        users_index_rows.append({
            "Id": uid,
            "DisplayName": u.get("displayName", ""),
            "UPN": upn,
            "AccountEnabled": u.get("accountEnabled", True),
            "UserType": u.get("userType", ""),
            "LastSignIn": fmt_dt(last_si),
        })

        flags = []
        if not u.get("accountEnabled", True):
            flags.append("Disabled")
        if u.get("userType") == "Guest" or "#EXT#" in upn:
            flags.append("Guest")
        if si_age is not None and si_age >= ctx.stale_days:
            flags.append(f"Inactive ({si_age}d)")
        if mfa_reg is False and u.get("accountEnabled", True):
            flags.append("No MFA Registered")
        if flags:
            entra_user_rows.append({
                "UserId": uid,
                "DisplayName": u.get("displayName", ""),
                "UserPrincipalName": upn,
                "AccountEnabled": u.get("accountEnabled", True),
                "UserType": u.get("userType", ""),
                "LastSignIn": fmt_dt(last_si),
                "MfaRegistered": mfa_reg,
                "Flags": "; ".join(flags),
            })

    deleted_index_rows = []
    for d in deleted_list:
        did = d.get("id", "")
        deleted_index_rows.append({
            "Id": did,
            "DisplayName": d.get("displayName", ""),
            "UPN": d.get("userPrincipalName", ""),
            "DeletedDateTime": d.get("deletedDateTime", ""),
        })
        entra_user_rows.append({
            "UserId": did,
            "DisplayName": d.get("displayName", ""),
            "UserPrincipalName": d.get("userPrincipalName", ""),
            "AccountEnabled": False,
            "UserType": "SoftDeleted",
            "LastSignIn": "",
            "MfaRegistered": "",
            "Flags": f"Soft-Deleted ({d.get('deletedDateTime', '')})",
        })

    write_csv(csv_dir / "_raw_entra_users_index.csv", ["Id", "DisplayName", "UPN", "AccountEnabled", "UserType", "LastSignIn"], users_index_rows)
    write_csv(csv_dir / "_raw_entra_deleted_users.csv", ["Id", "DisplayName", "UPN", "DeletedDateTime"], deleted_index_rows)
    write_csv(csv_dir / "03_entra_inactive_and_mfa_users.csv", ["UserId", "DisplayName", "UserPrincipalName", "AccountEnabled", "UserType", "LastSignIn", "MfaRegistered", "Flags"], entra_user_rows)

    # 3. Directory Roles
    log("Collecting Entra ID directory roles...")
    dir_roles, dr_err = clients.graph_get_all(f"{GRAPH_V1}/directoryRoles?$expand=members")
    if dr_err:
        ctx.warn(f"Could not fetch Entra directory roles: {dr_err}")
    dir_role_rows = [
        {
            "RoleName": role.get("displayName", ""),
            "MemberType": m.get("@odata.type", "").split(".")[-1],
            "MemberId": m.get("id", ""),
            "DisplayName": m.get("displayName", ""),
            "UPN": m.get("userPrincipalName", ""),
            "AccountEnabled": m.get("accountEnabled", ""),
        }
        for role in dir_roles
        for m in role.get("members", [])
    ]
    write_csv(csv_dir / "04_entra_directory_roles.csv", ["RoleName", "MemberType", "MemberId", "DisplayName", "UPN", "AccountEnabled"], dir_role_rows)

    # 4. Conditional Access
    log("Collecting Conditional Access policies...")
    ca_policies, ca_err = clients.graph_get_all(f"{GRAPH_V1}/identity/conditionalAccess/policies")
    if ca_err:
        ctx.warn(f"Could not fetch Conditional Access policies: {ca_err}")
    ca_rows = [
        {
            "Name": p.get("displayName", ""),
            "State": p.get("state", ""),
            "IncludeUsers": str((p.get("conditions") or {}).get("users", {}).get("includeUsers", [])),
            "ExcludeUsers": str((p.get("conditions") or {}).get("users", {}).get("excludeUsers", [])),
            "GrantControls": str((p.get("grantControls") or {}).get("builtInControls", [])),
        }
        for p in ca_policies
    ]
    write_csv(csv_dir / "06_conditional_access_policies.csv", ["Name", "State", "IncludeUsers", "ExcludeUsers", "GrantControls"], ca_rows)

    # 5. Entra Apps, Service Principals & Sign-In Logs
    log("Collecting App Registrations, Service Principals, and Sign-in Logs...")
    apps, app_err = clients.graph_get_all(
        f"{GRAPH_V1}/applications?$select=id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials&$top=999"
    )
    if app_err:
        ctx.warn(f"Could not list App Registrations: {app_err}")

    sps, sp_err = clients.graph_get_all(
        f"{GRAPH_V1}/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,createdDateTime,passwordCredentials,keyCredentials,tags&$top=999"
    )
    if sp_err:
        ctx.warn(f"Could not list Service Principals: {sp_err}")

    write_csv(
        csv_dir / "_raw_entra_sps_index.csv",
        ["Id", "AppId", "DisplayName", "AccountEnabled"],
        [{"Id": s.get("id", ""), "AppId": s.get("appId", ""), "DisplayName": s.get("displayName", ""), "AccountEnabled": s.get("accountEnabled", True)} for s in sps],
    )

    since_str = (ctx.now - dt.timedelta(days=ctx.days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    signins, si_err = clients.graph_get_all(
        f"{GRAPH_V1}/auditLogs/signIns?$filter=createdDateTime ge {since_str}&$top=500",
        max_pages=args.max_signin_pages,
    )
    if si_err:
        ctx.warn(f"Could not read Entra signIn logs (requires Entra ID P1/P2 + AuditLog.Read.All): {si_err}")

    sp_signins, _ = clients.graph_get_all(
        f"{GRAPH_BETA}/auditLogs/signIns?$filter=createdDateTime ge {since_str} and signInEventTypes/any(t: t eq 'servicePrincipal')&$top=500",
        max_pages=min(10, args.max_signin_pages),
    )

    app_usage: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"last_signin": None, "signin_count": 0, "users": set(), "client_apps": set(), "calling_sps": set()}
    )
    for s in signins:
        app_id = s.get("appId")
        if not app_id:
            continue
        ts = parse_iso_dt(s.get("createdDateTime"))
        entry = app_usage[app_id]
        entry["signin_count"] += 1
        if ts and (entry["last_signin"] is None or ts > entry["last_signin"]):
            entry["last_signin"] = ts
        uname, upn = s.get("userDisplayName") or "", s.get("userPrincipalName") or ""
        if uname or upn:
            entry["users"].add(f"{uname} ({upn})".strip())
        if s.get("clientAppUsed"):
            entry["client_apps"].add(s["clientAppUsed"])

    for s in sp_signins:
        app_id = s.get("appId")
        if not app_id:
            continue
        ts = parse_iso_dt(s.get("createdDateTime"))
        entry = app_usage[app_id]
        entry["signin_count"] += 1
        if ts and (entry["last_signin"] is None or ts > entry["last_signin"]):
            entry["last_signin"] = ts
        sp_name = s.get("servicePrincipalName") or s.get("servicePrincipalId")
        if sp_name:
            entry["calling_sps"].add(sp_name)

    app_by_appid = {a["appId"]: a for a in apps if a.get("appId")}
    entra_app_rows: List[Dict[str, Any]] = []
    seen_appids: Set[str] = set()

    for sp in sps:
        app_id = sp.get("appId", "")
        sp_id = sp.get("id", "")
        is_reg = app_id in app_by_appid
        is_mi = sp.get("servicePrincipalType") == "ManagedIdentity"
        usage = app_usage.get(app_id)
        if not is_reg and not is_mi and not usage and "WindowsAzureActiveDirectoryIntegratedApp" not in (sp.get("tags") or []):
            continue

        seen_appids.add(app_id)
        reg = app_by_appid.get(app_id, {})
        owner_labels, assigned_labels = [], []
        if is_reg or "WindowsAzureActiveDirectoryIntegratedApp" in (sp.get("tags") or []):
            owners, o_err = clients.graph_get_all(f"{GRAPH_V1}/servicePrincipals/{sp_id}/owners?$select=id,displayName,userPrincipalName,accountEnabled")
            if not o_err:
                for o in owners:
                    st = " [DISABLED]" if o.get("accountEnabled") is False else ""
                    owner_labels.append(f"{o.get('displayName', '')} ({o.get('userPrincipalName', o.get('id', ''))}){st}")
            assigned, a_err = clients.graph_get_all(f"{GRAPH_V1}/servicePrincipals/{sp_id}/appRoleAssignedTo?$top=100")
            if not a_err:
                for a in assigned:
                    assigned_labels.append(f"{a.get('principalDisplayName') or a.get('principalId', '')} [{a.get('principalType', '')}]")

        last_si = usage["last_signin"] if usage else None
        age_days = days_ago(last_si, ctx.now)
        if not usage:
            usage_status = f"No Sign-Ins Recorded (Last {ctx.days}d)"
        elif age_days is not None and age_days >= ctx.stale_days:
            usage_status = f"Stale ({age_days}d since last use)"
        else:
            usage_status = "Active"

        cred_issues: List[str] = []
        for cred in (reg.get("passwordCredentials") or []) + (sp.get("passwordCredentials") or []):
            end_dt = parse_iso_dt(cred.get("endDateTime"))
            if end_dt:
                if end_dt < ctx.now:
                    cred_issues.append("Expired Secret")
                elif (end_dt - ctx.now).days <= 30:
                    cred_issues.append("Secret Expiring <30d")
        for cert in (reg.get("keyCredentials") or []) + (sp.get("keyCredentials") or []):
            end_dt = parse_iso_dt(cert.get("endDateTime"))
            if end_dt:
                if end_dt < ctx.now:
                    cred_issues.append("Expired Cert")
                elif (end_dt - ctx.now).days <= 30:
                    cred_issues.append("Cert Expiring <30d")

        active_users_str = "; ".join(sorted(usage["users"])[:25]) if usage and usage["users"] else ""
        if usage and len(usage["users"]) > 25:
            active_users_str += f" (+{len(usage['users']) - 25} more)"

        entra_app_rows.append({
            "DisplayName": sp.get("displayName", ""),
            "AppId": app_id,
            "ServicePrincipalId": sp_id,
            "Type": sp.get("servicePrincipalType", ""),
            "RegisteredInTenant": "Yes" if is_reg else "No",
            "Enabled": sp.get("accountEnabled", True),
            "CreatedDate": sp.get("createdDateTime", ""),
            "LastUsedDate": fmt_dt(last_si),
            "DaysSinceLastUse": age_days if age_days is not None else "",
            "SignInCount": usage["signin_count"] if usage else 0,
            "UsageStatus": usage_status,
            "ActiveUsers": active_users_str,
            "CallingAppsOrClients": "; ".join(sorted((usage["client_apps"] | usage["calling_sps"]))[:15]) if usage else "",
            "AssignedUsersAndGroups": "; ".join(assigned_labels[:25]),
            "Owners": "; ".join(owner_labels) if owner_labels else "No Owner / Orphaned",
            "CredentialAlerts": "; ".join(sorted(set(cred_issues))),
        })

    for app in apps:
        if app.get("appId") not in seen_appids:
            entra_app_rows.append({
                "DisplayName": app.get("displayName", ""),
                "AppId": app.get("appId", ""),
                "ServicePrincipalId": "",
                "Type": "AppRegistrationOnly (No SP)",
                "RegisteredInTenant": "Yes",
                "Enabled": "N/A",
                "CreatedDate": app.get("createdDateTime", ""),
                "LastUsedDate": "",
                "DaysSinceLastUse": "",
                "SignInCount": 0,
                "UsageStatus": "Unused (No Service Principal)",
                "ActiveUsers": "",
                "CallingAppsOrClients": "",
                "AssignedUsersAndGroups": "",
                "Owners": "",
                "CredentialAlerts": "",
            })

    write_csv(
        csv_dir / "05_entra_apps_and_usage.csv",
        ["DisplayName", "AppId", "ServicePrincipalId", "Type", "RegisteredInTenant", "Enabled", "CreatedDate", "LastUsedDate", "DaysSinceLastUse", "SignInCount", "UsageStatus", "ActiveUsers", "CallingAppsOrClients", "AssignedUsersAndGroups", "Owners", "CredentialAlerts"],
        entra_app_rows,
    )

    # 6. Resolve Entra Group members for any groups holding Azure RBAC roles
    raw_rbac = read_csv(csv_dir / "_raw_azure_rbac.csv")
    group_ids = {r["PrincipalId"] for r in raw_rbac if r.get("PrincipalType") == "Group" and r.get("PrincipalId")}
    group_member_rows = []
    if group_ids:
        log(f"Resolving transitive members for {len(group_ids)} Entra group(s) holding Azure RBAC roles...")
        for gid in group_ids:
            members, g_err = clients.graph_get_all(
                f"{GRAPH_V1}/groups/{gid}/transitiveMembers?$select=id,displayName,userPrincipalName,accountEnabled,userType"
            )
            if g_err:
                ctx.warn(f"Could not resolve members for group {gid}: {g_err}")
                continue
            for m in members:
                group_member_rows.append({
                    "GroupId": gid,
                    "MemberId": m.get("id", ""),
                    "DisplayName": m.get("displayName", ""),
                    "UPN": m.get("userPrincipalName", ""),
                    "AccountEnabled": m.get("accountEnabled", ""),
                    "UserType": m.get("userType", ""),
                })
    write_csv(csv_dir / "_raw_entra_group_members.csv", ["GroupId", "MemberId", "DisplayName", "UPN", "AccountEnabled", "UserType"], group_member_rows)

    append_warnings(ctx)

    report = try_build_comparative_report(ctx)
    if report:
        log(f"Comparative report generated: {report}")
    else:
        log("Entra ID collection complete. Now run: python audit_azure.py --interactive (using your Azure account) to complete the comparative audit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
