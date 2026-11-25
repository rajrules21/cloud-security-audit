#!/usr/bin/env python3
"""
Part 1: Azure Subscription & Resource Security Audit (run with your Azure account).

Collects across all accessible Azure subscriptions:
  - RBAC role assignments & role definitions
  - 90-day Azure control-plane Activity Logs (for unused-role detection)
  - Key Vault & Storage Account security posture
  - Public IPs & risky inbound NSG rules
  - Databases, App Services/Functions, ACR & AKS posture
  - Microsoft Defender for Cloud Secure Scores, Unhealthy Assessments, and Activity Log diagnostics

Writes CSVs to <output-dir>/csv/. If Entra ID CSVs from audit_entra.py are also
present in <output-dir>/csv/, automatically builds the comparative AUDIT_REPORT.md.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from audit_common import (
    ARM_BASE,
    PUBLIC_SOURCES,
    SENSITIVE_PORTS,
    AuditContext,
    AzureClients,
    append_warnings,
    fmt_dt,
    log,
    parse_iso_dt,
    try_build_comparative_report,
    write_csv,
)


def collect_subscriptions(
    clients: AzureClients, ctx: AuditContext, filter_subs: Optional[List[str]]
) -> List[Dict[str, Any]]:
    log("Discovering accessible Azure subscriptions...")
    subs, err = clients.arm_get_all(f"{ARM_BASE}/subscriptions?api-version=2022-12-01")
    if err:
        ctx.warn(f"Failed to list subscriptions: {err}")
        return []
    active = [s for s in subs if s.get("state") == "Enabled"]
    if filter_subs:
        wanted = {s.lower() for s in filter_subs}
        active = [s for s in active if s.get("subscriptionId", "").lower() in wanted]
    log(f"  Found {len(active)} enabled subscription(s) in scope.")
    return active


def collect_rbac_and_activity(
    clients: AzureClients,
    ctx: AuditContext,
    sub_ids: List[str],
    sub_name_by_id: Dict[str, str],
) -> None:
    log("Querying Azure RBAC role assignments and definitions via Resource Graph...")
    ra_query = """
    authorizationresources
    | where type == "microsoft.authorization/roleassignments"
    | project id, subscriptionId,
        principalId = tostring(properties.principalId),
        principalType = tostring(properties.principalType),
        roleDefinitionId = tostring(properties.roleDefinitionId),
        scope = tostring(properties.scope)
    """
    assignments, err = clients.resource_graph(ra_query, sub_ids)
    if err:
        ctx.warn(f"Failed to query RBAC role assignments: {err}")

    rd_query = """
    authorizationresources
    | where type == "microsoft.authorization/roledefinitions"
    | project id, roleName = tostring(properties.roleName)
    """
    defs, rd_err = clients.resource_graph(rd_query, sub_ids)
    if rd_err:
        ctx.warn(f"Failed to query RBAC role definitions: {rd_err}")

    role_name_by_id: Dict[str, str] = {}
    for d in defs:
        rid = (d.get("id") or "").lower()
        rname = d.get("roleName") or rid
        if rid:
            role_name_by_id[rid] = rname
            role_name_by_id[rid.split("/")[-1]] = rname

    raw_rbac_rows = []
    for ra in assignments:
        rdef_id = (ra.get("roleDefinitionId") or "").lower()
        rname = role_name_by_id.get(rdef_id) or role_name_by_id.get(rdef_id.split("/")[-1]) or rdef_id
        sid = ra.get("subscriptionId", "")
        raw_rbac_rows.append({
            "SubscriptionId": sid,
            "Subscription": sub_name_by_id.get(sid, sid),
            "Scope": ra.get("scope", ""),
            "RoleName": rname,
            "PrincipalType": ra.get("principalType", ""),
            "PrincipalId": ra.get("principalId", ""),
        })

    write_csv(
        ctx.csv_dir / "_raw_azure_rbac.csv",
        ["SubscriptionId", "Subscription", "Scope", "RoleName", "PrincipalType", "PrincipalId"],
        raw_rbac_rows,
    )
    log(f"  Saved {len(raw_rbac_rows)} RBAC role assignments.")

    lookback = min(ctx.days, 90)
    since_str = (ctx.now - dt.timedelta(days=lookback)).strftime("%Y-%m-%dT%H:%M:%SZ")
    log(f"Collecting Azure control-plane Activity Logs (last {lookback} days) across {len(sub_ids)} subscription(s)...")

    caller_activity: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"last_action": None, "action_count": 0}
    )
    for sub_id in sub_ids:
        url = (
            f"{ARM_BASE}/subscriptions/{sub_id}/providers/Microsoft.Insights/eventtypes/management/values"
            f"?api-version=2015-04-01&$filter=eventTimestamp ge '{since_str}'"
            f"&$select=caller,eventTimestamp"
        )
        events, a_err = clients.arm_get_all(url)
        if a_err:
            ctx.warn(f"Could not read Activity Logs for subscription {sub_id}: {a_err}")
            continue
        for ev in events:
            caller = (ev.get("caller") or "").strip().lower()
            if not caller:
                continue
            ts = parse_iso_dt(ev.get("eventTimestamp"))
            rec = caller_activity[caller]
            rec["action_count"] += 1
            if ts and (rec["last_action"] is None or ts > rec["last_action"]):
                rec["last_action"] = ts

    act_rows = [
        {"Caller": c, "LastAction": fmt_dt(v["last_action"]), "ActionCount": v["action_count"]}
        for c, v in caller_activity.items()
    ]
    write_csv(ctx.csv_dir / "_raw_azure_activity.csv", ["Caller", "LastAction", "ActionCount"], act_rows)
    log(f"  Saved {len(act_rows)} active Azure callers.")


def collect_resource_posture(clients: AzureClients, ctx: AuditContext, sub_ids: List[str]) -> None:
    log("Auditing Key Vaults and Storage Accounts...")
    kv_sa_rows: List[Dict[str, Any]] = []

    kvs, err = clients.resource_graph(
        """
        resources
        | where type == "microsoft.keyvault/vaults"
        | project subscriptionId, resourceGroup, name, location,
            publicNetworkAccess = tostring(properties.publicNetworkAccess),
            enableRbacAuthorization = tobool(properties.enableRbacAuthorization),
            enableSoftDelete = tobool(properties.enableSoftDelete),
            enablePurgeProtection = tobool(properties.enablePurgeProtection),
            defaultAction = tostring(properties.networkAcls.defaultAction)
        """,
        sub_ids,
    )
    if err:
        ctx.warn(f"Key Vault query failed: {err}")
    for kv in kvs:
        issues = []
        if kv.get("publicNetworkAccess", "Enabled") != "Disabled" and kv.get("defaultAction", "Allow") == "Allow":
            issues.append("Public network access unrestricted")
        if not kv.get("enableRbacAuthorization"):
            issues.append("Legacy Access Policies (RBAC not enabled)")
        if not kv.get("enablePurgeProtection"):
            issues.append("Purge Protection disabled")
        if not kv.get("enableSoftDelete", True):
            issues.append("Soft Delete disabled")
        kv_sa_rows.append({
            "ResourceType": "Key Vault",
            "SubscriptionId": kv.get("subscriptionId", ""),
            "ResourceGroup": kv.get("resourceGroup", ""),
            "Name": kv.get("name", ""),
            "Location": kv.get("location", ""),
            "Severity": "High" if issues else "OK",
            "Issues": "; ".join(issues) if issues else "Compliant",
            "Details": f"RBAC={kv.get('enableRbacAuthorization')}, PurgeProt={kv.get('enablePurgeProtection')}, NetDefault={kv.get('defaultAction')}",
        })

    sas, err = clients.resource_graph(
        """
        resources
        | where type == "microsoft.storage/storageaccounts"
        | project subscriptionId, resourceGroup, name, location,
            allowBlobPublicAccess = tobool(properties.allowBlobPublicAccess),
            allowSharedKeyAccess = properties.allowSharedKeyAccess,
            httpsOnly = tobool(properties.supportsHttpsTrafficOnly),
            minTls = tostring(properties.minimumTlsVersion),
            publicNetworkAccess = tostring(properties.publicNetworkAccess),
            defaultAction = tostring(properties.networkAcls.defaultAction)
        """,
        sub_ids,
    )
    if err:
        ctx.warn(f"Storage Account query failed: {err}")
    for sa in sas:
        issues = []
        if sa.get("allowBlobPublicAccess"):
            issues.append("Anonymous blob public access allowed")
        if sa.get("allowSharedKeyAccess") is not False:
            issues.append("Shared Key access enabled (prefer Entra ID auth)")
        if not sa.get("httpsOnly", True):
            issues.append("HTTPS-only disabled")
        if sa.get("minTls") not in ("TLS1_2", "TLS1_3"):
            issues.append(f"Minimum TLS is {sa.get('minTls') or 'unspecified'}")
        if sa.get("publicNetworkAccess", "Enabled") != "Disabled" and sa.get("defaultAction", "Allow") == "Allow":
            issues.append("Public network access open (defaultAction=Allow)")
        sev = "High" if sa.get("allowBlobPublicAccess") or not sa.get("httpsOnly", True) else ("Medium" if issues else "OK")
        kv_sa_rows.append({
            "ResourceType": "Storage Account",
            "SubscriptionId": sa.get("subscriptionId", ""),
            "ResourceGroup": sa.get("resourceGroup", ""),
            "Name": sa.get("name", ""),
            "Location": sa.get("location", ""),
            "Severity": sev,
            "Issues": "; ".join(issues) if issues else "Compliant",
            "Details": f"PublicBlob={sa.get('allowBlobPublicAccess')}, SharedKey={sa.get('allowSharedKeyAccess')}, TLS={sa.get('minTls')}",
        })

    write_csv(
        ctx.csv_dir / "07_keyvault_and_storage_findings.csv",
        ["ResourceType", "SubscriptionId", "ResourceGroup", "Name", "Location", "Severity", "Issues", "Details"],
        kv_sa_rows,
    )

    log("Auditing Public IPs and NSG inbound rules...")
    net_rows: List[Dict[str, Any]] = []
    pips, err = clients.resource_graph(
        """
        resources
        | where type == "microsoft.network/publicipaddresses"
        | project subscriptionId, resourceGroup, name,
            ipAddress = tostring(properties.ipAddress),
            attachedTo = tostring(properties.ipConfiguration.id)
        """,
        sub_ids,
    )
    if err:
        ctx.warn(f"Public IP query failed: {err}")
    for p in pips:
        net_rows.append({
            "FindingType": "Public IP",
            "SubscriptionId": p.get("subscriptionId", ""),
            "ResourceGroup": p.get("resourceGroup", ""),
            "ResourceName": p.get("name", ""),
            "Severity": "Info",
            "Detail": f"IP={p.get('ipAddress') or 'Dynamic/Unallocated'} | Attached={p.get('attachedTo') or 'Unattached'}",
        })

    nsgs, err = clients.resource_graph(
        """
        resources
        | where type == "microsoft.network/networksecuritygroups"
        | mv-expand rule = properties.securityRules
        | where tostring(rule.properties.direction) == "Inbound"
          and tostring(rule.properties.access) == "Allow"
        | project subscriptionId, resourceGroup, nsgName = name,
            ruleName = tostring(rule.name),
            priority = toint(rule.properties.priority),
            protocol = tostring(rule.properties.protocol),
            src = tostring(rule.properties.sourceAddressPrefix),
            srcs = tostring(rule.properties.sourceAddressPrefixes),
            dstPort = tostring(rule.properties.destinationPortRange),
            dstPorts = tostring(rule.properties.destinationPortRanges)
        """,
        sub_ids,
    )
    if err:
        ctx.warn(f"NSG query failed: {err}")
    for r in nsgs:
        src_combined = f"{r.get('src', '')} {r.get('srcs', '')}".lower()
        port_combined = f"{r.get('dstPort', '')} {r.get('dstPorts', '')}".lower()
        if any(p in src_combined for p in PUBLIC_SOURCES) and any(sp in port_combined for sp in SENSITIVE_PORTS):
            net_rows.append({
                "FindingType": "Risky Inbound NSG Rule",
                "SubscriptionId": r.get("subscriptionId", ""),
                "ResourceGroup": r.get("resourceGroup", ""),
                "ResourceName": f"{r.get('nsgName')} / {r.get('ruleName')}",
                "Severity": "Critical",
                "Detail": f"Priority={r.get('priority')} Source={r.get('src') or r.get('srcs')} -> Port={r.get('dstPort') or r.get('dstPorts')} ({r.get('protocol')})",
            })

    write_csv(
        ctx.csv_dir / "08_network_exposure_and_nsgs.csv",
        ["FindingType", "SubscriptionId", "ResourceGroup", "ResourceName", "Severity", "Detail"],
        net_rows,
    )

    log("Auditing Databases, App Services, ACR, and AKS...")
    compute_rows: List[Dict[str, Any]] = []
    dbs, err = clients.resource_graph(
        """
        resources
        | where type in~ ("microsoft.sql/servers", "microsoft.dbforpostgresql/flexibleservers", "microsoft.dbformysql/flexibleservers", "microsoft.documentdb/databaseaccounts")
        | project subscriptionId, resourceGroup, name, type,
            publicNetworkAccess = tostring(properties.publicNetworkAccess),
            entraOnly = tostring(properties.administrators.azureADOnlyAuthentication)
        """,
        sub_ids,
    )
    if err:
        ctx.warn(f"Database query failed: {err}")
    for db in dbs:
        issues = []
        if db.get("publicNetworkAccess", "Enabled") != "Disabled":
            issues.append("Public network access enabled")
        if db.get("type", "").lower() == "microsoft.sql/servers" and db.get("entraOnly") != "True":
            issues.append("SQL local auth enabled (Entra-only auth not enforced)")
        compute_rows.append({
            "Category": "Database",
            "ResourceType": db.get("type", ""),
            "SubscriptionId": db.get("subscriptionId", ""),
            "ResourceGroup": db.get("resourceGroup", ""),
            "Name": db.get("name", ""),
            "Severity": "High" if issues else "OK",
            "Issues": "; ".join(issues) if issues else "Compliant",
        })

    webapps, err = clients.resource_graph(
        """
        resources
        | where type == "microsoft.web/sites"
        | project subscriptionId, resourceGroup, name, kind,
            httpsOnly = tobool(properties.httpsOnly),
            minTls = tostring(properties.siteConfig.minTlsVersion),
            ftpsState = tostring(properties.siteConfig.ftpsState)
        """,
        sub_ids,
    )
    if err:
        ctx.warn(f"App Service query failed: {err}")
    for wa in webapps:
        issues = []
        if not wa.get("httpsOnly"):
            issues.append("HTTPS-only disabled")
        if wa.get("ftpsState") == "AllAllowed":
            issues.append("Unencrypted FTP allowed")
        if wa.get("minTls") and wa.get("minTls") not in ("1.2", "1.3"):
            issues.append(f"minTlsVersion={wa.get('minTls')}")
        compute_rows.append({
            "Category": "App Service / Function",
            "ResourceType": wa.get("kind", "web/sites"),
            "SubscriptionId": wa.get("subscriptionId", ""),
            "ResourceGroup": wa.get("resourceGroup", ""),
            "Name": wa.get("name", ""),
            "Severity": "Medium" if issues else "OK",
            "Issues": "; ".join(issues) if issues else "Compliant",
        })

    containers, err = clients.resource_graph(
        """
        resources
        | where type in~ ("microsoft.containerregistry/registries", "microsoft.containerservice/managedclusters")
        | project subscriptionId, resourceGroup, name, type,
            acrAdmin = tobool(properties.adminUserEnabled),
            publicNetworkAccess = tostring(properties.publicNetworkAccess),
            aksRbac = tobool(properties.enableRBAC),
            aksAad = tostring(properties.aadProfile.managed)
        """,
        sub_ids,
    )
    if err:
        ctx.warn(f"Container query failed: {err}")
    for c in containers:
        issues = []
        ctype = c.get("type", "").lower()
        if "containerregistry" in ctype:
            if c.get("acrAdmin"):
                issues.append("ACR Admin user enabled")
            if c.get("publicNetworkAccess", "Enabled") != "Disabled":
                issues.append("Public network access enabled")
        else:
            if not c.get("aksRbac"):
                issues.append("AKS RBAC disabled")
            if c.get("aksAad") != "True":
                issues.append("AKS Entra ID integration not managed")
        compute_rows.append({
            "Category": "Containers",
            "ResourceType": ctype,
            "SubscriptionId": c.get("subscriptionId", ""),
            "ResourceGroup": c.get("resourceGroup", ""),
            "Name": c.get("name", ""),
            "Severity": "High" if issues else "OK",
            "Issues": "; ".join(issues) if issues else "Compliant",
        })

    write_csv(
        ctx.csv_dir / "09_compute_db_and_paas_findings.csv",
        ["Category", "ResourceType", "SubscriptionId", "ResourceGroup", "Name", "Severity", "Issues"],
        compute_rows,
    )

    log("Collecting Defender for Cloud Secure Scores, Assessments, and Diagnostic Settings...")
    defender_rows: List[Dict[str, Any]] = []
    scores, err = clients.resource_graph(
        """
        securityresources
        | where type == "microsoft.security/securescores"
        | project subscriptionId, name,
            currentScore = todouble(properties.score.current),
            maxScore = todouble(properties.score.max),
            percentage = todouble(properties.score.percentage)
        """,
        sub_ids,
    )
    if err:
        ctx.warn(f"Defender Secure Score query failed: {err}")
    for s in scores:
        pct = round((s.get("percentage") or 0) * 100, 1)
        defender_rows.append({
            "RecordType": "Secure Score",
            "SubscriptionId": s.get("subscriptionId", ""),
            "Severity": "Info",
            "Title": f"Secure Score ({s.get('name')})",
            "Detail": f"{s.get('currentScore')}/{s.get('maxScore')} ({pct}%)",
        })

    assessments, err = clients.resource_graph(
        """
        securityresources
        | where type == "microsoft.security/assessments"
        | where tostring(properties.status.code) == "Unhealthy"
        | where tostring(properties.metadata.severity) in ("High", "Medium")
        | summarize AffectedResources = count() by subscriptionId,
            severity = tostring(properties.metadata.severity),
            displayName = tostring(properties.displayName)
        | order by severity asc, AffectedResources desc
        """,
        sub_ids,
    )
    if err:
        ctx.warn(f"Defender Assessments query failed: {err}")
    for a in assessments:
        defender_rows.append({
            "RecordType": "Defender Assessment",
            "SubscriptionId": a.get("subscriptionId", ""),
            "Severity": a.get("severity", ""),
            "Title": a.get("displayName", ""),
            "Detail": f"Unhealthy across {a.get('AffectedResources')} resource(s)",
        })

    for sub_id in sub_ids:
        diags, derr = clients.arm_get_all(
            f"{ARM_BASE}/subscriptions/{sub_id}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
        )
        if derr:
            ctx.warn(f"Could not check Activity Log diagnostic settings for {sub_id}: {derr}")
            continue
        if not diags:
            defender_rows.append({
                "RecordType": "Logging Gap",
                "SubscriptionId": sub_id,
                "Severity": "High",
                "Title": "Subscription Activity Log not exported",
                "Detail": "No Diagnostic Settings found forwarding Activity Logs",
            })
        else:
            defender_rows.append({
                "RecordType": "Logging Configured",
                "SubscriptionId": sub_id,
                "Severity": "OK",
                "Title": "Activity Log Diagnostic Settings present",
                "Detail": f"Settings: {', '.join(d.get('name', 'unnamed') for d in diags)}",
            })

    write_csv(
        ctx.csv_dir / "10_defender_scores_and_assessments.csv",
        ["RecordType", "SubscriptionId", "Severity", "Title", "Detail"],
        defender_rows,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Part 1: Azure Subscription & Resource Security Audit")
    parser.add_argument("--output-dir", default="./audit_output", help="Shared output folder (default: ./audit_output)")
    parser.add_argument("--days", type=int, default=90, help="Activity Log lookback window in days (default: 90)")
    parser.add_argument("--stale-days", type=int, default=60, help="Stale threshold in days (default: 60)")
    parser.add_argument("--subscription", nargs="*", help="Optional subscription IDs to audit (default: all)")
    parser.add_argument("--tenant-id", help="Optional Azure tenant ID")
    parser.add_argument("--interactive", action="store_true", help="Use interactive browser sign-in")
    parser.add_argument("--login-hint", help="Pre-fill a specific account email for interactive sign-in")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    csv_dir = out_dir / "csv"
    csv_dir.mkdir(parents=True, exist_ok=True)

    ctx = AuditContext(output_dir=out_dir, csv_dir=csv_dir, days=args.days, stale_days=args.stale_days)
    log(f"Starting Part 1 (Azure Audit) -> {out_dir}")
    clients = AzureClients(tenant_id=args.tenant_id, interactive=args.interactive, login_hint=args.login_hint)

    subs = collect_subscriptions(clients, ctx, args.subscription)
    sub_ids = [s["subscriptionId"] for s in subs]
    sub_name_by_id = {s["subscriptionId"]: s.get("displayName", s["subscriptionId"]) for s in subs}
    write_csv(
        csv_dir / "_raw_azure_subscriptions.csv",
        ["SubscriptionId", "DisplayName"],
        [{"SubscriptionId": s["subscriptionId"], "DisplayName": s.get("displayName", "")} for s in subs],
    )

    collect_rbac_and_activity(clients, ctx, sub_ids, sub_name_by_id)
    collect_resource_posture(clients, ctx, sub_ids)
    append_warnings(ctx)

    report = try_build_comparative_report(ctx)
    if report:
        log(f"Comparative report generated: {report}")
    else:
        log("Azure collection complete. Now run: python audit_entra.py --interactive (using your M365/Entra account) to complete the comparative audit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
