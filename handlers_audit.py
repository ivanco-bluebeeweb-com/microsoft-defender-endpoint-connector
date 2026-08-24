"""Estate-wide health audit for Defender for Endpoint."""
from __future__ import annotations

import defender_client as dc
from imperal_sdk import ActionResult

from app import ext, chat
from handlers_connection import _resolve_connection, _get_token
from schemas import NoParams, ConnectionRefParams, EstateAudit


@chat.function("audit_estate", "Build one aggregated health report across the connected Defender for Endpoint tenant: machine counts by health/isolation state, open/high-severity alerts, and critical CVE exposure.", action_type="read", chain_callable=True, data_model=EstateAudit, event="microsoft-defender-endpoint-connector.audit_estate")
async def audit_estate(ctx, params: ConnectionRefParams) -> ActionResult:
    """Build one aggregated health report across the connected Defender for Endpoint tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return ActionResult.error("No Microsoft Defender for Endpoint tenant is connected yet.")
    token = await _get_token(ctx, conn)
    try:
        machines_resp = await dc.api_get(ctx, token, "/machines", params={"$top": 500})
        machines = machines_resp.get("value", []) if isinstance(machines_resp, dict) else []
        alerts_resp = await dc.api_get(ctx, token, "/alerts", params={"$top": 500, "$filter": "status eq 'New' or status eq 'InProgress'"})
        alerts = alerts_resp.get("value", []) if isinstance(alerts_resp, dict) else []

        total = len(machines)
        active = sum(1 for m in machines if m.get("healthStatus") == "Active")
        isolated = sum(1 for m in machines if m.get("isolationState") not in (None, "", "Unisolated"))
        stale = sum(1 for m in machines if m.get("healthStatus") == "Inactive")
        open_alerts = len(alerts)
        high_sev = sum(1 for a in alerts if a.get("severity") in ("High", "Critical"))

        crit_cves = 0
        try:
            vuln_resp = await dc.api_get(ctx, token, "/vulnerabilities", params={"$top": 200, "$filter": "severity eq 'Critical'"})
            crit_cves = len(vuln_resp.get("value", [])) if isinstance(vuln_resp, dict) else 0
        except dc.ClientFail:
            pass  # TVM may not be licensed/scoped -- do not fail the whole audit for it

        summary = (
            f"{total} machines ({active} active, {isolated} isolated, {stale} stale); "
            f"{open_alerts} open alerts ({high_sev} high/critical); {crit_cves} critical CVE(s) exposed."
        )
        return ActionResult.success(
            data=EstateAudit(
                total_machines=total, active_machines=active, isolated_machines=isolated,
                stale_machines=stale, open_alerts=open_alerts, high_severity_alerts=high_sev,
                critical_cves_exposed=crit_cves, summary=summary,
            ),
            summary=summary,
        )
    except dc.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))
