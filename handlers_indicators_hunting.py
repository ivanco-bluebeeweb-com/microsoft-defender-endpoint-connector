"""Custom Indicators (IOCs) -- fleet-wide detection/block rules for hashes,
IPs, domains, and URLs -- plus Advanced Hunting (KQL) and Threat &
Vulnerability Management (CVE exposure).
"""
from __future__ import annotations

import defender_client as dc
from imperal_sdk import ActionResult

from app import ext, chat
from handlers_connection import _resolve_connection, _get_token
from schemas import (
    ListIndicatorsParams, CreateIndicatorParams, IndicatorIdParams,
    RunHuntingQueryParams, ListVulnerabilitiesParams,
    DefenderIndicator, IndicatorList, DeleteResult,
    HuntingResult, Vulnerability, VulnerabilityList,
)


def _no_conn() -> ActionResult:
    return ActionResult.error("No Microsoft Defender for Endpoint tenant is connected yet.")


def _to_indicator(d: dict) -> DefenderIndicator:
    return DefenderIndicator(
        indicator_id=str(d.get("id", "")),
        indicator_type=d.get("indicatorType", ""),
        indicator_value=d.get("indicatorValue", ""),
        action=d.get("action", ""),
        title=d.get("title", ""),
        severity=d.get("severity", ""),
    )


@chat.function("list_indicators", "List custom Indicators (IOCs) configured on the connected Defender for Endpoint tenant.", action_type="read", chain_callable=True, data_model=IndicatorList, event="microsoft-defender-endpoint-connector.list_indicators")
async def list_indicators(ctx, params: ListIndicatorsParams) -> ActionResult:
    """List custom Indicators (IOCs) configured on the connected Defender for Endpoint tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        resp = await dc.api_get(ctx, token, "/indicators", params={"$top": params.limit})
        items = resp.get("value", []) if isinstance(resp, dict) else []
        out = IndicatorList(indicators=[_to_indicator(d) for d in items])
        return ActionResult.success(data=out, summary=f"Found {len(out.indicators)} indicator(s).")
    except dc.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("create_indicator", "Create a custom Indicator (IOC) on the connected Defender for Endpoint tenant to flag or block a hash, IP, domain, or URL fleet-wide.", action_type="write", chain_callable=True, data_model=DefenderIndicator, event="microsoft-defender-endpoint-connector.create_indicator", effects=["defender.indicator.created"])
async def create_indicator(ctx, params: CreateIndicatorParams) -> ActionResult:
    """Create a custom Indicator (IOC) on the connected Defender for Endpoint tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        body = {
            "indicatorType": params.indicator_type,
            "indicatorValue": params.indicator_value,
            "action": params.action,
            "title": params.title,
            "description": params.description or params.title,
            "severity": params.severity,
        }
        resp = await dc.api_post(ctx, token, "/indicators", json=body)
        return ActionResult.success(data=_to_indicator(resp or {}), summary=f"Created indicator '{params.title}'.")
    except dc.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("delete_indicator", "Delete a custom Indicator (IOC) from the connected Defender for Endpoint tenant.", action_type="destructive", chain_callable=True, data_model=DeleteResult, event="microsoft-defender-endpoint-connector.delete_indicator", effects=["defender.indicator.deleted"])
async def delete_indicator(ctx, params: IndicatorIdParams) -> ActionResult:
    """Delete a custom Indicator (IOC) from the connected Defender for Endpoint tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        await dc.api_delete(ctx, token, f"/indicators/{params.indicator_id}")
        return ActionResult.success(data=DeleteResult(ok=True, detail="Indicator deleted."), summary="Indicator deleted.")
    except dc.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("run_hunting_query", "Run an Advanced Hunting KQL query against the connected Defender for Endpoint tenant (e.g. \"DeviceProcessEvents | take 10\"). Read-only investigation.", action_type="read", chain_callable=True, data_model=HuntingResult, event="microsoft-defender-endpoint-connector.run_hunting_query")
async def run_hunting_query(ctx, params: RunHuntingQueryParams) -> ActionResult:
    """Run an Advanced Hunting KQL query against the connected Defender for Endpoint tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        resp = await dc.api_post(ctx, token, "/advancedhunting/run", json={"Query": params.query})
        cols = [c.get("Name", "") for c in resp.get("Schema", [])] if isinstance(resp, dict) else []
        rows = resp.get("Results", []) if isinstance(resp, dict) else []
        out = HuntingResult(columns=cols, rows=rows, row_count=len(rows))
        return ActionResult.success(data=out, summary=f"Hunting query returned {out.row_count} row(s).")
    except dc.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("list_vulnerabilities", "List CVEs (Threat & Vulnerability Management) exposed across the fleet or on one machine.", action_type="read", chain_callable=True, data_model=VulnerabilityList, event="microsoft-defender-endpoint-connector.list_vulnerabilities")
async def list_vulnerabilities(ctx, params: ListVulnerabilitiesParams) -> ActionResult:
    """List CVEs (Threat & Vulnerability Management) exposed across the fleet or on one machine."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        if params.machine_id:
            resp = await dc.api_get(ctx, token, f"/machines/{params.machine_id}/vulnerabilities", params={"$top": params.limit})
        else:
            resp = await dc.api_get(ctx, token, "/vulnerabilities", params={"$top": params.limit})
        items = resp.get("value", []) if isinstance(resp, dict) else []
        vulns = [
            Vulnerability(
                cve_id=d.get("id", ""), severity=d.get("severity", ""),
                cvss_score=float(d.get("cvssV3", 0) or 0), machine_id=params.machine_id,
                software_name=d.get("name", ""), software_vendor=d.get("vendor", ""),
            )
            for d in items
        ]
        out = VulnerabilityList(vulnerabilities=vulns)
        return ActionResult.success(data=out, summary=f"Found {len(out.vulnerabilities)} CVE(s).")
    except dc.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))
