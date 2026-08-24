"""Alerts (Defender's core triage stream) management: list/get/update
(status, classification, determination, assignment).
"""
from __future__ import annotations

import defender_client as dc
from imperal_sdk import ActionResult

from app import ext, chat
from handlers_connection import _resolve_connection, _get_token
from schemas import (
    ListAlertsParams, AlertIdParams, UpdateAlertParams,
    DefenderAlert, AlertList,
)


def _no_conn() -> ActionResult:
    return ActionResult.error("No Microsoft Defender for Endpoint tenant is connected yet.")


def _to_alert(d: dict) -> DefenderAlert:
    return DefenderAlert(
        alert_id=d.get("id", ""),
        title=d.get("title", ""),
        severity=d.get("severity", ""),
        status=d.get("status", ""),
        category=d.get("category", ""),
        machine_id=d.get("machineId", ""),
        created=d.get("alertCreationTime", ""),
    )


@chat.function("list_alerts", "List Alerts in the connected Defender for Endpoint tenant, optionally filtered by an OData $filter (e.g. \"severity eq 'High'\").", action_type="read", chain_callable=True, data_model=AlertList, event="microsoft-defender-endpoint-connector.list_alerts")
async def list_alerts(ctx, params: ListAlertsParams) -> ActionResult:
    """List Alerts in the connected Defender for Endpoint tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        query: dict = {"$top": params.limit}
        if params.filter_expr:
            query["$filter"] = params.filter_expr
        resp = await dc.api_get(ctx, token, "/alerts", params=query)
        items = resp.get("value", []) if isinstance(resp, dict) else []
        out = AlertList(alerts=[_to_alert(d) for d in items])
        return ActionResult.success(data=out, summary=f"Found {len(out.alerts)} alert(s).")
    except dc.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("get_alert", "Read one Alert in full by its Defender alert id.", action_type="read", chain_callable=True, data_model=DefenderAlert, event="microsoft-defender-endpoint-connector.get_alert")
async def get_alert(ctx, params: AlertIdParams) -> ActionResult:
    """Read one Alert in full by its Defender alert id."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        d = await dc.api_get(ctx, token, f"/alerts/{params.alert_id}")
        return ActionResult.success(data=_to_alert(d), summary=f"Alert '{d.get('title', params.alert_id)}'.")
    except dc.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("update_alert", "Update an Alert's status, classification, determination, and/or assignment.", action_type="write", chain_callable=True, data_model=DefenderAlert, event="microsoft-defender-endpoint-connector.update_alert", effects=["defender.alert.updated"])
async def update_alert(ctx, params: UpdateAlertParams) -> ActionResult:
    """Update an Alert's status, classification, determination, and/or assignment."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    body: dict = {}
    if params.status:
        body["status"] = params.status
    if params.classification:
        body["classification"] = params.classification
    if params.determination:
        body["determination"] = params.determination
    if params.assigned_to:
        body["assignedTo"] = params.assigned_to
    if params.comment:
        body["comment"] = params.comment
    try:
        d = await dc.api_patch(ctx, token, f"/alerts/{params.alert_id}", json=body)
        return ActionResult.success(data=_to_alert(d), summary=f"Alert '{params.alert_id}' updated.")
    except dc.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))
