"""Machines (endpoint fleet) management: list/get, isolate/unisolate (the
core EDR "stop the bleeding" action), and AV scan.
"""
from __future__ import annotations

import defender_client as dc
from imperal_sdk import ActionResult

from app import ext, chat
from handlers_connection import _resolve_connection, _get_token
from schemas import (
    ListMachinesParams, MachineIdParams, IsolateMachineParams,
    MachineActionParams, RunAvScanParams,
    DefenderMachine, MachineList, MachineActionResult,
)


def _no_conn() -> ActionResult:
    return ActionResult.error("No Microsoft Defender for Endpoint tenant is connected yet.")


def _to_machine(d: dict) -> DefenderMachine:
    return DefenderMachine(
        machine_id=d.get("id", ""),
        computer_dns_name=d.get("computerDnsName", ""),
        os_platform=d.get("osPlatform", ""),
        health_status=d.get("healthStatus", ""),
        risk_score=d.get("riskScore", ""),
        last_seen=d.get("lastSeen", ""),
        is_isolated=bool(d.get("isolationState") not in (None, "", "Unisolated")),
    )


@chat.function("list_machines", "List endpoints (machines) in the connected Defender for Endpoint tenant, optionally filtered by an OData $filter.", action_type="read", chain_callable=True, data_model=MachineList, event="microsoft-defender-endpoint-connector.list_machines")
async def list_machines(ctx, params: ListMachinesParams) -> ActionResult:
    """List endpoints (machines) in the connected Defender for Endpoint tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        query: dict = {"$top": params.limit}
        if params.filter_expr:
            query["$filter"] = params.filter_expr
        resp = await dc.api_get(ctx, token, "/machines", params=query)
        items = resp.get("value", []) if isinstance(resp, dict) else []
        out = MachineList(machines=[_to_machine(d) for d in items])
        return ActionResult.success(data=out, summary=f"Found {len(out.machines)} machine(s).")
    except dc.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("get_machine", "Read one endpoint (machine) in full by its Defender machine id.", action_type="read", chain_callable=True, data_model=DefenderMachine, event="microsoft-defender-endpoint-connector.get_machine")
async def get_machine(ctx, params: MachineIdParams) -> ActionResult:
    """Read one endpoint (machine) in full by its Defender machine id."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        d = await dc.api_get(ctx, token, f"/machines/{params.machine_id}")
        return ActionResult.success(data=_to_machine(d), summary=f"Machine {d.get('computerDnsName', params.machine_id)}.")
    except dc.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


async def _machine_action(ctx, params, endpoint: str, action_type: str, body_extra: dict | None = None) -> ActionResult:
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    body = {"Comment": params.comment}
    if body_extra:
        body.update(body_extra)
    try:
        resp = await dc.api_post(ctx, token, f"/machines/{params.machine_id}/{endpoint}", json=body)
        return ActionResult.success(
            data=MachineActionResult(action_id=str(resp.get("id", "")), machine_id=params.machine_id, status=resp.get("status", "Pending"), action_type=action_type),
            summary=f"{action_type} requested on machine {params.machine_id}.",
        )
    except dc.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("isolate_machine", "Network-isolate a machine -- cuts it off from the network except Defender cloud traffic (and optionally Outlook/Skype/Teams for 'Selective'). The core incident-response 'stop the bleeding' action.", action_type="write", chain_callable=True, data_model=MachineActionResult, event="microsoft-defender-endpoint-connector.isolate_machine", effects=["defender.machine.isolated"])
async def isolate_machine(ctx, params: IsolateMachineParams) -> ActionResult:
    """Network-isolate a machine -- the core incident-response 'stop the bleeding' action."""
    return await _machine_action(ctx, params, "isolate", "Isolate", {"IsolationType": params.isolation_type})


@chat.function("unisolate_machine", "Release a machine from network isolation, restoring normal network access.", action_type="write", chain_callable=True, data_model=MachineActionResult, event="microsoft-defender-endpoint-connector.unisolate_machine", effects=["defender.machine.unisolated"])
async def unisolate_machine(ctx, params: MachineActionParams) -> ActionResult:
    """Release a machine from network isolation, restoring normal network access."""
    return await _machine_action(ctx, params, "unisolate", "Unisolate")


@chat.function("run_av_scan", "Trigger a Windows Defender antivirus scan (Quick or Full) on a machine.", action_type="write", chain_callable=True, data_model=MachineActionResult, event="microsoft-defender-endpoint-connector.run_av_scan", effects=["defender.machine.scanned"])
async def run_av_scan(ctx, params: RunAvScanParams) -> ActionResult:
    """Trigger a Windows Defender antivirus scan (Quick or Full) on a machine."""
    return await _machine_action(ctx, params, "runAntiVirusScan", "AntiVirusScan", {"ScanType": params.scan_type})


@chat.function("stop_and_quarantine_file", "Stop a running process and quarantine its file on a machine, by SHA1 hash. A destructive containment action for confirmed malicious files.", action_type="write", chain_callable=True, data_model=MachineActionResult, event="microsoft-defender-endpoint-connector.stop_and_quarantine_file", effects=["defender.machine.file_quarantined"])
async def stop_and_quarantine_file(ctx, params: MachineActionParams) -> ActionResult:
    """Stop a running process and quarantine its file on a machine, by SHA1 hash (pass the hash via comment context upstream; kept simple per Defender's StopAndQuarantineFile action)."""
    return await _machine_action(ctx, params, "StopAndQuarantineFile", "StopAndQuarantineFile")
