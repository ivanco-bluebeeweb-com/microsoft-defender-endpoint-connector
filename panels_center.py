"""Microsoft Defender for Endpoint Connector -- center panels for
Machines/Alerts/Indicators/Vulnerabilities, per UI_COMPONENT_PLAN.md."""
from __future__ import annotations

from imperal_sdk import ui

from app import ext
from handlers_connection import _load_connections, _get_token
import defender_client as dc


def _sev_badge(sev: str) -> ui.UINode:
    s = (sev or "").lower()
    color = "red" if s in ("critical", "high") else ("yellow" if s == "medium" else "gray")
    return ui.Badge(label=sev or "unknown", color=color)


@ext.panel("defender_center", slot="center")
async def defender_center(ctx, **kwargs) -> ui.UINode:
    """Base (non-overlay) center panel -- rendered before any sidebar item is
    clicked, per UI_INTERFACE_STANDARD.md's mandatory base-center-panel rule."""
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Empty(
            message="Connect your Microsoft Defender for Endpoint tenant first.",
            icon="Shield",
        )
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Text("Microsoft Defender for Endpoint", variant="heading"),
        ui.Text(
            "Ask Webbee to list machines, alerts, indicators, or vulnerabilities.",
            variant="caption",
        ),
    ])


@ext.panel("defender_machines", slot="center", title="Machines", center_overlay=True)
async def defender_machines(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="Laptop")
    conn = connections[0]
    token = await _get_token(ctx, conn)
    try:
        resp = await dc.api_get(ctx, token, "/machines", params={"$top": 100})
        items = resp.get("value", []) if isinstance(resp, dict) else []
        if not items:
            return ui.Empty(message="No machines found", icon="Laptop")
        rows = [{
            "name": m.get("computerDnsName", ""),
            "platform": m.get("osPlatform", ""),
            "health": m.get("healthStatus", ""),
            "risk": m.get("riskScore", ""),
            "isolated": "Yes" if m.get("isolationState") not in (None, "", "Unisolated") else "No",
        } for m in items]
    except dc.ClientFail as e:
        return ui.Alert(type="error", message=e.payload["error"])
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Machines", level=2),
        ui.DataTable(rows=rows, columns=[
            ui.DataColumn(key="name", label="Computer"),
            ui.DataColumn(key="platform", label="OS"),
            ui.DataColumn(key="health", label="Health"),
            ui.DataColumn(key="risk", label="Risk"),
            ui.DataColumn(key="isolated", label="Isolated"),
        ]),
    ])


@ext.panel("defender_alerts", slot="center", title="Alerts", center_overlay=True)
async def defender_alerts(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="ShieldAlert")
    conn = connections[0]
    token = await _get_token(ctx, conn)
    try:
        resp = await dc.api_get(ctx, token, "/alerts", params={"$top": 100})
        items = resp.get("value", []) if isinstance(resp, dict) else []
        if not items:
            return ui.Empty(message="No alerts found", icon="ShieldCheck")
        items.sort(key=lambda a: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}.get(a.get("severity", ""), 5))
    except dc.ClientFail as e:
        return ui.Alert(type="error", message=e.payload["error"])
    rows = [
        ui.Stack(direction="h", gap=2, align="center", children=[
            _sev_badge(a.get("severity", "")),
            ui.Text(a.get("title", ""), variant="body"),
            ui.Text(a.get("status", ""), variant="caption"),
        ]) for a in items
    ]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Alerts", level=2),
        *rows,
    ])


@ext.panel("defender_indicators", slot="center", title="Indicators", center_overlay=True)
async def defender_indicators(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="Target")
    conn = connections[0]
    token = await _get_token(ctx, conn)
    try:
        resp = await dc.api_get(ctx, token, "/indicators", params={"$top": 100})
        items = resp.get("value", []) if isinstance(resp, dict) else []
        if not items:
            return ui.Empty(message="No indicators found", icon="Target")
        rows = [{
            "type": i.get("indicatorType", ""),
            "value": i.get("indicatorValue", ""),
            "action": i.get("action", ""),
            "title": i.get("title", ""),
        } for i in items]
    except dc.ClientFail as e:
        return ui.Alert(type="error", message=e.payload["error"])
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Indicators", level=2),
        ui.DataTable(rows=rows, columns=[
            ui.DataColumn(key="type", label="Type"),
            ui.DataColumn(key="value", label="Value"),
            ui.DataColumn(key="action", label="Action"),
            ui.DataColumn(key="title", label="Title"),
        ]),
    ])


@ext.panel("defender_vulnerabilities", slot="center", title="Vulnerabilities", center_overlay=True)
async def defender_vulnerabilities(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="Bug")
    conn = connections[0]
    token = await _get_token(ctx, conn)
    try:
        resp = await dc.api_get(ctx, token, "/vulnerabilities", params={"$top": 100})
        items = resp.get("value", []) if isinstance(resp, dict) else []
        if not items:
            return ui.Empty(message="No vulnerabilities found", icon="ShieldCheck")
        items.sort(key=lambda v: v.get("cvssV3", 0), reverse=True)
        rows = [{
            "cve": v.get("id", ""),
            "severity": v.get("severity", ""),
            "cvss": v.get("cvssV3", ""),
            "exposed_machines": v.get("exposedMachines", ""),
        } for v in items]
    except dc.ClientFail as e:
        return ui.Alert(type="error", message=e.payload["error"])
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Vulnerabilities (Threat & Vulnerability Management)", level=2),
        ui.DataTable(rows=rows, columns=[
            ui.DataColumn(key="cve", label="CVE"),
            ui.DataColumn(key="severity", label="Severity"),
            ui.DataColumn(key="cvss", label="CVSS"),
            ui.DataColumn(key="exposed_machines", label="Exposed machines"),
        ]),
    ])


