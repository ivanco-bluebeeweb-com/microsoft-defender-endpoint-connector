"""Microsoft Defender for Endpoint Connector -- App settings panel (disconnect only)."""
from __future__ import annotations

from imperal_sdk import ui

from app import ext
from handlers_connection import _load_connections


@ext.panel("defender_settings", slot="center", title="Microsoft Defender for Endpoint settings", icon="Settings", center_overlay=True)
async def defender_settings(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Text("No Microsoft Defender for Endpoint tenant connected yet.", variant="body")
    rows = []
    for c in connections:
        rows.append(ui.Stack(direction="h", gap=2, align="center", children=[
            ui.Text(f"{c.get('label') or c.get('tenant_id', '')}", variant="body"),
            ui.Button("Disconnect", variant="destructive", on_click=ui.Call("disconnect_defender", {"connection_id": c.get("id", "")})),
        ]))
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Connected tenants", level=2),
        *rows,
    ])
