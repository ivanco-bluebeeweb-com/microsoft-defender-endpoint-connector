"""Connection management: connect/disconnect Defender for Endpoint tenants.
Same shape as CrowdStrike Falcon Connector's / Okta Connector's connection
handlers -- async, one secret holding a JSON array, proactive Azure AD token
caching per connection (see defender_client.py).
"""
from __future__ import annotations

import json
import time
import uuid

from imperal_sdk import ActionResult

import defender_client as dc
from app import ext, chat
from schemas import (
    NoParams, ConnectionRefParams,
    ConnectDefenderParams, DefenderConnection, ConnectionList,
    DisconnectDefenderParams, DeleteResult,
)

_CONN_SECRET = "defender_connections"
_TOKEN_CACHE: dict[str, dict] = {}


async def _load_connections(ctx) -> list[dict]:
    raw = await ctx.secrets.get(_CONN_SECRET)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return data if isinstance(data, list) else []


async def _save_connections(ctx, items: list[dict]) -> None:
    await ctx.secrets.set(_CONN_SECRET, json.dumps(items))


async def _resolve_connection(ctx, connection_id: str = "") -> dict | None:
    conns = await _load_connections(ctx)
    if not conns:
        return None
    if connection_id:
        for c in conns:
            if c.get("id") == connection_id:
                return c
        return None
    return conns[0]


async def _get_token(ctx, conn: dict) -> str:
    """Return a cached, still-valid Azure AD token for this connection, or
    fetch a fresh one and cache it. Proactive refresh: re-auth once the
    cached token is within 60s of expiry (handled inside dc.get_token)."""
    cid = conn["id"]
    cached = _TOKEN_CACHE.get(cid)
    if cached and cached.get("expires_at", 0) > time.time():
        return cached["access_token"]
    fresh = await dc.get_token(ctx, conn["tenant_id"], conn["client_id"], conn["client_secret"])
    _TOKEN_CACHE[cid] = fresh
    return fresh["access_token"]


def _mask(client_id: str) -> str:
    if len(client_id) <= 6:
        return "…"
    return client_id[:4] + "…" + client_id[-2:]


@chat.function("connect_defender", "Connect your own Microsoft Defender for Endpoint tenant by saving its Azure AD tenant/client credentials, after checking they actually work.", action_type="write", chain_callable=True, data_model=DefenderConnection, event="microsoft-defender-endpoint-connector.connect_defender", effects=["defender.provider.connected"])
async def connect_defender(ctx, params: ConnectDefenderParams) -> ActionResult:
    """Connect your own Microsoft Defender for Endpoint tenant by saving its Azure AD tenant/client credentials, after checking they actually work."""
    try:
        token_info = await dc.get_token(ctx, params.tenant_id, params.client_id, params.client_secret)
    except dc.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))

    conns = await _load_connections(ctx)
    conn_id = str(uuid.uuid4())
    entry = {
        "id": conn_id,
        "label": params.label or params.tenant_id,
        "tenant_id": params.tenant_id,
        "client_id": params.client_id,
        "client_secret": params.client_secret,
    }
    conns.append(entry)
    await _save_connections(ctx, conns)
    _TOKEN_CACHE[conn_id] = token_info
    return ActionResult.success(
        data=DefenderConnection(
            connection_id=conn_id, label=entry["label"], tenant_id=params.tenant_id,
            client_id_masked=_mask(params.client_id),
        ),
        summary=f"Connected Microsoft Defender for Endpoint tenant '{entry['label']}'.",
    )


@chat.function("disconnect_defender", "Disconnect a Microsoft Defender for Endpoint tenant: deletes the saved Azure AD credentials. Nothing in Defender itself is changed.", action_type="write", chain_callable=True, data_model=DeleteResult, event="microsoft-defender-endpoint-connector.disconnect_defender", effects=["defender.provider.disconnected"])
async def disconnect_defender(ctx, params: DisconnectDefenderParams) -> ActionResult:
    """Disconnect a Microsoft Defender for Endpoint tenant: deletes the saved Azure AD credentials. Nothing in Defender itself is changed."""
    conns = await _load_connections(ctx)
    remaining = [c for c in conns if c.get("id") != params.connection_id]
    if len(remaining) == len(conns):
        return ActionResult.error(f"No saved Defender for Endpoint connection with id '{params.connection_id}'.")
    await _save_connections(ctx, remaining)
    _TOKEN_CACHE.pop(params.connection_id, None)
    return ActionResult.success(data=DeleteResult(ok=True, detail="Defender for Endpoint tenant disconnected."), summary="Disconnected.")


@chat.function("list_connections", "List the connected Microsoft Defender for Endpoint tenants (tenant id + masked Client ID).", action_type="read", chain_callable=True, data_model=ConnectionList, event="microsoft-defender-endpoint-connector.list_connections")
async def list_connections(ctx, params: NoParams) -> ActionResult:
    """List the connected Microsoft Defender for Endpoint tenants."""
    conns = await _load_connections(ctx)
    items = [
        DefenderConnection(connection_id=c["id"], label=c.get("label", ""), tenant_id=c.get("tenant_id", ""), client_id_masked=_mask(c.get("client_id", "")))
        for c in conns
    ]
    return ActionResult.success(data=ConnectionList(connections=items), summary=f"{len(items)} tenant(s) connected.")
