"""Microsoft Defender for Endpoint Connector extension declaration.

Defender for Endpoint (MDE) is Microsoft's cloud-native EDR/XDR platform,
exposed through the WindowsDefenderATP API (api.securitycenter.microsoft.com)
-- Machines, Alerts, Indicators (custom IOCs), Machine Actions, Advanced
Hunting, and Threat & Vulnerability Management (TVM), plus Azure AD OAuth2
client-credentials for auth.

WHY BYOK (bring-your-own Azure AD App Registration) -- same reasoning as
Azure Connector / Okta Connector. MDE lives inside the user's OWN Microsoft
365 / Azure AD tenant -- Imperal cannot broker access to someone else's
endpoint estate centrally. The user registers an Azure AD Application with
WindowsDefenderATP Application permissions (Machine.ReadWrite.All,
Alert.ReadWrite.All, Ti.ReadWrite, AdvancedQuery.Read.All, etc.), grants
admin consent, and pastes tenant_id/client_id/client_secret once,
Vault-encrypted via ctx.secrets.

WHY TENANT ID IS A SEPARATE REQUIRED FIELD, NOT INFERRED.
Azure AD OAuth2 client-credentials tokens are minted per-tenant at
https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token -- there is
no way to discover a tenant from a client_id alone, so tenant_id is a
required field of connect_defender.
"""
from __future__ import annotations

from imperal_sdk import ChatExtension, Extension

ext = Extension(
    "microsoft-defender-endpoint-connector",
    version="0.1.0",
    display_name="Microsoft Defender for Endpoint",
    description=(
        "Connect your own Microsoft Defender for Endpoint tenant (Azure AD "
        "App Registration) to manage Machines, Alerts, Incidents, custom "
        "Indicators, Machine Actions (isolate/scan), Advanced Hunting "
        "queries, and Threat & Vulnerability Management."
    ),
    icon="icon.svg",
    capabilities=["defender:read", "defender:write"],
    actions_explicit=True,
    system=False,
)

chat = ChatExtension(
    ext,
    tool_name="microsoft_defender_endpoint",
    description=(
        "Microsoft Defender for Endpoint Connector -- manage Machines, "
        "Alerts, Incidents, Indicators, Machine Actions, Advanced Hunting, "
        "and Vulnerability Management for a connected MDE tenant."
    ),
)

ext.secret(
    "defender_connections",
    "JSON list of connected Defender for Endpoint tenants and encrypted credentials. Managed only through connect_defender and disconnect_defender.",
    required=True,
    write_mode="both",
    max_bytes=65536,
    rotation_hint_days=90,
)(lambda: None)


@ext.health_check
async def health_check(ctx) -> dict:
    """Report whether at least one Defender for Endpoint tenant is saved."""
    import json

    raw = await ctx.secrets.get("defender_connections")
    connections = []
    if raw:
        try:
            connections = json.loads(raw)
        except (TypeError, ValueError):
            connections = []
    return {
        "healthy": True,
        "connections": len(connections),
        "detail": f"{len(connections)} Defender for Endpoint tenant(s) connected." if connections else "No tenant connected yet.",
    }
