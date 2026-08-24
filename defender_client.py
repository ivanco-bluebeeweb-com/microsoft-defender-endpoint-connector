"""Microsoft Defender for Endpoint HTTP client -- Azure AD OAuth2
client-credentials auth against a user's own tenant, thin wrappers around
the WindowsDefenderATP API (api.securitycenter.microsoft.com/api).

WHY AZURE AD OAUTH2 CLIENT CREDENTIALS.
Defender for Endpoint delegates all authentication to Azure AD -- there is
no MDE-specific API key. A confidential-client Azure AD App Registration
with WindowsDefenderATP Application permissions gets a Bearer token from
https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token using the
`.default` scope against resource api.securitycenter.microsoft.com. Tokens
expire in ~1 hour; this client proactively re-authenticates when a cached
token is close to expiry (same principle as Power BI Connector / Azure
Connector's Azure AD OAuth2 clients in this portfolio).

WHY 401 vs 403 ARE HANDLED DIFFERENTLY.
A 401 means the Azure AD token itself is invalid/expired/wrong tenant. A
403 means the token is valid but the App Registration lacks the specific
Application permission (e.g. Machine.Isolate) needed for this call, and
that permission was not admin-consented -- a fixable, more specific cause
that must be reported distinctly from "wrong credentials".
"""
from __future__ import annotations

import time

TOKEN_MISSING = "MDE_TOKEN_MISSING"
AUTH_REJECTED = "MDE_AUTH_REJECTED"
SCOPE_DENIED = "MDE_SCOPE_DENIED"
NOT_FOUND = "MDE_NOT_FOUND"
VALIDATION_FAILED = "MDE_VALIDATION_FAILED"
RESPONSE_UNEXPECTED = "MDE_RESPONSE_UNEXPECTED"
UNREACHABLE = "MDE_UNREACHABLE"
RATE_LIMITED = "MDE_RATE_LIMITED"
BACKEND_5XX = "MDE_BACKEND_5XX"

_MESSAGES = {
    TOKEN_MISSING: "No Azure AD token available -- reconnect this Defender for Endpoint tenant.",
    AUTH_REJECTED: "Azure AD rejected these credentials. Check tenant_id, client_id, and client_secret are correct and the secret has not expired.",
    SCOPE_DENIED: "This App Registration lacks the WindowsDefenderATP Application permission required for this action, or admin consent has not been granted for it.",
    NOT_FOUND: "The requested resource was not found in Defender for Endpoint.",
    VALIDATION_FAILED: "Defender for Endpoint rejected the request payload.",
    RESPONSE_UNEXPECTED: "Defender for Endpoint returned an unexpected response.",
    UNREACHABLE: "Could not reach Defender for Endpoint or Azure AD login endpoints.",
    RATE_LIMITED: "Defender for Endpoint rate-limited this request. Try again shortly.",
    BACKEND_5XX: "Defender for Endpoint reported an internal error.",
}

_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
_API_BASE = "https://api.securitycenter.microsoft.com/api"


class ClientFail(Exception):
    def __init__(self, code: str, retryable: bool = False, detail: str = ""):
        msg = _MESSAGES.get(code, code)
        if detail:
            msg = f"{msg} ({detail})"
        self.payload = {"error": msg, "retryable": retryable, "code": code}
        super().__init__(msg)


async def get_token(ctx, tenant_id: str, client_id: str, client_secret: str) -> dict:
    """Exchange tenant/client credentials for an Azure AD Bearer token via
    the v2.0 client-credentials flow, scoped to the Defender API resource."""
    import httpx

    url = _TOKEN_URL.format(tenant=tenant_id)
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://api.securitycenter.microsoft.com/.default",
    }
    try:
        async with httpx.AsyncClient(timeout=30.0) as http:
            resp = await http.post(url, data=data)
    except httpx.RequestError as exc:
        raise ClientFail(UNREACHABLE, retryable=True, detail=str(exc)) from exc

    if resp.status_code == 401 or resp.status_code == 400:
        raise ClientFail(AUTH_REJECTED, retryable=False, detail=f"HTTP {resp.status_code}")
    if resp.status_code >= 500:
        raise ClientFail(BACKEND_5XX, retryable=True, detail=f"HTTP {resp.status_code}")
    if resp.status_code != 200:
        raise ClientFail(RESPONSE_UNEXPECTED, retryable=False, detail=f"HTTP {resp.status_code}")

    body = resp.json()
    access_token = body.get("access_token", "")
    expires_in = int(body.get("expires_in", 3600))
    if not access_token:
        raise ClientFail(TOKEN_MISSING, retryable=False)
    return {"access_token": access_token, "expires_at": time.time() + expires_in - 60}


async def _request(ctx, method: str, token: str, path: str, params: dict | None = None, json: dict | None = None) -> dict:
    import httpx

    url = f"{_API_BASE}{path}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        async with httpx.AsyncClient(timeout=30.0) as http:
            resp = await http.request(method, url, headers=headers, params=params, json=json)
    except httpx.RequestError as exc:
        raise ClientFail(UNREACHABLE, retryable=True, detail=str(exc)) from exc

    if resp.status_code == 401:
        raise ClientFail(AUTH_REJECTED, retryable=False)
    if resp.status_code == 403:
        raise ClientFail(SCOPE_DENIED, retryable=False)
    if resp.status_code == 404:
        raise ClientFail(NOT_FOUND, retryable=False)
    if resp.status_code == 429:
        raise ClientFail(RATE_LIMITED, retryable=True)
    if resp.status_code >= 500:
        raise ClientFail(BACKEND_5XX, retryable=True, detail=f"HTTP {resp.status_code}")
    if resp.status_code >= 400:
        raise ClientFail(VALIDATION_FAILED, retryable=False, detail=f"HTTP {resp.status_code}: {resp.text[:200]}")

    if not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError as exc:
        raise ClientFail(RESPONSE_UNEXPECTED, retryable=False, detail=str(exc)) from exc


async def api_get(ctx, token: str, path: str, params: dict | None = None) -> dict:
    return await _request(ctx, "GET", token, path, params=params)


async def api_post(ctx, token: str, path: str, json: dict | None = None) -> dict:
    return await _request(ctx, "POST", token, path, json=json)


async def api_patch(ctx, token: str, path: str, json: dict | None = None) -> dict:
    return await _request(ctx, "PATCH", token, path, json=json)


async def api_delete(ctx, token: str, path: str) -> dict:
    return await _request(ctx, "DELETE", token, path)
