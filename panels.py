"""Microsoft Defender for Endpoint Connector panels.

SIDEBAR CONTENT -- NO CARDS ANYWHERE, per ~/UI_INTERFACE_STANDARD.md's "left
sidebar, no decorated cards" rule (same convention as CrowdStrike Falcon
Connector's / Okta Connector's panels.py). Every section is a plain
ui.Stack, stacked vertically and left-aligned, no Card border/background/
shadow. Disconnect lives only in "App settings" (panels_settings.py). The
one secondary "App settings" button is always the LAST element at the
bottom of the sidebar.

Per Vlad's standing rule: every input carries its own label (not just a
placeholder), placeholders are contextually specific, the form container is
stretched to the full width of the left sidebar with its contents stretched
to fill it, and the sidebar carries NO instructions that duplicate the "How
do I set this up?" modal.
"""
from __future__ import annotations

from imperal_sdk import ui

from app import ext
from handlers_connection import _load_connections


def _settings_button() -> ui.UINode:
    return ui.Button(
        "App settings", variant="secondary", size="sm", full_width=True,
        icon="Settings", on_click=ui.Call("__panel__defender_settings"),
    )


@ext.panel("defender_sidebar", slot="left", title="Microsoft Defender for Endpoint")
async def defender_sidebar(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Stack(direction="v", gap=3, align="stretch", children=[
            ui.Button("Как зарегистрировать Azure AD App?", variant="ghost", size="sm", icon="HelpCircle",
                      on_click=ui.Call("__panel__defender_connect_help")),
            ui.Form(action="connect_defender", submit_label="Подключить тенант", full_width=True, children=[
                ui.Stack(direction="v", gap=1, align="stretch", children=[
                    ui.Text("Название (опционально)", variant="caption"),
                    ui.Input(param_name="label", placeholder="Acme Corp Tenant"),
                ]),
                ui.Stack(direction="v", gap=1, align="stretch", children=[
                    ui.Text("Azure AD Tenant ID", variant="caption"),
                    ui.Input(param_name="tenant_id", placeholder="00000000-0000-0000-0000-000000000000"),
                ]),
                ui.Stack(direction="v", gap=1, align="stretch", children=[
                    ui.Text("Azure AD Application (client) ID", variant="caption"),
                    ui.Input(param_name="client_id", placeholder="00000000-0000-0000-0000-000000000000"),
                ]),
                ui.Stack(direction="v", gap=1, align="stretch", children=[
                    ui.Text("Client Secret", variant="caption"),
                    ui.Input(param_name="client_secret", type="password", placeholder="Значение секрета Azure AD App"),
                ]),
            ]),
        ])
    c = connections[0]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Text(c.get("label") or c.get("tenant_id", ""), variant="body"),
        ui.Divider(),
        ui.Button("Machines", variant="ghost", full_width=True, icon="Laptop", on_click=ui.Call("__panel__defender_machines")),
        ui.Button("Alerts", variant="ghost", full_width=True, icon="ShieldAlert", on_click=ui.Call("__panel__defender_alerts")),
        ui.Button("Indicators", variant="ghost", full_width=True, icon="Target", on_click=ui.Call("__panel__defender_indicators")),
        ui.Button("Vulnerabilities", variant="ghost", full_width=True, icon="Bug", on_click=ui.Call("__panel__defender_vulnerabilities")),
        ui.Divider(),
        _settings_button(),
    ])


@ext.panel("defender_connect_help", slot="overlay", title="Как зарегистрировать Azure AD App?")
async def defender_connect_help(ctx, **kwargs) -> ui.UINode:
    return ui.Markdown(text=(
        "**Azure Portal > Microsoft Entra ID > App registrations > New registration.**\n\n"
        "1. Создайте регистрацию (Single tenant).\n"
        "2. **API permissions** > Add a permission > **WindowsDefenderATP** > Application permissions:\n"
        "   `Machine.ReadWrite.All`, `Alert.ReadWrite.All`, `Ti.ReadWrite`, "
        "`AdvancedQuery.Read.All`, `Vulnerability.Read.All`.\n"
        "3. Нажмите **Grant admin consent** для вашего тенанта.\n"
        "4. **Certificates & secrets** > New client secret — скопируйте значение сразу "
        "(оно больше не покажется).\n"
        "5. Скопируйте **Application (client) ID** и **Directory (tenant) ID** со страницы Overview.\n\n"
        "Все 4 значения нужны для подключения слева: Tenant ID, Client ID, Client Secret."
    ))
