"""Pydantic input contracts and SDL result entities for Microsoft Defender for Endpoint Connector."""
from __future__ import annotations

from imperal_sdk import sdl
from pydantic import BaseModel, Field


class NoParams(BaseModel):
    pass


class ConnectionRefParams(BaseModel):
    connection_id: str = Field("", description="Optional saved Defender for Endpoint tenant connection ID. Omit to use the first connected tenant.")


class ConnectDefenderParams(BaseModel):
    label: str = Field("", description="Friendly tenant label, e.g. 'Acme Corp Tenant'.")
    tenant_id: str = Field(..., description="Azure AD tenant ID (GUID) the App Registration belongs to.")
    client_id: str = Field(..., description="Azure AD Application (client) ID with WindowsDefenderATP API permissions.")
    client_secret: str = Field(..., description="Azure AD Application client secret value.")


class DisconnectDefenderParams(ConnectionRefParams):
    connection_id: str = Field(..., description="Saved Defender for Endpoint tenant connection ID to remove from Imperal.")


class ListMachinesParams(ConnectionRefParams):
    filter_expr: str = Field("", description="Optional OData $filter, e.g. \"healthStatus eq 'Active'\".")
    limit: int = Field(50, description="Max machines to return (1-500).")


class MachineIdParams(ConnectionRefParams):
    machine_id: str = Field(..., description="Defender machine id.")


class MachineActionParams(ConnectionRefParams):
    machine_id: str = Field(..., description="Defender machine id to act on.")
    comment: str = Field(..., description="Reason/comment for this action, required by the Defender API and shown in the action audit trail.")


class IsolateMachineParams(MachineActionParams):
    isolation_type: str = Field("Full", description="'Full' (complete network isolation) or 'Selective' (allows Outlook/Skype/Teams).")


class RunAvScanParams(MachineActionParams):
    scan_type: str = Field("Quick", description="'Quick' or 'Full' antivirus scan.")


class ListAlertsParams(ConnectionRefParams):
    filter_expr: str = Field("", description="Optional OData $filter, e.g. \"severity eq 'High'\".")
    limit: int = Field(50, description="Max alerts to return (1-500).")


class AlertIdParams(ConnectionRefParams):
    alert_id: str = Field(..., description="Defender alert id.")


class UpdateAlertParams(AlertIdParams):
    status: str = Field("", description="New status: 'New', 'InProgress', or 'Resolved'. Leave empty to not change.")
    classification: str = Field("", description="'TruePositive', 'FalsePositive', or 'Unknown'. Leave empty to not change.")
    determination: str = Field("", description="Determination detail, e.g. 'Malware', 'SecurityPersonnel', 'Other'.")
    assigned_to: str = Field("", description="Email of the analyst to assign this alert to. Leave empty to not change.")
    comment: str = Field("", description="Optional comment to add to the alert.")


class ListIndicatorsParams(ConnectionRefParams):
    limit: int = Field(50, description="Max indicators to return (1-500).")


class CreateIndicatorParams(ConnectionRefParams):
    indicator_type: str = Field(..., description="Indicator type: 'FileSha1', 'FileSha256', 'IpAddress', 'DomainName', or 'Url'.")
    indicator_value: str = Field(..., description="The actual indicator value (hash, IP, domain, or URL).")
    action: str = Field("Alert", description="Action Defender takes: 'Alert', 'AlertAndBlock', 'Block', 'Allowed', or 'BlockAndRemediate'.")
    title: str = Field(..., description="Short title for this indicator, shown in the console.")
    description: str = Field(..., description="Longer description of why this indicator was added.")
    severity: str = Field("Medium", description="'Informational', 'Low', 'Medium', or 'High'.")


class IndicatorIdParams(ConnectionRefParams):
    indicator_id: str = Field(..., description="Defender custom indicator id.")


class RunHuntingQueryParams(ConnectionRefParams):
    query: str = Field(..., description="Advanced Hunting KQL query, e.g. \"DeviceProcessEvents | take 10\".")


class ListVulnerabilitiesParams(ConnectionRefParams):
    machine_id: str = Field("", description="Optional: restrict to CVEs exposed on this one machine id.")
    limit: int = Field(50, description="Max results to return (1-500).")


class DefenderConnection(sdl.Entity):
    connection_id: str
    label: str
    tenant_id: str
    client_id_masked: str


class ConnectionList(sdl.Entity):
    connections: list[DefenderConnection] = []


class DeleteResult(sdl.Entity):
    ok: bool
    detail: str = ""


class DefenderMachine(sdl.Entity):
    machine_id: str
    computer_dns_name: str
    os_platform: str
    health_status: str
    risk_score: str
    last_seen: str
    is_isolated: bool = False


class MachineList(sdl.Entity):
    machines: list[DefenderMachine] = []


class MachineActionResult(sdl.Entity):
    action_id: str
    machine_id: str
    status: str
    action_type: str


class DefenderAlert(sdl.Entity):
    alert_id: str
    title: str
    severity: str
    status: str
    category: str
    machine_id: str
    created: str


class AlertList(sdl.Entity):
    alerts: list[DefenderAlert] = []


class DefenderIndicator(sdl.Entity):
    indicator_id: str
    indicator_type: str
    indicator_value: str
    action: str
    title: str
    severity: str


class IndicatorList(sdl.Entity):
    indicators: list[DefenderIndicator] = []


class HuntingResult(sdl.Entity):
    columns: list[str] = []
    rows: list[dict] = []
    row_count: int = 0


class Vulnerability(sdl.Entity):
    cve_id: str
    severity: str
    cvss_score: float = 0.0
    machine_id: str
    software_name: str
    software_vendor: str


class VulnerabilityList(sdl.Entity):
    vulnerabilities: list[Vulnerability] = []


class EstateAudit(sdl.Entity):
    total_machines: int
    active_machines: int
    isolated_machines: int
    stale_machines: int
    open_alerts: int
    high_severity_alerts: int
    critical_cves_exposed: int
    summary: str
