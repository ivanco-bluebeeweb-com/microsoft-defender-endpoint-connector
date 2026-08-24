# Microsoft Defender for Endpoint Connector — Connector Discovery

**Дата discovery:** 2026-08-24. SIEM/SOAR-серия — "максимальный функционал,
полный максимум" заявлен для всей серии заранее, повторный вопрос не
требуется, тот же прецедент, что Zscaler/CircleCI/MuleSoft.

## 1. Что такое Defender for Endpoint архитектурно

Microsoft Defender for Endpoint (MDE) — EDR-компонент Microsoft 365
Defender, единый flat tenant-wide REST API на `api.securitycenter.microsoft.com`
(в отличие от Sentinel, у которого API — слой поверх ARM с трёхуровневой
resource-адресацией, и в отличие от Cortex XDR с per-tenant FQDN). Простейшая
из трёх адресаций в этой серии — только `tenant_id`.

## 2. Авторизация — Azure AD OAuth2 client_credentials

App Registration: `tenant_id` + `client_id` + `client_secret`, тот же паттерн,
что Azure Connector/Power Automate Connector/Microsoft Sentinel Connector в
этом портфеле. Требуемые Application permissions: `Machine.ReadWrite.All`,
`Alert.ReadWrite.All`, `Ti.ReadWrite` (indicators), `Vulnerability.Read.All` —
в отличие от Sentinel, всё под одним resource audience
(`https://api.securitycenter.microsoft.com/.default`), не нужно двух
отдельных scope.

## 3. Ключевые домены API

- `/machines` — инвентарь endpoint-ов: `healthStatus`, `riskScore`,
  `exposureLevel`, `osPlatform`, `lastSeen`. Read-heavy, плюс
  `/machines/{id}/isolate` и `/machines/{id}/unisolate` — та же природа
  необратимого до explicit-unisolate действия, что у Cortex XDR
  isolate_endpoint.
- `/alerts` — плоский список алертов с `severity`/`status`/`classification`/
  `determination`, привязка к `machineId`. Update поддерживает
  `assignedTo`/`status`/`classification`/`determination`/comment.
- `/indicators` (Ti.ReadWrite) — Custom Indicators (файл-хэш/IP/URL/
  domain-based), CRUD + `action` (Alert/Block/Allowed) — тот же паттерн,
  что threat-intel у Sentinel и IOC management у Cortex XDR/CrowdStrike.
- `/vulnerabilities` (`/machines/{id}/vulnerabilities`) — Threat & Vulnerability
  Management: список CVE по машине с `cvssScore`/`exposedMachines`/
  `publishedOn`. Read-only в этом ярусе.
- Advanced Hunting (`/advancedqueries/run`) — KQL-подобные запросы к
  Defender-специфичной схеме таблиц (`DeviceEvents`, `DeviceNetworkEvents`
  и т.д.) — концептуально аналогично Sentinel `run_kql_query`, но своя
  отдельная схема таблиц, не Log Analytics workspace.

## 4. Коды ошибок и ограничения

401/403 стандартный OAuth2 паттерн (invalid_client / insufficient
permissions на уровне App Registration Application permissions, не
delegated). Isolate/unisolate — асинхронные операции, возвращают
Action id, нужен последующий poll `/machineactions/{id}` для статуса —
не мгновенный синхронный результат, в отличие от Cortex XDR isolate.

## 5. Ярусы функционала (максимум по заявленному объёму)

**Ярус 1:** connect (tenant_id/client_id/client_secret), list/get machines,
isolate/unisolate, list/update alerts.

**Ярус 2:** indicators (list/create/delete), vulnerabilities (list per
machine), advanced hunting query.

**Ярус 3 (value-add):** `audit_defender_tenant` — риск-балл машин выше
порога без активного расследования, открытые High-severity алерты без
assignedTo.

Источники: learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/
apis-intro, learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/
api/machineaction.
