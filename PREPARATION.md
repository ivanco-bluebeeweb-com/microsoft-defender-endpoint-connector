# Microsoft Defender for Endpoint Connector — Preparation (Фаза 2.5, до кода)

**Дата:** 2026-08-24. Основано на `CONNECTOR_DISCOVERY.md`. SIEM/SOAR-серия —
"максимальный функционал, полный максимум" заявлен заранее.

## 1. WHY BYOK

Defender for Endpoint живёт в собственном Microsoft 365 тенанте клиента —
Imperal не брокерит доступ централизованно, тот же принцип, что Azure
Connector/Power Automate Connector/Microsoft Sentinel Connector.

## 2. WHY только tenant_id/client_id/client_secret (три поля, не шесть как у
Sentinel)

В отличие от Sentinel (слой поверх ARM с subscription/resource-group/
workspace адресацией), Defender for Endpoint — flat tenant-wide API:
один tenant = один API surface, без дополнительной resource-иерархии.
Простейшая из трёх SIEM/SOAR-адресаций (Sentinel: 6 полей, Cortex XDR: 3
поля + FQDN, Defender: 3 поля).

## 3. WHY isolate/unisolate возвращают Action id, а не мгновенный результат

Machine isolation в Defender — асинхронная операция (реальная сетевая
изоляция endpoint-а занимает время на стороне агента), API возвращает
`/machineactions/{id}` для последующего опроса статуса, а не булев успех
сразу. UI и описание инструмента явно называют это ("действие запущено,
проверьте статус"), а не обещают мгновенный эффект.

## 4. WHY один OAuth2 resource audience, а не два (в отличие от Sentinel)

Machines/Alerts/Indicators/Vulnerabilities/Advanced Hunting — всё под
`https://api.securitycenter.microsoft.com/.default`, единый токен
переиспользуется для всех вызовов, в отличие от Sentinel, где ARM и Log
Analytics Query API требуют раздельных scope/токенов.

## 5. WHY isolate_machine требует явного предупреждения о необратимости

Тот же класс риска, что Cortex XDR isolate_endpoint — обрывает сетевой
доступ живого пользователя. UI и описание инструмента явно называют
hostname/machine_id перед вызовом, требуют explicit confirmation.

## 6. Scope (Ярус 1+2+3, максимум по заявленному объёму)

**Ярус 1:** connect_defender (tenant_id/client_id/client_secret),
list/get machines, isolate/unisolate, list/update alerts.

**Ярус 2:** indicators (list/create/delete), vulnerabilities (list per
machine).

**Ярус 3 (value-add + hunting):** advanced hunting query (KQL-подобный
против Defender-схемы), `audit_defender_tenant` — машины с высоким
risk score без активного расследования, открытые High-severity алерты
без assignedTo.

## 7. Ценообразование

Заполняется после сборки, тот же принцип, что Sentinel/Cortex XDR/Splunk/
Zscaler: read дешевле write, isolate_machine (destructive-adjacent) дороже
прямых list/get, audit_defender_tenant (агрегирующий отчёт) дороже прямых
CRUD вызовов.
