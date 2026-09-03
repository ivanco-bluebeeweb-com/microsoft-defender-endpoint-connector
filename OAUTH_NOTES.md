# Microsoft Defender for Endpoint Connector — заметка по аутентификации (OAuth)

Дата анализа: 2026-08-31

## Коротко: OAuth ЕСТЬ, серверный (client credentials) — Azure AD App Registration

Коннектор подключается к тенанту Defender for Endpoint через **Azure AD App
Registration** (Tenant ID + Client ID + Client Secret) и работает с
Defender API / Microsoft Graph от имени приложения. Токен обновляется
автоматически — браузер не нужен.

## Как устроено подключение

В панели Imperal вводятся **Tenant ID + Client ID + Client Secret** от
App Registration. Приложению нужны Application permissions к
`https://api.securitycenter.microsoft.com` (Machine.Read.All,
Machine.Isolate, Machine.Scan, Alert.ReadWrite.All и пр. — по нужным
функциям) с admin consent.

## Что автоматизировано, а что — руками

| Этап | Как делается |
|---|---|
| App Registration + секрет + permissions + consent | **РУКАМИ** — Entra ID, только администратор тенанта |
| Получение/обновление токена | **АВТОМАТИЧЕСКИ** |

## Следствие для тестирования

Полный тест (машины, алерты, изоляция, AV-скан, hunting KQL) требует
Tenant ID + Client ID + Client Secret реального тенанта с admin consent
и развёрнутым Defender for Endpoint.

## Проверено в проде

После точечного деплоя (99f7d850, 21/21 проверок) list_connections
работает чисто — пустой список, без ошибок контракта.
