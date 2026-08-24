# Microsoft Defender for Endpoint Connector — UI component plan

Источники: `Docs/session-notes/UI_COMPONENT_VOCABULARY.md`, `UI_INTERFACE_STANDARD.md`,
`concepts/panels.md`. Основано на функционале `microsoft-defender-endpoint-connector`.

## 0. Разница с IDEAL_ONBOARDING.md
Идеал предполагает интерактивный чеклист Application permissions и модальное
подтверждение перед isolate_machine. Реализация делает проверку тем же способом, что
и другие Azure AD OAuth2 client-credentials коннекторы портфеля (Power BI, Azure) —
`connect_defender` сам выполняет пробный обмен токена и один вызов `/machines?$top=1`
перед сохранением. Чеклист разрешений описан текстом (`ui.Markdown`) в help-overlay.
Явного модального confirm перед isolate_machine нет как отдельного UI-элемента — 2-step
подтверждение для write/destructive действий обеспечивается платформой на уровне kernel
(`action_type`), не отдельным диалогом в этом приложении.

## 1. Компоненты

| Экран | Примитивы | Почему именно эти |
|---|---|---|
| Sidebar (left, not connected) | `ui.Stack`(v, align="stretch") + `ui.Button`("Как зарегистрировать Azure AD App?" → help overlay) + `ui.Form`(connect_defender) с лейблами на каждом `ui.Input` | Без карточек, без дублирования инструкций — паттерн CrowdStrike/Okta/ServiceNow. Форма растянута на всю ширину сайдбара. |
| Connect form fields | labelled `ui.Input`(label, placeholder "Acme Corp Tenant") + labelled `ui.Input`(tenant_id, placeholder "00000000-...") + labelled `ui.Input`(client_id, placeholder "00000000-...") + labelled `ui.Input`(client_secret, type="password") | Все три Azure AD значения нужны отдельными явными полями — нет способа объединить/угадать. |
| Help overlay | `ext.panel(slot="overlay")` + `ui.Markdown`(путь Azure Portal > App registrations, список Application permissions по функциям) | Единственное место с инструкциями подключения — не дублируется в сайдбаре. |
| Sidebar (connected) | `ui.Stack`(v) + `ui.Text`(tenant label) + `ui.Divider` + `ui.Button`×4 (Machines/Alerts/Indicators/Vulnerabilities) + `ui.Button`("App settings") | Плоский список разделов без карточек, ровно то же расположение, что у CrowdStrike/Okta. |
| Machines (center) | `ui.Header` + `ui.DataTable`(computer, OS, health, risk, isolated) | Табличный вид — стандарт для списков сущностей с несколькими полями. |
| Alerts (center) | `ui.Header` + список `ui.Stack`(h) строк с `ui.Badge`(severity, error/warning/default) + title + status | Критичные алерты визуально выделены цветом бейджа, отсортированы severity-first в handler'е (нет отдельного "pin to top" примитива). |
| Indicators (center) | `ui.Header` + `ui.DataTable`(type, value, action, title) | Табличный вид для списка IOC. |
| Vulnerabilities (center) | `ui.Header` + `ui.DataTable`(CVE, severity, CVSS, exposed machines), отсортировано по CVSS убыв. в handler'е | Табличный вид, сортировка на уровне данных — нет отдельного primitve для client-side сортировки таблицы. |
| App settings (center) | `ui.Header` + список `ui.Stack`(h) строк: `ui.Text`(tenant) + `ui.Button`("Disconnect", variant="destructive") | Disconnect — единственное деструктивное действие в сайдбаре по конвенции, живёт только в Settings. |

## 2. Ограничения SDK, повлиявшие на реализацию
- Нет per-scope toggle-виджета, привязанного к одной форме — чеклист разрешений сделан текстом.
- Нет отдельного client-side "pin critical to top" примитива для таблиц — сортировка делается в Python перед рендером.
- Нет built-in modal-confirm перед конкретным действием — 2-step confirmation gate для write/destructive действий обеспечивает kernel через `action_type`, не сам UI-код этого приложения.
