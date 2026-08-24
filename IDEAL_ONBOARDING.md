# Microsoft Defender for Endpoint Connector — идеальный первый запуск

Источник: `ONBOARDING_FIRST_LAUNCH_STANDARD.md`. Целевой пользователь: SOC-аналитик
или security engineer из команды Microsoft 365 / Azure, впервые открывающий
приложение, обычно в момент реагирования на инцидент или настройки нового окружения.

## 1. Credential type
Azure AD tenant ID + Application (App Registration) с Application-разрешениями
WindowsDefenderATP API (Machine.ReadWrite.All, Alert.ReadWrite.All, Ti.ReadWrite,
AdvancedQuery.Read.All, Vulnerability.Read.All), с admin-consent, плюс client secret.

## 2. Идеальный флоу (без ограничений SDK)
1. **Чеклист нужных Application permissions прямо в форме подключения** — Defender
   требует явного admin consent на каждое разрешение при регистрации приложения в Azure AD;
   идеально показать интерактивный список "что нужно для каких функций", чтобы
   пользователь не создавал App Registration с недостающими правами и не натыкался
   на 403 только при первом реальном действии (изоляции хоста, например).
2. **Проверка подключения реальным вызовом перед сохранением** — обмен client
   credentials на Azure AD токен через `/oauth2/v2.0/token`, затем лёгкий вызов
   (`/machines?$top=1`) чтобы подтвердить не только валидность credentials, но и
   реальную работу Machine.Read — а не просто сохранить тройку ключей вслепую.
3. **После успеха — сразу estate health snapshot** — количество machines по
   healthStatus, число изолированных, открытые alerts по severity, и топ критичных
   CVE по exposedMachines, чтобы пользователь сразу увидел живые данные, а не пустой экран.
4. **Явное предупреждение перед isolate_machine** — изоляция хоста обрывает почти
   весь сетевой доступ пользователя мгновенно; идеально — модальное подтверждение с
   именем машины и типом изоляции (Full/Selective) перед выполнением, а не тихое действие.
5. **Понятные сообщения на 401 vs 403** — 401 значит протухший/неверный client
   secret (подсказка: обновить в Azure AD > Certificates & secrets), 403 значит
   недостающее Application permission без admin consent (подсказка: какое именно
   разрешение добавить) — не обобщённый "unauthorized".
6. **run_hunting_query как отдельный "продвинутый" режим** — Advanced Hunting KQL
   мощный, но требует знания схемы таблиц (DeviceProcessEvents, DeviceNetworkEvents
   и т.д.); идеально — несколько готовых шаблонов запросов на выбор, а не только
   пустое текстовое поле.

## 3. Реализовано сейчас
`connect_defender` выполняет реальный обмен токена перед сохранением (см. п.2).
`audit_estate` строит агрегированный отчёт (см. п.3). `isolate_machine` требует
обязательное поле `comment` (Defender API и так требует его, что естественно
создаёт "паузу для объяснения"), но не показывает модальное подтверждение --
2-step confirmation gate обеспечивается платформой через `action_type="write"`/
`"destructive"` на уровне kernel, не самим handler'ом. Ошибки 401/403 различаются
в `defender_client.py` (`AUTH_REJECTED` vs `SCOPE_DENIED`) с разными текстами.
Готовых шаблонов KQL-запросов нет — `run_hunting_query` принимает произвольный текст.
