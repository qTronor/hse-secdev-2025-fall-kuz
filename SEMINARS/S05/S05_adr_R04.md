# ADR: Input Validation & Size Limits for CSV Import
Status: Proposed

## Context
Risk: `R-04 “Вредоносный CSV (Tampering)” (L=4, I=4, Score=16) — в топе из-за высокой вероятности подмены/грязных данных и ущерба целостности/безопасности (CSV Injection).`
DFD: `U --> A, A --> S2, S2 --> D`
NFR: `NFR-013-1, NFR-013-2`
Assumptions:
- Импорт по HTTP в один публичный gateway; сервис импорта — S2.
- Лимит файла ≤ 10 MiB; SLO: при росте нагрузки ×2 P95 растёт ≤1.2×; 5xx ≤1 %.
- Единый формат ошибок: RFC7807 с `correlation_id`.

## Decision
Вводим строгую валидацию CSV: базовые лимиты и MIME — на периметре (gateway), схема/типы/нормализация и защита от формульных инъекций — в S2.
- Param/Policy: **Content-Length ≤ 10 MiB** (scope: `POST /api/import/csv`, layer: gateway). Нарушение → **413** (RFC7807).
- Param/Policy: **MIME allowlist** `{text/csv, application/csv}` (layer: gateway). Нарушение → **415** (RFC7807).
- Param/Policy: **Strict CSV schema (allowlist колонок/типов)** (layer: S2). Лишние/неизвестные поля → **400** (RFC7807).
- Param/Policy: **Normalization** — даты → **UTC ISO-8601**, строки → **NFC**, телефоны → **E.164** (layer: S2). Невалидные записи отклоняются.
- Param/Policy: **CSV Injection guard** — значения, начинающиеся с `=`, `+`, `-`, `@`, сохраняются как текст (экранируем/строкизируем) или отклоняются согласно политике (layer: S2).
- Param/Policy: **Errors** — везде `application/problem+json` + `correlation_id` (gateway + S2).
- Notes: Границы действия — только `POST /api/import/csv`; на другие аплоады правила будут расширены отдельными ADR при необходимости.

## Alternatives
- Alt B: **API Gateway schema validation** (проверка схемы CSV на периметре) — отклонено сейчас из-за повышенной сложности (кастом-плагин/скрипт, буферизация тела, эксплуатационные риски). Оставляем как дополнение (ранний reject заголовков/колонок).

## Consequences
**Положительные:**
- Блокируем грязные/вредоносные CSV до записи в БД; снижаем риск CSV Injection.
- Предсказуемые, стандартизованные ошибки для клиентов; улучшенная трассировка (`correlation_id`).

**Негативные/издержки:**
- Дополнительные проверки в S2 увеличат CPU/latency на импорт.
- Жёстче требования к формату файлов; потребуется поддержка схемы и тестов.

## DoD / Acceptance
Given CSV **12 MiB** или `Content-Type=application/pdf`  
When `POST /api/import/csv`  
Then ответ **413**/**415** с `Content-Type: application/problem+json`, полями RFC7807 и `correlation_id` в теле/логах

Given CSV с **лишней колонкой** `foo`  
When `POST /api/import/csv`  
Then **400** (RFC7807) с `detail` вида `"unexpected column 'foo'"`

Given CSV со значением ячейки, начинающимся с `=IMPORT(...)`  
When импорт завершён  
Then значение **не исполняется** в Excel/BI (сохранено как текст или запись отклонена согласно политике), unit `sanitize-formulas` — зелёный

Checks:
- test: e2e `import-size-check`, e2e `import-schema-extra-cols`, unit `normalize-fields`, unit `sanitize-formulas`
- log: структурные JSON-логи с `correlation_id`, без PII/сырых файлов; причина отказа (`reason=size|mime|schema|sanitize`)
- metric/SLO: % отклонений по причинам отображается; при ×2 нагрузке `P95_import_time` **≤ 1.2×** базовой; доля 5xx **≤ 1 %**

## Rollback / Fallback
Feature flag `csv_validation_enabled` (S2) и конфиг `gateway.csv_limits_enabled`.  
Откат: отключаем флаги, оставляя только size/MIME на периметре; усиливаем мониторинг ошибок импорта и ручной quarantine. План наблюдения: алерты на рост 4xx по причинам `schema/sanitize`.

## Trace
- DFD: `S04_dfd.md` — U --> A, A --> S2, S2 --> D
- STRIDE: `S04_stride_matrix.md` — Node: S2 Import , Edge: S2→D
- Risk scoring: `S04_risk_scoring.md` — R-04 (Top-5, Rank #1)
- NFR: `S03` — NFR-013-1, NFR-013-2
- Issues: `#import-validate`, `#sanitize-csv`, `#rfc7807-errors-import`

## Ownership & Dates
Owner: backend team  
Reviewers: devops, QA  
Date created: 2025-10-12  
Last updated: 2025-10-12

## Open Questions
- Политика для ячеек с формулами: всегда экранировать или отклонять строку/файл?
