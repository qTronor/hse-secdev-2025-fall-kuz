# ADR: Role-Based PII Filter for Exports

Status: Proposed

## Context

Risk: **R-03 “Утечка персональных данных при экспорте (S3)”** (L = 3, I = 5, Score = 15) — в топе из-за высокого влияния при массовом экспорте клиентских данных.  
DFD: U --> A, A --> S3, S3 --> D  
NFR: `NFR-014-1`  
Assumptions:

- Экспорт файлов выполняется сервисом `exporter` в объектное хранилище S3.
- Есть флаг `include_pii`, но без строгой проверки ролей.
- Публичные pre-signed URL доступны всем, кто получил ссылку.
- Требуется соответствие 152-ФЗ и GDPR.

## Decision

Вводится **ролевой фильтр доступа и маскирование PII** при экспорте.

- **Param/Policy:** `include_pii` разрешён только ролям `admin`, `dpo` (scope: `GET /api/export*`, layer: S3 service). Остальные → **403 (RFC7807)**.
- **Param/Policy:** При `include_pii=false` — маскирование полей (`email`, `phone`, `inn`, `address`) на стороне S3 до выгрузки.
- **Param/Policy:** S3 Lifecycle Rule → удаление файлов через ≤ 30 дней с момента создания.
- **Param/Policy:** Логи содержат `actor_role`, `include_pii`, `export_id`, `file_key`, без PII.
- **Param/Policy:** Аудит-запись `export.created` отправляется в БД.
- **Notes:** Политика применяется только к S3; для `Y (Analytics API)` используется агрегация без PII.

## Alternatives

- **Alt A:** Маскирование PII в БД на уровне view — затрагивает все сервисы, риск потери данных для аналитики.
- **Alt B:** Post-processing утилита (очистка PII после экспорта) — возможен временной разрыв и окно утечки.
- **Alt C (выбран):** Ролевой фильтр и маскирование в S3 Export Service — локально, мало зависимостей, моментальный эффект.

## Consequences

**Положительные:**

- Исключается массовая утечка PII при ошибках ролей или конфигов.
- Выполняются требования GDPR/152-ФЗ.

**Негативные/издержки:**

- Админам потребуется дополнительное обучение по новым ролям.
- Усложняется отладка экспортных данных из-за маскирования.

## DoD / Acceptance

**Given** роль `analyst` и параметр `include_pii=true`  
**When** `GET /api/export?format=csv`  
**Then** возвращается **403 (RFC7807)**, файл не создаётся.

**Given** роль `admin` и `include_pii=true`  
**When** экспорт завершён  
**Then** в логе есть `actor_role=admin`, файл в S3 не публичный, удаляется ≤ 30 дней, PII в предпросмотре маскированы.

**Checks:**

- **test:** `export_pii_access_test`, `mask_pii_fields`.
- **log:** в stdout/ELK отсутствуют паттерны `\d{11}` или `@`; присутствуют `actor_role`, `include_pii`.
- **scan/policy:** S3 Lifecycle rule “Delete after 30d” активна.
- **metric/SLO:** 0 инцидентов `export PII leak` за спринт.

## Rollback / Fallback

Фича-флаг `export_pii_filter_enabled` (в сервисе).  
Откат: OFF → старое поведение (без маскирования, но PII ограничивается MIME ACL).  
Мониторинг: резкий рост 403 по endpoint `exports` и alert на S3 Public Access.

## Trace

- DFD: `U → A → S3 → D` (Export Service)
- STRIDE: I (Information Disclosure)
- Risk scoring: `R-03 (Top-5, Rank #2)`
- NFR: `NFR-014-1 (Privacy/PII)`
- Issues: `#export-pii-filter`, `#s3-retention-policy`

## Ownership & Dates

Owner: Data Platform Team  
Reviewers: Security Officer, Privacy Lead  
Date created: 2025-10-12  
Last updated: 2025-10-12

## Open Questions

- Маскировать по типу поля (например, телефон — последние 4 цифры)?
- Расширить S3 Lifecycle на `Y (Analytics API)` дампы?    
