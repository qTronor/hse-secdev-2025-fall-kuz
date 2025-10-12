# STRIDE per element (объединённый проект)

| Element | Data/Boundary | Threat | Description | NFR link (ID) | Mitigation idea (ADR later) |
|----------|---------------|---------|-------------|---------------|------------------------------|
| Edge: U→A | Public API | S | Подмена токена авторизации при импорте/экспорте | NFR-013-7, NFR-014-5 | JWT TTL + подпись |
| Edge: U→A | File upload | T | Изменение CSV перед валидацией (инъекция формул) | NFR-013-1 | InputValidation + sanitize |
| Edge: U→A | Auth forms | S | Подмена email при запросе сброса пароля | NFR-003-6 | CAPTCHA + rate limit |
| Node: S1 Auth | Token | I | Утечка токена сброса в логах | NFR-003-4 | Маскирование токенов |
| Node: S2 Import | CSV file | I | Утечка PII в CSV при ошибке схемы | NFR-013-8 | PII check + reject |
| Node: S3 Export | Query result | I | Экспорт с PII без прав | NFR-014-1 | Role check + include_pii=false |
| Node: A | Controller | D | Массовые запросы (DoS) на импорт/экспорт | NFR-013-5, NFR-014-2 | RateLimit middleware |
| Edge: S2→D | SQL insert | T | Изменение записей при импорте | NFR-013-2 | Parameterized queries |
| Edge: S3→D | SQL select | I | Утечка tenant data | NFR-014-10 | Tenant isolation |
| Node: D | Database | R | Нет аудита операций импорта/экспорта | NFR-013-10, NFR-014-7 | Audit log on commit |
| Node: S3 | Business logic | E | Обход RBAC при экспорте | NFR-014-5 | Role check in query |
| Edge: S1→X | SMTP | D | Повторные письма при сбое | need NFR | Retry + CircuitBreaker |
| Edge: S3→Y | External API | D | Нет таймаутов, зависание | need NFR | Timeout ≤2s, retry ≤3 |
| Node: S2 | Job Worker | R | Нет логов фоновых задач импорта | NFR-013-3 | Correlation ID + jobId |
| Node: S1 | Audit | R | Нет записи о смене пароля | NFR-003-4 | Audit event |
| Node: A | Public API | I | Ошибки API раскрывают внутренние поля | NFR-013-6, NFR-014-4 | RFC7807 errors |
| Node: D | Storage | I | Хранение CSV без шифрования | need NFR | AES-256 at rest |
| Node: D | Storage | D | Переполнение хранилища большими CSV | NFR-013-1 | File size ≤10 MiB |
| Node: S3 | Performance | D | Долгие выгрузки блокируют сервер | NFR-014-3 | Async export job |
| Node: U | Client | S | Фишинговые ссылки сброса | NFR-003-2 | Signed HTTPS link |