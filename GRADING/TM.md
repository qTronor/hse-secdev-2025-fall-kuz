---
Изменено:
  - 12-10-2025, 22:16
Дата создания: 12-10-2025, 22:07
---
# TM — Модель угроз (Consolidated, RU)
Версия: 1.1 • Дата: 2025-10-12 • Владелец: Security/Architecture

## 1) Область и обзор системы
Цель: сервисы **Аутентификации/Сброса пароля (S1)**, **Импорта CSV (S2)** и **Экспорта CSV/JSON (S3)** за API‑шлюзом (**A**), с хранилищем (**D: PostgreSQL/объектное**), интеграциями SMTP (**X**) и внешним Analytics API (**Y**). Разделены границы доверия: Интернет ↔ Сервис, Сервис ↔ Внешние провайдеры, Сервис ↔ Хранилища.

### 1.1 DFD (Mermaid)
```mermaid
flowchart LR
  %% --- Trust boundaries ---
  subgraph Internet["Интернет / Внешние пользователи"]
    U["[U] Пользователь / Браузер / Мобильный клиент"]
  end

  subgraph Service["Основное приложение"]
    A["[A] API Gateway / Controller"]
    S1["[S1] Auth Service (Password Reset)"]
    S2["[S2] Import Service (CSV Upload)"]
    S3["[S3] Export Service (CSV/JSON)"]
    D["[D] PostgreSQL / Object Storage"]
  end

  subgraph External["Внешние сервисы"]
    X["[X] SMTP / Email API"]
    Y["[Y] Analytics / External API"]
  end

  %% --- Потоки данных ---
  U -- "POST /api/auth/forgot, /reset [NFR: Security-Secrets, API-Errors]" --> A
  U -- "POST /api/import/csv [NFR: InputValidation, Data-Integrity]" --> A
  U -- "GET /api/export?format=csv|json [NFR: Privacy/PII, RateLimiting]" --> A

  A -->|"DTO / Requests"| S1
  A -->|"CSV payload"| S2
  A -->|"Query params"| S3

  S1 -->|"Token SHA-256 [NFR: Secrets]"| D
  S1 -->|"Send reset email [NFR: Privacy]"| X
  X -->|"Email to user"| U

  S2 -->|"Validated data → DB [NFR: Integrity]"| D
  S3 -->|"Select & Format [NFR: Performance]"| D
  S3 -->|"HTTP/gRPC call [NFR: Timeouts]"| Y

  S2 -->|"Audit Import [NFR: Audit]"| D
  S3 -->|"Audit Export [NFR: Audit]"| D

  %% --- Границы доверия ---
  classDef boundary fill:#f6f6f6,stroke:#999,stroke-width:1px;
  class Internet,Service,External boundary;

### 1.2 Диаграмма контекста (Mermaid)
```mermaid
graph TD
  U[Users/Admins] -->|HTTPS| A[API Gateway]
  A -->|RBAC| S3[Export Service]
  A -->|Validation| S2[Import Service]
  A -->|Reset Flow| S1[Auth/Reset Service]
  S1 -->|Hash(token), Audit| D[(DB/Storage)]
  S2 -->|Validated rows| D
  S3 -->|Read/Mask| D
  S1 -->|Email reset| X[SMTP]
  S3 -->|Optional calls| Y[Analytics API]
```

## 2) Активы и цели безопасности
- **Учётные данные и токены сброса** — конфиденциальность, целостность, одноразовость.
- **Наборы клиентских данных/PII** — конфиденциальность, минимизация, законность обработки (GDPR/152‑ФЗ).
- **Доступность сервисов импорта/экспорта** — соблюдение SLO.
- **Операционные логи/аудит** — структурированные, без секретов/PII, трассировка по `correlation_id`.

## 3) Зоны доверия
1) Интернет ↔ Сервис (U↔A) — публичные API, загрузка/выгрузка файлов.  
2) Сервис ↔ Внешние (A↔X/Y) — почта/3rd‑party API.  
3) Сервис ↔ Хранилища (S*↔D) — БД/объектное, политики жизненного цикла.

## 4) STRIDE 

| Категория | Пример в контексте | Основная защита |
|---|---|---|
| S (Spoofing) | Подделка запросов, фишинговые ссылки сброса | Подписанные ссылки, единый ответ на неизвестный email, rate‑limit |
| T (Tampering) | Вредоносный CSV (формульная инъекция, схема) | MIME/размер, белый список схемы, нормализация, защита формул |
| R (Repudiation) | Отказ от факта импорта/экспорта/сброса | Аудит, неизменяемые логи, `correlation_id` |
| I (Information Disclosure) | Утечка PII при экспорте/в логах | RBAC `include_pii`, маскирование, запрет секретов в логах |
| D (Denial of Service) | Массовые импорты/экспорты, тяжелые запросы | Rate‑limit, очереди/воркеры, таймауты |
| E (Elevation of Privilege) | Обход ролей при экспорте | Централизованный RBAC, проверка на шлюзе и в сервисе |

## 5) Реестр рисков (топ)
| ID | Риск | L | I | Обоснование (кратко) |
|---|---|---:|---:|---|
| R‑04 | Tampering при импорте CSV | H | H | Часто, тяжело обнаружить; инъекции формул/структуры |
| R‑03 | Утечка PII при экспорте | M | C | Ошибка роли/флага `include_pii` → критич. утечка |
| R‑05 | Фишинг/злоупотр. письмом сброса | M | H | Компрометация аккаунта через фишинг/повтор |
| R‑01 | Утечка токенов в логах | L | H | Прямая угроза захвата сессии/аккаунта |
| R‑02 | DoS массовыми задачами | M | M | Блокировка воркеров/узких мест I/O |

## 6) Контроли (NFR, выдержки)
**US‑003 Сброс пароля**: энтропия ≥ 128 бит, TTL ≤ 15 мин, одноразово; хранить SHA‑256 хэш; унифицированный ответ; ошибки RFC7807; аудит (время/ip/user_id/correlation_id); лимит ≤5/час на IP/email; почтовые политики SPF/DKIM/DMARC; HSTS.  
**US‑013 Импорт CSV**: ≤10 MiB; MIME allowlist; жёсткая схема (лишние колонки — reject); нормализация (UTC ISO‑8601, NFC, E.164); защита формул; журнал jobId; RFC7807; RBAC (manager/admin).  
**US‑014 Экспорт CSV/JSON**: по умолчанию **без PII**; `include_pii=true` только `admin|dpo`; маскирование; retention 7–30 дней; лимиты/таймауты; RFC7807; owner‑only; аудит/метрики.

## 7) Принятые решения (ADR)
- **ADR (R‑04):** Валидация импорта и лимиты — шлюз: размер/MIME; S2: белый список схемы; нормализация; защита от CSV‑инъекций; RFC7807.
- **ADR (R‑03):** Ролевой фильтр PII при экспорте — `include_pii` только для админов/уполномоченных; маскирование; lifecycle S3 ≤30д; аудит; feature‑flag.
- **ADR (R‑05):** Подписанные HTTPS‑ссылки сброса + почтовые политики — HMAC‑подпись, TTL ≤15м, одноразово; DMARC/SPF/DKIM(+BIMI); rate‑limit /forgot; HSTS; без внешних редиректов.

## 8) Трассировка Threat → NFR → ADR → Тесты
| Threat/Risk | NFR | ADR/Политика | Evidence/Тесты |
|---|---|---|---|
| CSV tampering (R‑04) | NFR‑013‑1/2 | ADR R‑04 | e2e: `import-size-check`, `schema-extra-cols`; unit: `normalize-fields`, `sanitize-formulas` |
| PII export leak (R‑03) | NFR‑014‑1 | ADR R‑03 | e2e: `export_pii_access_test`; unit: `mask_pii_fields`; lifecycle policy |
| Phishing reset (R‑05) | NFR‑003‑1/2/6 | ADR R‑05 | e2e: `email-template-check`, `reset-limit-test`; unit: `token-hmac-verify` |
| Tokens in logs (R‑01) | NFR‑003‑4/7 | Политика mask/strip | Лог‑скан по сигнатурам секретов; JSON‑структура |
| DoS import/export (R‑02) | NFR‑013‑5, NFR‑014‑2 | Rate‑limit + Queue | Нагрузочные тесты; 429 + Retry‑After |

## 9) Тестирование, наблюдаемость, соответствие
- **Контракт ошибок:** RFC7807 с `correlation_id` во всех сервисах.
- **Аудит:** события импорта/экспорта/сброса, правила SIEM для аномалий.
- **Приватность:** экспорт без PII по умолчанию; маскирование; короткий retention.
- **Доступность/SLO:** ≥99.5% для критичных путей (reset/export); целевые perf‑SLO.
- **Почта:** SPF/DKIM/DMARC (p=reject), опц. BIMI.
- **Метрики:** таймеры и счётчики отказов/отбрасываний; дэшборды.

## 10) Открытые вопросы
- Политика обработки ячеек, похожих на формулы: экранировать vs. отклонять файл при порогах.
- Детализация маскировки по полям (пример: телефоны — последние 4 цифры).
- Применение lifecycle к выгрузкам внешней аналитики.
- Коды для просроченных/повторно использованных токенов (410 vs 409).

## 11) Приложения (артефакты)
- DFD — `S04_dfd.md`
- STRIDE‑матрица — `S04_stride_matrix.md`
- Оценка рисков — `S04_risk_scoring.md`
- Реестр NFR — `S03_register.md`
- ADR и Option‑матрицы — `S05_*`

