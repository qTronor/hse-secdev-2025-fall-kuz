# S04 - DFD для проекта "Data & Account Service"

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
