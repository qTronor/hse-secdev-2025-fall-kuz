# ADR: Signed HTTPS Reset Link + Mail Policies (Anti-Phishing)
Status: Proposed

## Context
Risk: `R-05 “Фишинговые письма сброса пароля” (L=3, I=5, Score=15) — высокая частота фишинга и критичные последствия захвата учётки.`
DFD: `X --> U, U --> A, A --> S1, S1 --> D`
NFR: `NFR-003-1, NFR-003-2, NFR-003-6`
Assumptions:
- Есть собственный домен рассылки; контролируем шаблоны писем.
- Хотим быстрое снижение риска без заметного ухудшения UX.
- Почтовая инфраструктура поддерживает SPF/DKIM/DMARC.

## Decision
Применяем кликабельную **подписанную HTTPS-ссылку** на бренд-домене, с коротким TTL и одноразовостью, усиливаем почтовые политики против спуфинга.
- Param/Policy: **Link format** `https://accounts.<domain>/reset?token=<jti>&sig=<base64url(HMAC-SHA256)>` (scope: reset).
    - **TTL ≤ 15 мин**, **single-use**; `token` хранится как **SHA-256** хэш (NFR-003-1).
    - **Signature**: `sig = HMAC-SHA256(secret, jti|sub|iat|exp|aud)`; clock skew ≤ 60 s.
    - **Host allowlist**: принимаем только `accounts.<domain>`; **HSTS**; запрет внешних редиректов.
- Param/Policy: **Email template** — без PII, только ссылка; `From: security@<domain>`; понятный текст, где явно указан домен (NFR-003-2).
- Param/Policy: **SPF/DKIM/DMARC (p=reject)** для домена рассылки; (опц.) **BIMI**.
- Param/Policy: **Rate limit** `POST /api/auth/forgot` ≤ **5 req/час** per IP/email; превышение → **429** + `Retry-After` (NFR-003-6).
- Param/Policy: **Error/Reuse handling**: истёкший токен → **410** (RFC7807), повторное использование → **409** (RFC7807); единый ответ на неизвестный email (NFR-003-3, если принят).
- Notes: Слой — ссылка/валидация в S1, лимиты на gateway, почтовые политики — на почтовом домене/провайдере.

## Alternatives
- **B: Linkless OTP (одноразовый код в письме, переход вручную).** Отклонено сейчас: выше сложность (новые UX-экраны, хранение/валидация OTP), больше трение для пользователя, дольше внедрение. Рассматривать как опциональный «строгий режим».

## Consequences
**Положительные:**
- Быстрый и понятный пользователю поток восстановления; существенное снижение риска фишинга и повторного использования ссылки.
- Улучшенная доставляемость и доверие к письмам (DMARC/BIMI), наблюдаемость кликов/ошибок подписи.

**Негативные/издержки:**
- Не устраняет полностью социальную инженерию (user всё ещё кликает по ссылке).
- Требует безопасного хранения ключа HMAC и дисциплины в управлении доменом рассылки.

## DoD / Acceptance
Given письмо сброса отправлено  
When пользователь открывает ссылку с **истёкшим** `exp`  
Then ответ **410** с `Content-Type: application/problem+json`, полями RFC7807 и `correlation_id`; токен остаётся невалидным в БД

Given повторный клик по уже использованной ссылке  
When запрос в `POST /api/auth/reset` с тем же `token`  
Then ответ **409** (RFC7807) без утечки наличия аккаунта; в аудите запись о повторе

Given письмо с **подменённым доменом** в ссылке  
When запрос приходит на хост, не входящий в allowlist  
Then запрос отклоняется **400**/**403** (RFC7807); событие фиксируется в логах (reason=`host_not_allowed`)

Given частые запросы forgot с одного IP/email  
When порог **5/час** превышен  
Then часть запросов получает **429** + корректный `Retry-After`

Checks:
- test: e2e `email-template-check` (нет PII, корректный домен/HTTPS), e2e `reset-limit-test`, unit `token-hmac-verify`, unit `single-use-mark`.
- log: JSON-логи без токена/PII; поля `event=reset_link_clicked|token_used|token_reused`, `correlation_id`, `user_id/null`, `ip`.
- scan/policy: DMARC `p=reject` включён; DKIM валиден; HSTS для `accounts.<domain>`.
- metric/SLO: доля отказов по `host_not_allowed` и `sig_invalid` видна; нет роста P95 > базовой линии на форме reset.

## Rollback / Fallback
Feature flag `reset_signed_link_enabled`. Откат: выключить проверку `sig`/одноразовости, оставить TTL и rate limit; мониторить рост успешных сбросов/жалоб на фишинг. В случае проблем доставки — временно ослабить DMARC до `p=quarantine` (с планом возврата к `p=reject`).

## Trace
- DFD: `S04_dfd.md` — `X --> U, U --> A, A --> S1, S1 --> D`
- STRIDE: `S04_stride_matrix.md` — Edge: U→A, Edge: S1→X
- Risk scoring: `S04_risk_scoring.md` — R-05 (Top-5)
- NFR: `S03` — NFR-003-1, NFR-003-2, NFR-003-6
- Issues: `#reset-signed-link`, `#dmarc-rollout`, `#rate-limit-forgot`

## Ownership & Dates
Owner: backend  
Reviewers: security, devops, QA  
Date created: 2025-10-12  
Last updated: 2025-10-12

## Open Questions
- Политика для «linkless OTP» как альтернативного канала — включать per-tenant/per-user?
