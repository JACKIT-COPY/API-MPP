# Payouts Review — API-MPP

Date: 2026-01-07

## Scope
- Files inspected: [server.js](server.js#L2736-L3120)
- Endpoints reviewed: `GET /creators/:creatorId/earnings`, `POST /creators/:creatorId/payouts/request`, `POST /api/mpesa/b2c_callback`, `PUT /creators/:creatorId/payout-settings`, `GET /creators/:creatorId/transactions/export`

## High-level observations
- The payout flow uses a `transactions` audit trail and DB transactions (`BEGIN`/`COMMIT`/`ROLLBACK`) — good for traceability.
- The code inserts a pending payout row before calling the external payment provider (good practice), and a callback endpoint updates status.

## High-priority issues (action required)
1. Sensitive logging
   - The code logs access tokens, security credentials, full payloads and provider responses. These logs risk leaking secrets and should be removed or redacted immediately.
   - Examples: token/credential logs and B2C payload/response dumps in `server.js`.

2. Race condition / double-withdrawal risk
   - Available-balance is computed, then a payout row is inserted; concurrent requests can cause overspend.
   - Mitigation: acquire a per-creator lock (DB advisory lock) or SELECT ... FOR UPDATE on a dedicated balances row; compute balance + insert while locked.

3. Balance calculation fragility
   - Current SQL uses NOT EXISTS to exclude covered subscriptions; the logic is complex and fragile.
   - Recommendation: simplify by treating payouts as negative amounts and computing available = SUM(subscriptions) + SUM(payouts) (or explicit formula using ABS for payouts).

4. Decimal handling: `parseInt` used for monetary amounts
   - `transactions.amount` is NUMERIC(10,2) but code uses `parseInt`, losing cents. Use `parseFloat` (or a BigDecimal/decimal library) and validate currency precision.

5. Callback matching fragility
   - The code updates `transaction_id` with the provider's `OriginatorConversationID` after initiating B2C call. If callback arrives before that update, lookup fails.
   - Mitigation: persist both a local `id`/`local_txn` and a `provider_originator_id` field atomically before calling the provider; use the provider id to match callbacks.

6. Callback authenticity and validation
   - The callback endpoint trusts incoming payloads. Add verification (HMAC/signature if provided), IP allowlist, or secret URL token — and require HTTPS.

7. Error exposure
   - Avoid returning raw `error.message` or stack traces in production responses.


## Medium / operational issues
- Unsupported payment methods (`bank`, `paypal`, `stripe`) are allowed in settings but not implemented — either disable in UI or add stubs with clear errors.
- Payout settings phone validation only accepts `254XXXXXXXXX`. Consider normalizing inputs (accept `+254`, `07...`) and convert.
- Logging should be reduced to structured, non-sensitive traces and error events should trigger alerts.

## Suggested quick fixes (I can implement)
1. Remove/redact logs that print tokens, security credentials, full payloads, and provider responses.
2. Replace `parseInt` with `parseFloat` when parsing DB `amount` values; ensure formatting with two decimals when writing CSV/export.
3. Add a DB advisory lock around the balance check and payout insert to prevent concurrent oversubscription.
4. Add `mpesa_originator_id` (nullable) column and update transaction logic to write provider IDs before awaiting callback; match callback against `mpesa_originator_id`.
5. Harden the callback handler: coerce `ResultCode` to Number, validate payload shape, and log only non-sensitive parts.

## Longer-term improvements
- Normalize transaction semantics: store positive amounts for income, negative for payouts (or keep positive and add `direction` column). Make balance calculations explicit and well-tested.
- Add integration tests that simulate concurrent payout requests to verify locking prevents double withdrawals.
- Add monitoring/alerts for long-pending payouts and high failure rates.
- Implement idempotency keys for payout requests so retries are safe.
- Add rate-limiting to payout endpoints and enforce stricter authorization checks.

## Recommended next steps
1. Apply quick fixes 1–4 above (redact logs, parseFloat, advisory lock, and dual-ID column). I can implement these changes now.
2. Add unit/integration tests for balance calculation and callback processing.
3. Review provider docs to implement callback verification and full error-handling for M-Pesa B2C.

## References (key lines)
- Payout request handler: [server.js](server.js#L2736-L2878)
- B2C callback: [server.js](server.js#L2920-L2950)
- Earnings and balance query: [server.js](server.js#L2640-L2760)
- Payout settings endpoint: [server.js](server.js#L2920-L3043)

---
If you want, I can open a PR implementing the quick fixes now (redaction, parseFloat, advisory lock, and storing provider IDs). Which changes should I start with?
