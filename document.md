# Password reset delivery over RabbitMQ

## What was broken

Two things, both on this branch:

1. `passwdmgt/handlers.go` had a `DeliverPasswordReset` method that was a stub:
   ```go
   func (handler *DBHandler) DeliverPasswordReset(email, phone, token string) error {
       return nil
   }
   ```
   It satisfied the `ResetTokenDeliverer` interface that `ForgotPasswordHandler` calls, but did nothing — it always returned `nil` without sending the token anywhere.

2. `main.go` never gave `passwdHandler` a `Deliverer` at all, so in production `h.Deliverer == nil` was always true, and `ForgotPasswordHandler` just logged "no deliverer configured" and skipped delivery entirely — even once (1) was fixed, nothing would have called it.

There was also a latent bug in `messaging/rabbitmq.go`:
```go
conn, err := amqp.Dial("RABBITMQ_URL")
```
That dials the literal string `"RABBITMQ_URL"`, not the value of the environment variable. It never worked.

## What changed, file by file

### `messaging/rabbitmq.go`
- Fixed the `Dial` bug: `amqp.Dial(os.Getenv("RABBITMQ_URL"))`, with the same fail-fast pattern `ConnectDatabase` (`database.go`) already uses for the Postgres env vars — if `RABBITMQ_URL` is empty, `NewRabbitMQ` returns an error immediately instead of trying to dial an empty string.
- Added two queue-name constants: `PasswordResetEmailQueue = "password_reset_email"` and `PasswordResetSMSQueue = "password_reset_sms"`.
- Added `PublishJSON(queueName string, payload any) error` — declares the queue (durable, idempotent — safe to call every time) and publishes `payload` as a persistent JSON message.

### `passwdmgt/handlers.go`
- Added a `publisher` interface (`PublishJSON(queueName string, payload any) error`) — the narrow slice of `*messaging.RabbitMQ` that `DeliverPasswordReset` actually needs. This mirrors the existing `sqlExecutor`/`ResetTokenDeliverer` pattern already used in this codebase, and it's what makes `DeliverPasswordReset` unit-testable without a real broker (see `recordingPublisher` in the test file).
- Added an `MQ publisher` field to `DBHandler`.
- Implemented `DeliverPasswordReset`: if `email` is non-empty, publish `{email, token}` to `password_reset_email`; if `phone` is non-empty, publish `{phone, token}` to `password_reset_sms`. Both are attempted independently (one queue's failure doesn't skip the other), and any errors are combined with `errors.Join` and returned.

### `main.go`
- Connects to RabbitMQ right after the DB connects: `mq, err := messaging.NewRabbitMQ()`, `log.Fatal` on failure (same as the DB connect), `defer mq.Close()`.
- `passwdHandler := passwdmgt.DBHandler{DB: db, MQ: mq}` then `passwdHandler.Deliverer = &passwdHandler` — this second line has to be separate because a struct literal can't take the address of itself inline. This is what actually turns on delivery: `DBHandler` acts as its own `Deliverer`, backed by `MQ`.

### `docker-compose.yaml`
- Added a `rabbitmq` service (`rabbitmq:3-management`) alongside the existing Postgres `db` service, with credentials matching what's already in `.env`'s `RABBITMQ_URL`, so `docker compose up` gives you a broker that the app can connect to out of the box.

### Tests
- `passwdmgt/handlers_test.go`: added `recordingPublisher`, a fake `publisher` (same style as the existing `recordingDeliverer`), and `Test_DeliverPasswordReset`, which covers: both contacts present, only email, only phone, one queue failing while the other still gets attempted, and both queues failing.
- `messaging/rabbitmq_test.go` (new): a single `TestNewRabbitMQ_MissingURL` test confirming the fail-fast behavior when `RABBITMQ_URL` is unset. `PublishJSON` itself isn't unit-tested here since it wraps a real broker connection — the `passwdmgt` tests above cover the calling logic through the `publisher` interface instead.

`ForgotPasswordHandler` itself did not need to change — it already nil-checks `Deliverer` and only logs (never fails the HTTP response) if delivery errors, which is exactly the right behavior for the new implementation too.

## The mental model (if RabbitMQ is new to you)

- A **connection** is the TCP link to the broker; a **channel** is a lightweight virtual connection multiplexed over it — almost everything (declaring queues, publishing) happens on a channel, not the connection directly. That's why `RabbitMQ` holds both `Conn` and `Ch`.
- A **queue** is where messages actually sit until a consumer reads them. `QueueDeclare` creates it if it doesn't exist yet, or is a no-op if it already exists with the same settings — that's why it's safe to call on every publish rather than once at startup.
- An **exchange** is what a publisher actually sends messages to; it then routes them into queues based on rules. We're using the **default exchange** (name `""`), which every RabbitMQ broker provides for free: it routes a message straight into the queue whose name matches the routing key exactly. So `Publish("", "password_reset_email", ...)` delivers directly into the `password_reset_email` queue — no separate binding step needed.
- We use **two queues** instead of one because they represent two independent delivery channels (email vs. SMS) that a real system would have two separate worker processes consuming from — an email-sending worker never needs to see a phone number, and vice versa. Only one of `email`/`phone` is populated per message, by design.
- `DeliveryMode: amqp.Persistent` tells the broker to write the message to disk, so it survives a broker restart while it's still queued and unconsumed.

## How to test it

### 1. Start the broker (and DB)

```bash
docker compose up -d
```

This starts Postgres on `5432` and RabbitMQ on `5672` (AMQP) and `15672` (management UI), with credentials matching the `RABBITMQ_URL` already in `.env`.

Confirm `.env` has:
```
RABBITMQ_URL=amqp://my_rabbit_admin_user:complex_password_xyz_4_rabbit@localhost:5672/
```
(This was already present before this change — only the code that reads it was fixed.)

### 2. Run the app

```bash
go run .
```

If `RABBITMQ_URL` is missing or the broker isn't reachable, the app now fails fast at startup with a clear error instead of silently running with no delivery (the old, broken behavior).

### 3. Trigger a password reset

`/auth/forgot-password` only delivers a token for an account that actually exists in the `users` table, so you need a real seeded row first (register a user via `/auth/register`, or insert one directly). Then:

```bash
curl -X POST localhost:8000/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email":"someone@example.com"}'
```

The HTTP response is always `200` with the same generic message, whether or not the account exists (that's deliberate — see the comment on `ForgotPasswordHandler`) and even if RabbitMQ publishing fails. Publish failures only show up in the server log.

### 4. Watch it arrive

Open `http://localhost:15672` and log in with the same credentials as `RABBITMQ_URL` (`my_rabbit_admin_user` / `complex_password_xyz_4_rabbit`). Under **Queues**, you should see `password_reset_email` (or `password_reset_sms`, if you reset by phone) with a message count. Click into it and use **Get messages** to inspect the actual JSON payload — you'll see `{"email": "...", "token": "..."}`.

### 5. Run the automated tests

```bash
go test ./...
```

All packages should pass, including the new `Test_DeliverPasswordReset` cases in `passwdmgt` and `TestNewRabbitMQ_MissingURL` in `messaging`. These don't need Docker or a real broker running — they use the `recordingPublisher` fake and an env-var check respectively.

### Things worth trying to build intuition

- Stop the `rabbitmq` container (`docker compose stop rabbitmq`) and hit `/auth/forgot-password` again — the HTTP call still returns `200`, but you'll see a `failed to deliver password reset for user ...` line in the server log. This is the "delivery failure never surfaces to the caller" behavior mentioned above.
- Reset by phone instead of email (`{"phone": "..."}`) and check the management UI again — you should see `password_reset_sms` get the message instead of `password_reset_email`.
- Restart the `rabbitmq` container after publishing a message that hasn't been consumed yet — it should still be there afterward, because of `DeliveryMode: amqp.Persistent`.
