# SnapPwd Service (API)

[![Live App](https://img.shields.io/badge/Live_App-snappwd.io-00C853?style=for-the-badge&logo=appveyor)](https://snappwd.io)

The high-performance, open-source backend API for [SnapPwd](https://snappwd.io). Built with Rust (Axum) and Redis.

This service powers:
- [SnapPwd Web](https://github.com/SnapPwd/snappwd-web) (Self-hosted frontend)
- [SnapPwd CLI](https://github.com/SnapPwd/snappwd-cli)

## Architecture

- **Zero-Knowledge Payload Storage**: The service receives *already encrypted* data. It never sees encryption keys or the plaintext contents of secrets/files.
  - **Note**: Metadata is *not* encrypted. File `originalFilename` and `contentType`, plus any arbitrary secret `metadata` (e.g. `{"label": "API key for staging"}`), are stored in plaintext in Redis and returned to anyone with the ID via `?peek=true`. Filenames and labels often reveal what a secret is — omit sensitive metadata, or encrypt it client-side before submission.
- **Ephemeral**: Data is stored in Redis with automatic expiration (TTL).
- **Stateless**: No persistent database (SQL/NoSQL) is required, just Redis.

## Prerequisites

- **Redis**: A running Redis instance (version 6.2+ required for atomic GETDEL).
- **Rust**: 1.85+ (if building from source).

## Configuration

Configuration is handled via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | The HTTP port to listen on. | `3000` |
| `REDIS_URL` | Connection string for Redis. | `redis://127.0.0.1:6379` |
| `RUST_LOG` | Log level (e.g., `debug`, `info`). | `info` |

## Running Locally

1. **Start Redis**:
   ```bash
   docker run -d -p 6379:6379 redis
   ```

2. **Run the Service**:
   ```bash
   export REDIS_URL=redis://127.0.0.1:6379
   export PORT=8080
   cargo run
   ```

## Docker Deployment

A `Dockerfile` is included for containerized deployment.

```bash
docker build -t snappwd-service .
docker run -d \
  -p 8080:3000 \
  -e REDIS_URL=redis://your-redis-host:6379 \
  snappwd-service
```

## API Endpoints

- `POST /v1/secrets`: Store an encrypted secret with time-based expiration.
- `GET /v1/secrets/{id}`: Retrieve a secret. Deletes after retrieval by default. Use `?peek=true` to view metadata without deleting.
- `POST /v1/files`: Store an encrypted file with metadata and time-based expiration.
- `GET /v1/files/{id}`: Retrieve a file. Deletes after retrieval by default. Use `?peek=true` to view metadata without deleting.

## License

MIT

## Sender reveal notifications

`POST /v1/secrets` accepts optional `senderEmail`, a single bare ASCII email
address (maximum 254 bytes). Whitespace is trimmed; blank/null/omitted values
opt out. Invalid addresses return 400; non-string values return 422.
If notifications are unconfigured, requests with an address return 503 before
storage; requests without one keep working.

Configure `SMTP_HOST`, `SMTP_FROM`, and optionally `SMTP_PORT` (default 587).
Authentication uses `SMTP_USERNAME` and `SMTP_PASSWORD` together. STARTTLS is
required and server certificates are verified. Partial/invalid configuration
fails startup. Keep credentials in deployment secrets. No production setup or
migration is applied by this change; deploy the service and configure SMTP before
enabling an email field in clients.

The address is stored privately in the same Redis record and expires/deletes
with the secret. It is excluded from create, peek, and reveal responses. Only the
winner of atomic GETDEL sends a notification; peek, expiration, repeat access,
and legacy records without an address never send mail. The email contains the
secret ID, never ciphertext, keys, metadata, or a reveal link. It confirms API
retrieval, since successful browser decryption is invisible to this service.

Delivery is a single best-effort attempt awaited for at most five seconds.
Failures are logged without addresses or SMTP error details and do not prevent
returning the encrypted secret. There is no retry/outbox: crashes after deletion
or SMTP failures can lose the notification. SMTP acceptance does not guarantee
inbox delivery.

Run `cargo test` for unit tests. Run the real Redis + local SMTP sink integration
suite with a dedicated Redis 6.2+ instance:

```sh
TEST_REDIS_URL=redis://127.0.0.1:6379 cargo test notification_lifecycle -- --ignored
```
