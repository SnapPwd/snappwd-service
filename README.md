# SnapPwd Service (API)

[![Live App](https://img.shields.io/badge/Live_App-snappwd.io-00C853?style=for-the-badge&logo=appveyor)](https://snappwd.io)

The high-performance, open-source backend API for [SnapPwd](https://snappwd.io). Built with Rust (Axum) and Redis.

This service powers:
- [SnapPwd Web](https://github.com/SnapPwd/snappwd-web) (Self-hosted frontend)
- [SnapPwd CLI](https://github.com/SnapPwd/snappwd-cli)

## Architecture

- **Zero-Knowledge Payload Storage**: The service receives *already encrypted* data. It never sees encryption keys or the plaintext contents of secrets/files.
  - **Note**: Metadata is *not* encrypted. File `originalFilename` and `contentType`, plus supported secret `metadata` (e.g. `{"label": "API key for staging"}`), are stored in plaintext in Redis and returned to anyone with the ID via `?peek=true`. Filenames and labels often reveal what a secret is — omit sensitive metadata, or encrypt it client-side before submission.
- **Ephemeral**: Data is stored in Redis with automatic expiration (TTL).
- **Stateless**: No persistent database (SQL/NoSQL) is required, just Redis.

## Metadata limits and rendering

Secret metadata accepts only `label`, `intendedRecipient`, `note`, `rotateBy`,
`rotationReason`, and `shareType`, with respective limits of 120, 254, 1000, 64,
240, and 64 UTF-8 bytes after trimming. Empty values are dropped. The normalized
metadata object is additionally limited to **4 KiB (4096 serialized JSON bytes)**,
including keys and JSON escaping. Invalid metadata returns `422`. These limits
apply to new submissions; legacy stored metadata remains readable until expiry.

The notification address is not metadata: `senderEmail` is a separate top-level
request field (see [Sender reveal notifications](#sender-reveal-notifications)),
so these limits and the field allowlist do not apply to it.

All returned metadata is **untrusted input**. Consumers must use text rendering
or context-appropriate escaping for labels, notes, file `originalFilename`, and
other metadata. Never insert them as raw HTML. Size/schema validation does not
make a string safe to render.

## Prerequisites

- **Redis**: A running Redis instance (version 6.2+ required for atomic GETDEL).
- **Rust**: 1.85+ (if building from source).

## Configuration

Configuration is handled via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | The HTTP port to listen on. | `8080` |
| `REDIS_URL` | Connection string for Redis. | `redis://127.0.0.1:6379` |
| `MAX_FILE_SIZE_MB` | Maximum encrypted file size before base64 overhead. | `2` |
| `WRITE_REQUESTS_PER_MINUTE` | Combined write attempts per client IP per 60-second window, shared across replicas using Redis. | `10` |
| `STORAGE_MAX_BYTES` | Redis allocated-memory admission threshold, including legacy data and prospective serialized payload/overhead. | `134217728` (128 MiB) |
| `STORAGE_MAX_KEYS` | Maximum keys in the selected Redis database, including legacy data and rate-limit keys. | `10000` |
| `WRITE_API_TOKEN` | Optional bearer token for both POST routes; at least 32 non-space ASCII characters. | unset (public writes) |
| `TRUSTED_PROXY_IPS` | Comma-separated literal socket-peer IPs permitted to supply a single `X-Real-IP`. | empty |
| `RUST_LOG` | Log level (e.g., `debug`, `info`). | `info` |

## Secret payload limits

`encryptedSecret` is limited to **1.5 MiB (1572864 UTF-8 bytes)** after JSON decoding,
including the ciphertext's encoding/encryption envelope, rather than the original
plaintext size. Larger values return `400`. The complete `POST /v1/secrets` JSON
body is limited to **2 MiB (2097152 bytes)** and larger bodies return `413`,
independently of `MAX_FILE_SIZE_MB`.

## Running Locally

1. **Start Redis**:
   ```bash
   docker run -d -p 127.0.0.1:6379:6379 --memory 384m redis:7-alpine \
     redis-server --maxmemory 256mb --maxmemory-policy volatile-ttl
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
  -p 8080:8080 \
  -e REDIS_URL=redis://your-redis-host:6379 \
  snappwd-service
```

## API Endpoints

- `POST /v1/secrets`: Store an encrypted secret with time-based expiration; returns `200` and an `sps-` ID.
- `GET /v1/secrets/{id}`: Retrieve a secret. Deletes after retrieval by default. Use `?peek=true` to view metadata without deleting.
- `POST /v1/files`: Store an encrypted file with metadata and time-based expiration; returns `200` and an `spf-` ID.
- `GET /v1/files/{id}`: Retrieve a file. Deletes after retrieval by default. Use `?peek=true` to view metadata without deleting.

## License

MIT

## Sender reveal notifications

`POST /v1/secrets` and `POST /v1/files` accept optional `senderEmail`, a single bare ASCII email
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
with the secret or file. It is excluded from create, peek, and reveal responses. Only the
winner of atomic GETDEL sends a notification; peek, expiration, repeat access,
and legacy records without an address never send mail. The email contains the
secret/file ID, never ciphertext, keys, metadata, or a reveal link. It confirms API
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

File notifications use the same SMTP configuration and failure semantics. File
retrieval responses preserve metadata, encryptedData and createdAt, while the
private senderEmail is never serialized into a public response.

## Abuse protection and rollout

Both POST routes enforce admission before reading/parsing the body. Invalid or missing
write credentials return `401`; rate exhaustion returns `429` with `Retry-After` in
seconds. Redis failure or capacity exhaustion returns `503`, including for rate-limit
state creation. Reads and CORS preflight remain public. The existing transport body
limit still applies (`413`). Invalid requests consume a write allowance.

Use a dedicated standalone Redis instance/database for this service. All replicas must
use the same database and protection settings. Atomic Lua scripts check `DBSIZE` and
`INFO memory` before writes, including pre-existing records; no migration or counter
backfill is required. Memory admission reserves twice the serialized value length plus
1 KiB of overhead. This is a conservative estimate, not an exact allocator/RSS limit;
configure Redis `maxmemory` separately, with ample headroom above `STORAGE_MAX_BYTES`
for temporary allocations, connections, script execution and allocator fragmentation.
Keep a container/host memory limit above Redis `maxmemory`. Key slots and memory become
available after one-time `GETDEL` or expiration, without a separate accounting ledger.
The Redis ACL must permit `INFO`, `DBSIZE`, `EVALSHA`/`EVAL`/`SCRIPT LOAD`, `GET`, `SET`,
`INCR`, `TTL`, `GETDEL` and existing read operations. Redis Cluster is not supported.

`compose.yaml` and `redis.conf` supply an example deployment with Redis `maxmemory
256mb`, `volatile-ttl`, and a 384 MiB container limit; start with `docker compose up
--build`. Redis is accessible only on the internal network. The service never changes
Redis configuration automatically. Apply equivalent settings to managed Redis before
public exposure. Monitor memory, evictions and `429`/`503` responses. Under emergency
memory pressure, `volatile-ttl` can evict any expiring record early, including a secret
or rate-limit counter; that can cause early `404`s or reset an allowance. If preserving
records until their TTL is required, use `noeviction` and accept rejected writes instead.
See [Redis eviction behavior](https://redis.io/docs/latest/develop/reference/eviction/).

By default the socket peer is the client IP; forwarded headers are ignored. Behind a
reverse proxy, set `TRUSTED_PROXY_IPS` to its exact peer addresses and configure it to
**overwrite** `X-Real-IP` with the verified client IP. Missing, duplicate, or malformed
headers from a trusted proxy return `400`. Keep direct access to the backend restricted.
Without this configuration clients behind the proxy share one write allowance. IPv4
mapped IPv6 addresses are normalized. Rate limits are per IP, so shared NATs share an
allowance and distributed attackers can still fill the bounded capacity.

For private deployments, set `WRITE_API_TOKEN` to a randomly generated token and send
`Authorization: Bearer <token>` on POST requests over HTTPS. Enabling it requires
updating every writer; recipients can still retrieve shares without a token. Never
embed a shared server token in a public browser bundle. Public browser deployments
can leave the token unset and rely on rate/storage limits plus edge traffic controls.

## Verification

```bash
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
# Against an explicitly disposable Redis database (test flushes that database):
TEST_REDIS_URL=redis://127.0.0.1:16389 cargo test --locked redis_admission -- --ignored
```

The Redis integration test exercises concurrent rate/storage admission, limiter state
bounds, memory rejection, TTL reclamation and one-time access races.
