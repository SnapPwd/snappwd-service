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

- **Redis**: A running Redis instance (version 6.2+ required for GETDEL).
- **Rust**: 1.70+ (if building from source).

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

- `POST /v1/secrets`: Store an encrypted secret with time-based expiration.
- `GET /v1/secrets/{id}`: Retrieve a secret. Deletes after retrieval by default. Use `?peek=true` to view metadata without deleting.
- `POST /v1/files`: Store an encrypted file with metadata and time-based expiration.
- `GET /v1/files/{id}`: Retrieve a file. Deletes after retrieval by default. Use `?peek=true` to view metadata without deleting.

## License

MIT

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
