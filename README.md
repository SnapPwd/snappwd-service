# SnapPwd Service (API)

[![Live App](https://img.shields.io/badge/Live_App-snappwd.io-00C853?style=for-the-badge&logo=appveyor)](https://snappwd.io)

The high-performance, open-source backend API for [SnapPwd](https://snappwd.io). Built with Rust (Axum) and Redis.

This service powers:
- [SnapPwd Web](https://github.com/SnapPwd/snappwd-web) (Self-hosted frontend)
- [SnapPwd CLI](https://github.com/SnapPwd/snappwd-cli)

## Architecture

- **Zero-Knowledge Storage**: The service receives *already encrypted* data. It never sees encryption keys or plaintext.
- **Ephemeral**: Data is stored in Redis with automatic expiration (TTL).
- **Stateless**: No persistent database (SQL/NoSQL) is required, just Redis.

## Prerequisites

- **Redis**: A running Redis instance (version 6+ recommended).
- **Rust**: 1.70+ (if building from source).

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
