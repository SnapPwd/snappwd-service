# Use a multi-stage build for small final image
FROM rust:1.84-slim-bookworm as builder

WORKDIR /usr/src/app
COPY . .

# Install build dependencies (if any needed, e.g. pkg-config, libssl-dev)
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Build the release binary
RUN cargo build --release

# Final runtime image
FROM debian:bookworm-slim

# Install runtime dependencies (OpenSSL is common)
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/local/bin

# Copy the binary from the builder
COPY --from=builder /usr/src/app/target/release/snappwd-service .

# Set default env vars (can be overridden)
ENV RUST_LOG=info
ENV PORT=8080

# Cloud Run expects the container to listen on $PORT
CMD ["sh", "-c", "./snappwd-service"]
