# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-23

### Added

- Rust/Axum API for storing and retrieving client-encrypted secrets and files,
  with Redis expiration, atomic one-time retrieval, and metadata-only peeking.
- Separate `sps-` and `spf-` identifiers, bounded payloads and validated secret
  metadata. Metadata remains plaintext; encryption keys stay with clients.
- Optional sender email notifications after retrieval, including accessor details
  and authenticated client information supplied by a trusted frontend.
- Optional write authentication, per-IP write limits, Redis storage admission
  limits, and explicit trusted proxy configuration.
- Docker and Docker Compose self-hosting setup with bounded Redis memory.
- MIT license, API documentation, and Rust unit and Redis integration tests.

[Unreleased]: https://github.com/SnapPwd/snappwd-service/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SnapPwd/snappwd-service/releases/tag/v0.1.0
