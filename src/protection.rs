use crate::{models::ErrorResponse, AppState};
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use std::net::{IpAddr, SocketAddr};

#[derive(Clone)]
pub struct Config {
    pub max_bytes: u64,
    pub max_keys: u64,
    pub writes_per_minute: u64,
    pub write_token: Option<String>,
    pub trusted_proxies: Vec<IpAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_bytes: 128 * 1024 * 1024,
            max_keys: 10_000,
            writes_per_minute: 10,
            write_token: None,
            trusted_proxies: vec![],
        }
    }
}

impl Config {
    pub fn from_env() -> Self {
        fn positive(name: &str, default: u64) -> u64 {
            match std::env::var(name) {
                Ok(value) => value
                    .parse::<u64>()
                    .ok()
                    .filter(|n| *n > 0 && *n <= (1 << 53))
                    .unwrap_or_else(|| panic!("{name} must be a positive integer <= 2^53")),
                Err(std::env::VarError::NotPresent) => default,
                Err(_) => panic!("{name} must be valid UTF-8"),
            }
        }
        let defaults = Self::default();
        let write_token = match std::env::var("WRITE_API_TOKEN") {
            Ok(token) => {
                assert!(
                    token.len() >= 32 && token.bytes().all(|b| b.is_ascii_graphic()),
                    "WRITE_API_TOKEN must contain at least 32 printable non-space ASCII characters"
                );
                Some(token)
            }
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => panic!("WRITE_API_TOKEN must be valid UTF-8"),
        };
        let trusted_proxies = std::env::var("TRUSTED_PROXY_IPS")
            .unwrap_or_default()
            .split(',')
            .filter(|v| !v.trim().is_empty())
            .map(|v| {
                v.trim()
                    .parse()
                    .expect("TRUSTED_PROXY_IPS must contain literal IP addresses")
            })
            .collect();
        Self {
            max_bytes: positive("STORAGE_MAX_BYTES", defaults.max_bytes),
            max_keys: positive("STORAGE_MAX_KEYS", defaults.max_keys),
            writes_per_minute: positive("WRITE_REQUESTS_PER_MINUTE", defaults.writes_per_minute),
            write_token,
            trusted_proxies,
        }
    }
}

// Redis serializes scripts, so concurrent writers/replicas cannot race past
// admission. Count all keys (including legacy data and limiter keys); use Redis's
// actual allocated memory, with conservative room for the next value/overhead.
const CAPACITY: &str = r#"
local function capacity(extra)
    local memory = redis.call('INFO', 'memory')
    local used = tonumber(string.match(memory, 'used_memory:(%d+)'))
    return used and used + extra <= tonumber(ARGV[1])
        and redis.call('DBSIZE') < tonumber(ARGV[2])
end
"#;

pub async fn store(
    client: &redis::Client,
    config: &Config,
    id: &str,
    value: &str,
    ttl: u64,
) -> Result<(), redis::RedisError> {
    let script = redis::Script::new(&format!(
        "{CAPACITY}\n\
        if not capacity(string.len(ARGV[3]) * 2 + 1024) then return 0 end\n\
        return redis.call('SET', KEYS[1], ARGV[3], 'EX', ARGV[4], 'NX') and 1 or 0"
    ));
    let mut conn = client.get_multiplexed_async_connection().await?;
    let admitted: i64 = script
        .key(id)
        .arg(config.max_bytes)
        .arg(config.max_keys)
        .arg(value)
        .arg(ttl)
        .invoke_async(&mut conn)
        .await?;
    if admitted != 1 {
        return Err(redis::RedisError::from((
            redis::ErrorKind::ResponseError,
            "Storage capacity exceeded",
        )));
    }
    Ok(())
}

// Fixed window anchored at the first request; rejected requests do not extend
// the window or grow the counter. Both creation routes share one IP allowance.
pub async fn rate_limit(
    client: &redis::Client,
    config: &Config,
    ip: IpAddr,
) -> Result<i64, redis::RedisError> {
    let script = redis::Script::new(&format!(
        "{CAPACITY}\n\
        local count = tonumber(redis.call('GET', KEYS[1]) or '0')\n\
        if count >= tonumber(ARGV[3]) then return math.max(1, redis.call('TTL', KEYS[1])) end\n\
        if count == 0 then\n\
            if not capacity(1024) then return -1 end\n\
            redis.call('SET', KEYS[1], 1, 'EX', 60)\n\
        else redis.call('INCR', KEYS[1]) end\n\
        return 0"
    ));
    let mut conn = client.get_multiplexed_async_connection().await?;
    script
        .key(format!("snappwd:write-rate:{ip}"))
        .arg(config.max_bytes)
        .arg(config.max_keys)
        .arg(config.writes_per_minute)
        .invoke_async(&mut conn)
        .await
}

fn error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: message.into(),
        }),
    )
        .into_response()
}

fn client_ip(request: &Request, config: &Config) -> Option<IpAddr> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()?
        .0
        .ip();
    let peer = match peer {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(peer),
        _ => peer,
    };
    if config.trusted_proxies.contains(&peer) {
        // Require a single IP overwritten by the trusted proxy, never accept a
        // client-controlled X-Forwarded-For chain.
        let mut values = request.headers().get_all("x-real-ip").iter();
        let ip = values.next()?.to_str().ok()?.parse::<IpAddr>().ok()?;
        if values.next().is_some() {
            return None;
        }
        Some(match ip {
            IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(ip)),
            _ => ip,
        })
    } else {
        Some(peer)
    }
}

pub async fn guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if let Some(token) = &state.protection.write_token {
        let expected = format!("Bearer {token}");
        // Constant-time comparison for equal-length credentials.
        let mut headers = request.headers().get_all(header::AUTHORIZATION).iter();
        let provided = headers.next().map(|v| v.as_bytes()).unwrap_or_default();
        let mismatch = provided.len() != expected.len()
            || provided
                .iter()
                .zip(expected.bytes())
                .fold(0u8, |diff, (a, b)| diff | (*a ^ b))
                != 0;
        if mismatch || headers.next().is_some() {
            let mut response = error(StatusCode::UNAUTHORIZED, "Valid write token required");
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
            return response;
        }
    }
    let Some(ip) = client_ip(&request, &state.protection) else {
        return error(StatusCode::BAD_REQUEST, "Client IP unavailable or invalid");
    };
    match rate_limit(&state.redis, &state.protection, ip).await {
        Ok(0) => next.run(request).await,
        Ok(retry) if retry > 0 => {
            let mut response = error(StatusCode::TOO_MANY_REQUESTS, "Write rate limit exceeded");
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, retry.to_string().parse().unwrap());
            response
        }
        result => {
            if let Err(e) = result {
                tracing::error!("Write admission failed: {e}");
            }
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Storage unavailable or capacity exceeded",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::Request as HttpRequest,
        routing::{get, post},
        Router,
    };
    use tower::ServiceExt;

    fn state(config: Config) -> AppState {
        AppState {
            redis: std::sync::Arc::new(redis::Client::open("redis://127.0.0.1:1").unwrap()),
            max_file_size_bytes: 2 * 1024 * 1024,
            protection: config,
        }
    }
    fn app(state: AppState) -> Router {
        Router::new()
            .route("/v1/secrets", post(|| async { "ok" }))
            .route("/v1/files", post(|| async { "ok" }))
            .route_layer(axum::middleware::from_fn_with_state(state, guard))
            .route("/read", get(|| async { "ok" }))
    }
    fn request(path: &str) -> Request {
        let mut req = HttpRequest::builder()
            .method("POST")
            .uri(path)
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo("192.0.2.1:1234".parse::<SocketAddr>().unwrap()));
        req
    }

    #[test]
    fn proxy_headers_are_only_trusted_from_configured_peers() {
        let mut req = request("/v1/secrets");
        req.headers_mut()
            .insert("x-real-ip", "198.51.100.2".parse().unwrap());
        let mut config = Config::default();
        assert_eq!(client_ip(&req, &config), Some("192.0.2.1".parse().unwrap()));
        config.trusted_proxies.push("192.0.2.1".parse().unwrap());
        assert_eq!(
            client_ip(&req, &config),
            Some("198.51.100.2".parse().unwrap())
        );
        req.headers_mut()
            .insert("x-real-ip", "198.51.100.2, 192.0.2.3".parse().unwrap());
        assert_eq!(client_ip(&req, &config), None);
        req.headers_mut().remove("x-real-ip");
        assert_eq!(client_ip(&req, &config), None);
    }

    #[tokio::test]
    async fn auth_is_checked_before_redis_and_reads_remain_public() {
        let token = "a".repeat(32);
        let app = app(state(Config {
            write_token: Some(token.clone()),
            ..Config::default()
        }));
        for path in ["/v1/secrets", "/v1/files"] {
            for value in [None, Some("Bearer wrong".to_string())] {
                let mut req = request(path);
                if let Some(value) = value {
                    req.headers_mut()
                        .insert(header::AUTHORIZATION, value.parse().unwrap());
                }
                assert_eq!(
                    app.clone().oneshot(req).await.unwrap().status(),
                    StatusCode::UNAUTHORIZED
                );
            }
            let mut req = request(path);
            req.headers_mut().insert(
                header::AUTHORIZATION,
                format!("Bearer {token}").parse().unwrap(),
            );
            // Auth accepted, but Redis unavailable: fail closed.
            assert_eq!(
                app.clone().oneshot(req).await.unwrap().status(),
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
        let req = HttpRequest::builder()
            .uri("/read")
            .body(Body::empty())
            .unwrap();
        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_peer_fails_closed() {
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/v1/files")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app(state(Config::default()))
                .oneshot(req)
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }

    // Run against a disposable Redis: TEST_REDIS_URL=redis://127.0.0.1:16389
    // cargo test --locked redis_admission -- --ignored
    #[tokio::test]
    #[ignore = "requires disposable Redis in TEST_REDIS_URL"]
    async fn redis_admission() {
        use redis::AsyncCommands;
        let client =
            redis::Client::open(std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL required"))
                .unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        // This integration test intentionally flushes the explicitly supplied disposable DB.
        let _: () = redis::cmd("FLUSHDB").query_async(&mut conn).await.unwrap();
        // Exercise the production router: shared allowance, error headers,
        // preflight, public reads, and capacity failure through handlers.
        let config = Config {
            writes_per_minute: 2,
            ..Config::default()
        };
        let state = AppState {
            redis: std::sync::Arc::new(client.clone()),
            max_file_size_bytes: 2 * 1024 * 1024,
            protection: config,
        };
        let app = crate::app(state.clone());
        let mut req = request("/v1/secrets");
        req.headers_mut()
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        *req.body_mut() = Body::from(r#"{"encryptedSecret":"ciphertext","expiration":60}"#);
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let id = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["secretId"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut req = request("/v1/files");
        req.headers_mut()
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        *req.body_mut() = Body::from(
            r#"{"metadata":{"originalFilename":"x","contentType":"text/plain","iv":"iv"},"encryptedData":"YWJj","expiration":60}"#,
        );
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::OK
        );
        // Exhausted before JSON extraction, despite an invalid body.
        let response = app.clone().oneshot(request("/v1/secrets")).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            response.headers()[header::RETRY_AFTER]
                .to_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                > 0
        );
        for (suffix, expected) in [
            ("?peek=true", StatusCode::OK),
            ("", StatusCode::OK),
            ("", StatusCode::NOT_FOUND),
        ] {
            let req = HttpRequest::builder()
                .uri(format!("/v1/secrets/{id}{suffix}"))
                .body(Body::empty())
                .unwrap();
            assert_eq!(app.clone().oneshot(req).await.unwrap().status(), expected);
        }
        let req = HttpRequest::builder()
            .method("OPTIONS")
            .uri("/v1/files")
            .header("origin", "https://example.com")
            .header("access-control-request-method", "POST")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::OK
        );
        let constrained = crate::app(AppState {
            protection: Config {
                max_bytes: 1,
                ..state.protection.clone()
            },
            ..state
        });
        let mut req = request("/v1/files");
        req.extensions_mut().insert(ConnectInfo(
            "192.0.2.99:1234".parse::<SocketAddr>().unwrap(),
        ));
        assert_eq!(
            constrained.oneshot(req).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let _: () = redis::cmd("FLUSHDB").query_async(&mut conn).await.unwrap();
        let config = Config {
            max_keys: 5,
            writes_per_minute: 2,
            ..Config::default()
        };
        let ip = "192.0.2.42".parse().unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..20 {
            let c = client.clone();
            let cfg = config.clone();
            tasks.spawn(async move { rate_limit(&c, &cfg, ip).await.unwrap() });
        }
        let mut allowed = 0;
        while let Some(result) = tasks.join_next().await {
            if result.unwrap() == 0 {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 2);
        let ttl: i64 = conn.ttl("snappwd:write-rate:192.0.2.42").await.unwrap();
        assert!((1..=60).contains(&ttl));
        // A distinct IP has its own allowance.
        assert_eq!(
            rate_limit(&client, &config, "192.0.2.43".parse().unwrap())
                .await
                .unwrap(),
            0
        );
        for i in 0..20 {
            let c = client.clone();
            let cfg = config.clone();
            tasks.spawn(async move {
                store(&c, &cfg, &format!("sps-test-{i}"), "ciphertext", 60)
                    .await
                    .is_ok() as i64
            });
        }
        let mut stored = 0;
        while let Some(result) = tasks.join_next().await {
            stored += result.unwrap();
        }
        assert_eq!(stored, 3); // two limiter keys + three data keys
        let count: u64 = redis::cmd("DBSIZE").query_async(&mut conn).await.unwrap();
        assert_eq!(count, 5);
        assert_eq!(
            rate_limit(&client, &config, "192.0.2.44".parse().unwrap())
                .await
                .unwrap(),
            -1
        );
        let keys: Vec<String> = conn.keys("sps-test-*").await.unwrap();
        let id = &keys[0];
        let first = crate::db::get_secret(&client, id);
        let second = crate::db::get_secret(&client, id);
        let (a, b) = tokio::join!(first, second);
        assert_eq!(
            usize::from(a.unwrap().is_some()) + usize::from(b.unwrap().is_some()),
            1
        );
        store(&client, &config, "sps-replacement", "replacement", 1)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        assert!(crate::db::get_secret(&client, "sps-replacement")
            .await
            .unwrap()
            .is_none());
        store(&client, &config, "sps-after-expiry", "ciphertext", 60)
            .await
            .unwrap();
        let tiny = Config {
            max_bytes: 1,
            ..config.clone()
        };
        assert!(store(&client, &tiny, "sps-no-room", "ciphertext", 60)
            .await
            .is_err());
        assert_eq!(
            rate_limit(&client, &tiny, "192.0.2.45".parse().unwrap())
                .await
                .unwrap(),
            -1
        );
        // Actual allocated memory plus prospective value size is checked too.
        let info: String = redis::cmd("INFO")
            .arg("memory")
            .query_async(&mut conn)
            .await
            .unwrap();
        let used = info
            .lines()
            .find_map(|line| line.strip_prefix("used_memory:"))
            .unwrap()
            .trim()
            .parse::<u64>()
            .unwrap();
        let near = Config {
            max_bytes: used + 4096,
            max_keys: 100,
            ..config
        };
        assert!(
            store(&client, &near, "sps-too-big", &"x".repeat(100_000), 60)
                .await
                .is_err()
        );
        let _: () = redis::cmd("FLUSHDB").query_async(&mut conn).await.unwrap();
    }
}
