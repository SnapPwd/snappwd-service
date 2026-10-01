use crate::{handlers, notifications::Notifier, AppState};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    routing::{get, post},
    Router,
};
use redis::AsyncCommands;
use std::sync::Arc;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::mpsc,
};
use tower::ServiceExt;

async fn request(
    app: &Router,
    method: &str,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    (response.status(), {
        let bytes = to_bytes(response.into_body(), 10000).await.unwrap();
        serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            serde_json::Value::String(String::from_utf8_lossy(&bytes).into_owned())
        })
    })
}

fn app(redis: Arc<redis::Client>, notifier: Option<Arc<Notifier>>) -> Router {
    Router::new()
        .route("/v1/secrets", post(handlers::create_secret))
        .route("/v1/secrets/:id", get(handlers::get_secret))
        .with_state(AppState {
            redis,
            notifier,
            max_file_size_bytes: 2 * 1024 * 1024,
        })
}

#[tokio::test]
#[ignore = "Requires dedicated Redis 6.2+ via TEST_REDIS_URL"]
async fn notification_lifecycle() {
    let redis = Arc::new(
        redis::Client::open(std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL")).unwrap(),
    );
    let mut conn = redis.get_multiplexed_async_connection().await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, mut received) = mpsc::unbounded_channel();
    // Minimal SMTP sink: real SMTP transport, no external mail delivery.
    let sink = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut read = BufReader::new(read);
            write.write_all(b"220 localhost test\r\n").await.unwrap();
            let mut data = false;
            let mut message = String::new();
            loop {
                let mut line = String::new();
                if read.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                if data {
                    if line == ".\r\n" {
                        tx.send(message.clone()).unwrap();
                        data = false;
                        write.write_all(b"250 accepted\r\n").await.unwrap();
                    } else {
                        message.push_str(&line)
                    }
                } else if line.starts_with("EHLO") {
                    write.write_all(b"250 localhost\r\n").await.unwrap();
                } else if line.starts_with("DATA") {
                    data = true;
                    write.write_all(b"354 send data\r\n").await.unwrap();
                } else if line.starts_with("QUIT") {
                    write.write_all(b"221 bye\r\n").await.unwrap();
                    break;
                } else {
                    write.write_all(b"250 ok\r\n").await.unwrap()
                }
            }
        }
    });
    let app = app(redis.clone(), Some(Arc::new(Notifier::local(port))));
    let payload = serde_json::json!({"encryptedSecret":"ciphertext", "expiration":60, "senderEmail":" sender@example.com "});
    let (status, created) = request(&app, "POST", "/v1/secrets", payload.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(created.get("senderEmail").is_none());
    let id = created["secretId"].as_str().unwrap();
    let stored: String = conn.get(id).await.unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&stored).unwrap()["senderEmail"],
        "sender@example.com"
    );
    let ttl: i64 = conn.ttl(id).await.unwrap();
    assert!((1..=60).contains(&ttl));
    let (status, peek) = request(
        &app,
        "GET",
        &format!("/v1/secrets/{id}?peek=true"),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(peek.get("senderEmail").is_none());
    assert!(received.try_recv().is_err());
    let uri = format!("/v1/secrets/{id}");
    let (first, second) = tokio::join!(
        request(&app, "GET", &uri, serde_json::Value::Null),
        request(&app, "GET", &uri, serde_json::Value::Null)
    );
    let (winner, loser) = if first.0 == StatusCode::OK {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(
        winner,
        (
            StatusCode::OK,
            serde_json::json!({"encryptedSecret":"ciphertext"})
        )
    );
    assert_eq!(loser.0, StatusCode::NOT_FOUND);
    let mail = received.try_recv().unwrap();
    assert!(mail.contains("To: sender@example.com"));
    assert!(mail.contains(id));
    assert!(!mail.contains("ciphertext"));
    assert!(!conn.exists::<_, bool>(id).await.unwrap());
    assert_eq!(
        request(&app, "GET", &uri, serde_json::Value::Null).await.0,
        StatusCode::NOT_FOUND
    );
    assert!(received.try_recv().is_err());

    // Redis controls expiration; advance it without waiting for wall time.
    let (_, created) = request(&app, "POST", "/v1/secrets", payload.clone()).await;
    let id = created["secretId"].as_str().unwrap();
    let _: bool = conn.expire(id, 0).await.unwrap();
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("/v1/secrets/{id}"),
            serde_json::Value::Null
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert!(received.try_recv().is_err());

    // Omitted and blank addresses remain fully compatible.
    for email in [serde_json::Value::Null, serde_json::json!(" ")] {
        let (_, created) = request(
            &app,
            "POST",
            "/v1/secrets",
            serde_json::json!({"encryptedSecret":"no-mail", "expiration":60, "senderEmail":email}),
        )
        .await;
        let id = created["secretId"].as_str().unwrap();
        assert_eq!(
            request(
                &app,
                "GET",
                &format!("/v1/secrets/{id}"),
                serde_json::Value::Null
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    for value in [
        "legacy-ciphertext",
        r#"{"encryptedSecret":"old-json","createdAt":1,"metadata":null}"#,
    ] {
        let id = format!("sps-{}", uuid::Uuid::new_v4());
        let _: () = conn.set_ex(&id, value, 60).await.unwrap();
        assert_eq!(
            request(
                &app,
                "GET",
                &format!("/v1/secrets/{id}"),
                serde_json::Value::Null
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    assert!(received.try_recv().is_err());
    sink.abort();
    assert!(sink.await.unwrap_err().is_cancelled());

    // SMTP refusal cannot prevent access or resurrect a consumed secret.
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let failing = self::app(redis.clone(), Some(Arc::new(Notifier::local(port))));
    let (_, created) = request(&failing, "POST", "/v1/secrets", payload.clone()).await;
    let id = created["secretId"].as_str().unwrap();
    assert_eq!(
        request(
            &failing,
            "GET",
            &format!("/v1/secrets/{id}"),
            serde_json::Value::Null
        )
        .await,
        (
            StatusCode::OK,
            serde_json::json!({"encryptedSecret":"ciphertext"})
        )
    );
    assert!(!conn.exists::<_, bool>(id).await.unwrap());
    let disabled = self::app(redis, None);
    assert_eq!(
        request(&disabled, "POST", "/v1/secrets", payload).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        request(
            &disabled,
            "POST",
            "/v1/secrets",
            serde_json::json!({"encryptedSecret":"test", "expiration":60, "senderEmail":"invalid"})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(
            &disabled,
            "POST",
            "/v1/secrets",
            serde_json::json!({"encryptedSecret":"test", "expiration":60, "senderEmail":123})
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}
