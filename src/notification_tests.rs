use crate::{notifications::Notifier, AppState};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
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
                .header("user-agent", "lifecycle-test/1.0")
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
    crate::build_app(AppState {
        protection: crate::protection::Config {
            writes_per_minute: 100,
            ..Default::default()
        },
        redis,
        notifier,
        max_file_size_bytes: 2 * 1024 * 1024,
    })
    .layer(axum::Extension(axum::extract::ConnectInfo(
        "192.0.2.50:1234".parse::<std::net::SocketAddr>().unwrap(),
    )))
}

#[tokio::test]
#[ignore = "Requires dedicated Redis 6.2+ via TEST_REDIS_URL"]
async fn notification_lifecycle() {
    lifecycle(false).await;
}

#[tokio::test]
#[ignore = "Requires dedicated Redis 6.2+ via TEST_REDIS_URL"]
async fn file_notification_lifecycle() {
    lifecycle(true).await;
}

async fn lifecycle(is_file: bool) {
    let endpoint = if is_file { "/v1/files" } else { "/v1/secrets" };
    let id_field = if is_file { "fileId" } else { "secretId" };
    let prefix = if is_file { "spf" } else { "sps" };
    let metadata = serde_json::json!({"originalFilename":"private.txt", "contentType":"text/plain", "iv":"private-iv"});
    let expected = |value: &serde_json::Value| {
        if is_file {
            assert!(value["createdAt"].as_u64().is_some());
            serde_json::json!({"metadata":metadata,"encryptedData":"ciphertext", "createdAt":value["createdAt"]})
        } else {
            serde_json::json!({"encryptedSecret":"ciphertext"})
        }
    };
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
    let payload = if is_file {
        serde_json::json!({"metadata":metadata,"encryptedData":"ciphertext", "expiration":60, "senderEmail":" sender@example.com "})
    } else {
        serde_json::json!({"encryptedSecret":"ciphertext", "expiration":60, "senderEmail":" sender@example.com "})
    };
    let (status, created) = request(&app, "POST", endpoint, payload.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(created.get("senderEmail").is_none());
    let id = created[id_field].as_str().unwrap();
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
        &format!("{endpoint}/{id}?peek=true"),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(peek.get("senderEmail").is_none());
    assert!(received.try_recv().is_err());
    let uri = format!("{endpoint}/{id}");
    let (first, second) = tokio::join!(
        request(&app, "GET", &uri, serde_json::Value::Null),
        request(&app, "GET", &uri, serde_json::Value::Null)
    );
    let (winner, loser) = if first.0 == StatusCode::OK {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(winner.0, StatusCode::OK);
    assert_eq!(winner.1, expected(&winner.1));
    assert_eq!(loser.0, StatusCode::NOT_FOUND);
    let mail = received.try_recv().unwrap();
    assert!(mail.contains("To: sender@example.com"));
    assert!(mail.contains(id));
    assert!(mail.contains("IP address: 192.0.2.50"));
    assert!(mail.contains("User agent: lifecycle-test/1.0"));
    assert!(!mail.contains("ciphertext"));
    assert!(!mail.contains("private.txt"));
    assert!(!mail.contains("private-iv"));
    assert!(mail.contains(if is_file {
        "file was accessed"
    } else {
        "secret was accessed"
    }));
    assert!(!conn.exists::<_, bool>(id).await.unwrap());
    assert_eq!(
        request(&app, "GET", &uri, serde_json::Value::Null).await.0,
        StatusCode::NOT_FOUND
    );
    assert!(received.try_recv().is_err());

    // Redis controls expiration; advance it without waiting for wall time.
    let (_, created) = request(&app, "POST", endpoint, payload.clone()).await;
    let id = created[id_field].as_str().unwrap();
    let _: bool = conn.expire(id, 0).await.unwrap();
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("{endpoint}/{id}"),
            serde_json::Value::Null
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert!(received.try_recv().is_err());

    // Omitted and blank addresses remain fully compatible.
    for email in [
        None,
        Some(serde_json::Value::Null),
        Some(serde_json::json!(" ")),
    ] {
        let mut optional = payload.clone();
        if let Some(email) = email {
            optional["senderEmail"] = email;
        } else {
            optional.as_object_mut().unwrap().remove("senderEmail");
        }
        let (_, created) = request(&app, "POST", endpoint, optional).await;
        let id = created[id_field].as_str().unwrap();
        assert_eq!(
            request(
                &app,
                "GET",
                &format!("{endpoint}/{id}"),
                serde_json::Value::Null
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    let legacy = if is_file {
        vec![serde_json::json!({"metadata":metadata,"encryptedData":"ciphertext"}).to_string()]
    } else {
        vec![
            "legacy-ciphertext".to_string(),
            r#"{"encryptedSecret":"old-json","createdAt":1,"metadata":null}"#.to_string(),
        ]
    };
    for value in legacy {
        let id = format!("{prefix}-{}", uuid::Uuid::new_v4());
        let _: () = conn.set_ex(&id, value, 60).await.unwrap();
        assert_eq!(
            request(
                &app,
                "GET",
                &format!("{endpoint}/{id}"),
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
    let (_, created) = request(&failing, "POST", endpoint, payload.clone()).await;
    let id = created[id_field].as_str().unwrap();
    let revealed = request(
        &failing,
        "GET",
        &format!("{endpoint}/{id}"),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(revealed.0, StatusCode::OK);
    assert_eq!(revealed.1, expected(&revealed.1));
    assert!(!conn.exists::<_, bool>(id).await.unwrap());
    let disabled = self::app(redis, None);
    let mut omitted = payload.clone();
    omitted.as_object_mut().unwrap().remove("senderEmail");
    let (status, created) = request(&disabled, "POST", endpoint, omitted).await;
    assert_eq!(status, StatusCode::OK);
    let id = created[id_field].as_str().unwrap();
    assert_eq!(
        request(
            &disabled,
            "GET",
            &format!("{endpoint}/{id}"),
            serde_json::Value::Null
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(&disabled, "POST", endpoint, payload.clone())
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        request(&disabled, "POST", endpoint, {
            let mut invalid = payload.clone();
            invalid["senderEmail"] = serde_json::json!("invalid");
            invalid
        })
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(&disabled, "POST", endpoint, {
            let mut invalid = payload.clone();
            invalid["senderEmail"] = serde_json::json!(123);
            invalid
        })
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}
