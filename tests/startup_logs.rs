use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

// Always reap the service, including when a test fails or startup times out.
struct Service(Child);

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn startup_logs(redis_url: &str, expect_listening: bool) -> String {
    let mut command = Command::new(env!("CARGO_BIN_EXE_snappwd-service"));
    command
        .env("REDIS_URL", redis_url)
        .env("PORT", "0")
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Isolate startup from any SMTP configuration on the test runner.
    for key in [
        "SMTP_HOST",
        "SMTP_FROM",
        "SMTP_PORT",
        "SMTP_USERNAME",
        "SMTP_PASSWORD",
    ] {
        command.env_remove(key);
    }
    let mut service = Service(command.spawn().expect("start service"));
    let stdout = service.0.stdout.take().unwrap();
    let stderr = service.0.stderr.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut logs = String::new();
        for line in BufReader::new(stdout).lines() {
            let line = line.expect("read startup log");
            logs.push_str(&line);
            logs.push('\n');
            if line.contains("listening on") {
                sender.send(logs.clone()).unwrap();
            }
        }
        let _ = sender.send(logs);
    });
    let logs = receiver
        .recv_timeout(Duration::from_secs(10))
        .expect("service must listen or finish within 10 seconds");
    if expect_listening {
        assert!(logs.contains("listening on"), "{logs}");
        service.0.kill().expect("stop service");
    }
    assert!(service.0.wait().is_ok());
    reader.join().unwrap();
    let stderr = std::io::read_to_string(stderr).expect("read stderr");
    format!("{logs}{stderr}")
}

#[test]
fn startup_does_not_log_redis_credentials() {
    for url in [
        "redis://127.0.0.1:6379",
        "redis://:startup-password@127.0.0.1:6379/0",
        "redis://startup-user:startup-password@127.0.0.1:6379/0",
        "redis://startup-user:encoded%40password@127.0.0.1:6379/0",
    ] {
        let logs = startup_logs(url, true);
        assert!(logs.contains("Initializing Redis client"), "{logs}");
        for sensitive in [
            url,
            "startup-user",
            "startup-password",
            "encoded%40password",
            "encoded@password",
        ] {
            assert!(!logs.contains(sensitive), "credential leaked: {logs}");
        }
    }
}

#[test]
fn invalid_redis_configuration_logs_only_the_error_category() {
    let url = "redis://startup-user:startup-password@127.0.0.1:invalid/0";
    let logs = startup_logs(url, false);
    assert!(logs.contains("Failed to initialize Redis client"), "{logs}");
    assert!(logs.contains("InvalidClientConfig"), "{logs}");
    assert!(!logs.contains("listening on"), "{logs}");
    for sensitive in [url, "startup-user", "startup-password"] {
        assert!(!logs.contains(sensitive), "credential leaked: {logs}");
    }
}
