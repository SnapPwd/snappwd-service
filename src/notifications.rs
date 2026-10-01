use lettre::{
    message::Mailbox, transport::smtp::authentication::Credentials, Address, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};
use std::{env, time::Duration};

pub fn normalize_email(value: Option<String>) -> Result<Option<String>, ()> {
    let Some(value) = value else { return Ok(None) };
    let email = value.trim();
    if email.is_empty() {
        return Ok(None);
    }
    // Accept a single bare address, never display names or header syntax.
    if email.len() > 254
        || !email.is_ascii()
        || email.chars().any(char::is_whitespace)
        || email.parse::<Address>().is_err()
    {
        return Err(());
    }
    Ok(Some(email.to_string()))
}

pub struct Notifier {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl Notifier {
    pub fn from_env() -> Result<Option<Self>, &'static str> {
        let host = env::var("SMTP_HOST").ok();
        let from = env::var("SMTP_FROM").ok();
        let username = env::var("SMTP_USERNAME").ok();
        let password = env::var("SMTP_PASSWORD").ok();
        if host.is_none()
            && from.is_none()
            && username.is_none()
            && password.is_none()
            && env::var_os("SMTP_PORT").is_none()
        {
            return Ok(None);
        }
        let host = host
            .filter(|s| !s.is_empty())
            .ok_or("SMTP_HOST is required")?;
        let from = from
            .ok_or("SMTP_FROM is required")?
            .parse()
            .map_err(|_| "Invalid SMTP_FROM")?;
        let port = env::var("SMTP_PORT")
            .unwrap_or_else(|_| "587".into())
            .parse::<u16>()
            .map_err(|_| "Invalid SMTP_PORT")?;
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
            .map_err(|_| "Invalid SMTP_HOST")?
            .port(port)
            .timeout(Some(Duration::from_secs(5)));
        match (username, password) {
            (Some(user), Some(pass)) => builder = builder.credentials(Credentials::new(user, pass)),
            (None, None) => {}
            _ => return Err("SMTP_USERNAME and SMTP_PASSWORD must be configured together"),
        }
        Ok(Some(Self {
            transport: builder.build(),
            from,
        }))
    }

    fn message(&self, recipient: &str, secret_id: &str) -> Result<Message, ()> {
        Message::builder().from(self.from.clone())
            .to(recipient.parse().map_err(|_| ())?)
            .subject("Your SnapPwd secret was accessed")
            .body(format!("Your SnapPwd secret ({secret_id}) was accessed and deleted.\n\nThe encrypted content was retrieved; SnapPwd cannot verify client-side decryption.\n"))
            .map_err(|_| ())
    }

    pub async fn send(&self, recipient: &str, secret_id: &str) -> Result<(), ()> {
        let message = self.message(recipient, secret_id)?;
        tokio::time::timeout(Duration::from_secs(5), self.transport.send(message))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
        Ok(())
    }

    #[cfg(test)]
    pub fn local(port: u16) -> Self {
        Self {
            transport: AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("127.0.0.1")
                .port(port)
                .build(),
            from: "notify@example.com".parse().unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn stalled_smtp_is_bounded() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let started = tokio::time::Instant::now();
        assert!(Notifier::local(port)
            .send("sender@example.com", "sps-test")
            .await
            .is_err());
        assert!(started.elapsed() < Duration::from_secs(6));
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    #[test]
    fn validates_optional_bare_address() {
        for value in [None, Some("".into()), Some("  ".into())] {
            assert_eq!(normalize_email(value), Ok(None));
        }
        assert_eq!(
            normalize_email(Some(" sender@example.com ".into())),
            Ok(Some("sender@example.com".into()))
        );
        for value in [
            "bad",
            "a@b@c.com",
            "Name <a@example.com>",
            "a@example.com\r\nBcc: b@example.com",
            "a@example.com,b@example.com",
        ] {
            assert!(normalize_email(Some(value.into())).is_err(), "{value}");
        }
    }
}
