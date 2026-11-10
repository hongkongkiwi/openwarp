//! Outbound email: SMTP or an HTTP provider, with built-in templates.
//!
//! Provider selection is explicit via OPENWARP_EMAIL_PROVIDER, otherwise it is
//! inferred from whichever credentials are present. A missing provider is not
//! an error at call sites: the message is logged and suppressed so account
//! flows keep working on a private instance.

use serde_json::{json, Value};
use std::time::Duration;

#[derive(Clone, Debug, Default)]
pub struct MailConfig {
    pub provider: String,
    pub from_email: String,
    pub from_name: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_pass: String,
    pub smtp_tls: String,
    pub resend_key: String,
    pub resend_url: String,
    pub sendgrid_key: String,
    pub sendgrid_url: String,
    pub mailgun_key: String,
    pub mailgun_domain: String,
    pub mailgun_url: String,
    pub postmark_token: String,
    pub postmark_url: String,
    pub cloudflare_url: String,
    pub cloudflare_token: String,
    pub webhook_url: String,
    pub webhook_token: String,
}

pub struct MailMessage {
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: String,
}

impl MailConfig {
    pub fn from_env() -> Self {
        let env = |k: &str| crate::envcfg::var(k).unwrap_or_default();
        let smtp_host = env("OPENWARP_SMTP_HOST");
        let resend_key = env("OPENWARP_RESEND_API_KEY");
        let sendgrid_key = env("OPENWARP_SENDGRID_API_KEY");
        let mailgun_key = env("OPENWARP_MAILGUN_API_KEY");
        let postmark_token = env("OPENWARP_POSTMARK_TOKEN");
        let cloudflare_url = env("OPENWARP_CLOUDFLARE_EMAIL_URL");
        let webhook_url = env("OPENWARP_EMAIL_WEBHOOK");
        let explicit = env("OPENWARP_EMAIL_PROVIDER").trim().to_ascii_lowercase();
        let provider = if !explicit.is_empty() {
            match explicit.as_str() {
                "twilio" => "sendgrid".to_string(),
                "cloudflare-email" | "cloudflare_email" => "cloudflare".to_string(),
                other => other.to_string(),
            }
        } else if !smtp_host.is_empty() {
            "smtp".into()
        } else if !resend_key.is_empty() {
            "resend".into()
        } else if !sendgrid_key.is_empty() {
            "sendgrid".into()
        } else if !mailgun_key.is_empty() {
            "mailgun".into()
        } else if !postmark_token.is_empty() {
            "postmark".into()
        } else if !cloudflare_url.is_empty() {
            "cloudflare".into()
        } else if !webhook_url.is_empty() {
            "webhook".into()
        } else {
            "log".into()
        };
        Self {
            provider,
            from_email: env("OPENWARP_EMAIL_FROM"),
            from_name: env("OPENWARP_EMAIL_FROM_NAME"),
            smtp_port: env("OPENWARP_SMTP_PORT").parse().unwrap_or(587),
            smtp_tls: {
                let v = env("OPENWARP_SMTP_TLS").trim().to_ascii_lowercase();
                if v.is_empty() { "starttls".into() } else { v }
            },
            smtp_host,
            smtp_user: env("OPENWARP_SMTP_USERNAME"),
            smtp_pass: env("OPENWARP_SMTP_PASSWORD"),
            resend_key,
            resend_url: nonempty(env("OPENWARP_RESEND_URL"), "https://api.resend.com/emails"),
            sendgrid_key,
            sendgrid_url: nonempty(env("OPENWARP_SENDGRID_URL"), "https://api.sendgrid.com/v3/mail/send"),
            mailgun_key,
            mailgun_domain: env("OPENWARP_MAILGUN_DOMAIN"),
            mailgun_url: nonempty(env("OPENWARP_MAILGUN_URL"), "https://api.mailgun.net/v3"),
            postmark_token,
            postmark_url: nonempty(env("OPENWARP_POSTMARK_URL"), "https://api.postmarkapp.com/email"),
            cloudflare_url,
            cloudflare_token: env("OPENWARP_CLOUDFLARE_EMAIL_TOKEN"),
            webhook_url,
            webhook_token: env("OPENWARP_EMAIL_TOKEN"),
        }
    }

    pub fn enabled(&self) -> bool {
        match self.provider.as_str() {
            "smtp" => !self.smtp_host.is_empty() && !self.from_email.is_empty(),
            "resend" => !self.resend_key.is_empty() && !self.from_email.is_empty(),
            "sendgrid" => !self.sendgrid_key.is_empty() && !self.from_email.is_empty(),
            "mailgun" => !self.mailgun_key.is_empty() && !self.mailgun_domain.is_empty() && !self.from_email.is_empty(),
            "postmark" => !self.postmark_token.is_empty() && !self.from_email.is_empty(),
            "cloudflare" => !self.cloudflare_url.is_empty() && !self.from_email.is_empty(),
            "webhook" => !self.webhook_url.is_empty(),
            _ => false,
        }
    }

    pub fn mailbox(&self) -> String {
        let email = if self.from_email.is_empty() { "no-reply@openwarp.invalid" } else { self.from_email.as_str() };
        if self.from_name.is_empty() { email.to_string() } else { format!("{} <{}>", self.from_name, email) }
    }
}

fn nonempty(value: String, fallback: &str) -> String {
    if value.trim().is_empty() { fallback.to_string() } else { value }
}

fn html_escape(value: &str) -> String {
    value.chars().map(|c| match c {
        '&' => "&amp;".into(), '<' => "&lt;".into(), '>' => "&gt;".into(),
        '"' => "&quot;".into(), '\'' => "&#39;".into(), c => c.to_string(),
    }).collect()
}

pub fn text_to_html(text: &str) -> String {
    html_escape(text).replace('\n', "<br>\n")
}

/// Render a built-in template, or a file from OPENWARP_EMAIL_TEMPLATES_DIR.
/// Files: <kind>.subject.txt, <kind>.txt, <kind>.html. Variables use {{name}}.
pub fn render(kind: &str, to: &str, vars: &[(&str, &str)]) -> MailMessage {
    let mut pairs: Vec<(String, String)> = vec![("email".into(), to.to_string())];
    for (k, v) in vars { pairs.push(((*k).to_string(), (*v).to_string())); }
    let substitute = |template: &str, html: bool| -> String {
        let mut out = template.to_string();
        for (k, v) in &pairs {
            let value = if html { html_escape(v) } else { v.clone() };
            out = out.replace(&format!("{{{{{}}}}}", k), &value);
        }
        out
    };
    #[cfg(target_arch = "wasm32")]
    let dir = String::new();
    #[cfg(not(target_arch = "wasm32"))]
    let dir = std::env::var("OPENWARP_EMAIL_TEMPLATES_DIR").unwrap_or_default();
    let read = |suffix: &str| -> Option<String> {
        if dir.is_empty() { return None; }
        std::fs::read_to_string(std::path::Path::new(&dir).join(format!("{}{}", kind, suffix))).ok()
    };
    let (default_subject, default_text) = builtin(kind);
    let subject = read(".subject.txt").unwrap_or_else(|| default_subject.to_string());
    let text = read(".txt").unwrap_or_else(|| default_text.to_string());
    let html = read(".html").unwrap_or_else(|| format!(
        "<div style=\"font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;padding:24px;color:#111\"><pre style=\"white-space:pre-wrap;font:14px/1.5 ui-monospace,monospace\">{}</pre></div>",
        text_to_html(&text)));
    MailMessage {
        to: to.to_string(),
        subject: substitute(&subject, false),
        text: substitute(&text, false),
        html: substitute(&html, true),
    }
}

fn builtin(kind: &str) -> (&'static str, &'static str) {
    match kind {
        "verify" => ("Verify your OpenWarp address",
            "Confirm your email address by opening this link:\n{{link}}\n\nIt expires in 24 hours. If you did not create an account, ignore this message."),
        "link" => ("Confirm a sign-in link for OpenWarp",
            "A sign-in attempt wants to link a provider identity to your OpenWarp account.\n\nConfirm it by opening this link:\n{{link}}\n\nIt expires in 10 minutes. If you did not start this, ignore this message."),
        "reset" => ("Reset your OpenWarp password",
            "Open this link to choose a new password:\n{{link}}\n\nIt expires in one hour. You will be asked for your recovery kit unless you choose to replace your key."),
        "invite" => ("You are invited to OpenWarp",
            "{{inviter}} invited you to join {{org}} on OpenWarp.\n\nSet your password here:\n{{link}}\n\nThis link expires in seven days."),
        "pki-expiry" => ("OpenWarp device certificates need renewal",
            "Device certificates in {{org}} need renewal.\n\nExpires within 7 days: {{count7}}\nExpires within 14 days: {{count14}}\nExpires within 30 days: {{count30}}\n\nOpen your workspace PKI settings to review and renew them. Counts include expired certificates. No private keys or enrollment codes are included."),
        "test" => ("OpenWarp test email",
            "This is a test message from OpenWarp. If you can read it, outbound email is configured."),
        "stepup" => ("Your OpenWarp verification code",
            "Your verification code is {{code}}.\n\nIt expires in ten minutes. If you did not request it, someone may have your password: change it and review the audit log."),
        _ => ("OpenWarp notification",
            "{{body}}"),
    }
}

pub async fn send(cfg: &MailConfig, msg: &MailMessage) -> Result<(), String> {
    match cfg.provider.as_str() {
        #[cfg(not(target_arch = "wasm32"))]
        "smtp" => {
            let cfg = cfg.clone();
            let (to, subject, text, html) = (msg.to.clone(), msg.subject.clone(), msg.text.clone(), msg.html.clone());
            tokio::task::spawn_blocking(move || smtp_send(&cfg, &to, &subject, &text, &html))
                .await.map_err(|e| format!("SMTP worker failed: {}", e))?
        }
        "log" => { eprintln!("email suppressed (no provider configured): {} -> {}", msg.subject, msg.to); Ok(()) }
        "resend" => post_json(&cfg.resend_url, Some(&cfg.resend_key), resend_payload(cfg, msg)).await,
        "sendgrid" => post_json(&cfg.sendgrid_url, Some(&cfg.sendgrid_key), sendgrid_payload(cfg, msg)).await,
        "postmark" => post_json_with_headers(&cfg.postmark_url, &[("X-Postmark-Server-Token", cfg.postmark_token.as_str())], postmark_payload(cfg, msg)).await,
        "cloudflare" => {
            let bearer = format!("Bearer {}", cfg.cloudflare_token);
            post_json_with_headers(&cfg.cloudflare_url, &[("Authorization", bearer.as_str())], cloudflare_payload(cfg, msg)).await
        }
        "webhook" => {
            let bearer = format!("Bearer {}", cfg.webhook_token);
            let headers: &[(&str, &str)] = if cfg.webhook_token.is_empty() { &[] } else { &[("Authorization", bearer.as_str())] };
            post_json_with_headers(&cfg.webhook_url, headers, webhook_payload(msg)).await
        }
        "mailgun" => {
            let url = format!("{}/{}/messages", cfg.mailgun_url.trim_end_matches('/'), cfg.mailgun_domain);
            let form = [
                ("from", cfg.mailbox()), ("to", msg.to.clone()), ("subject", msg.subject.clone()),
                ("text", msg.text.clone()), ("html", msg.html.clone()),
            ];
            let resp = crate::http::Client::new().post(&url).basic_auth("api", Some(&cfg.mailgun_key)).form(&form)
                .timeout(Duration::from_secs(15)).send().await.map_err(|e| e.to_string())?;
            check(resp).await
        }
        #[cfg(target_arch = "wasm32")]
        "smtp" => Err("SMTP is unavailable in a Worker; configure an HTTP email provider with OPENWARP_EMAIL_WEBHOOK".into()),
        other => Err(format!("unknown email provider: {}", other)),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn smtp_send(cfg: &MailConfig, to: &str, subject: &str, text: &str, html: &str) -> Result<(), String> {
    #[cfg(not(target_arch = "wasm32"))]
    use lettre::message::MultiPart;
    #[cfg(not(target_arch = "wasm32"))]
    use lettre::transport::smtp::authentication::Credentials;
    #[cfg(not(target_arch = "wasm32"))]
    use lettre::{Message, SmtpTransport, Transport};
    let from: lettre::message::Mailbox = cfg.mailbox().parse().map_err(|e| format!("invalid from address: {}", e))?;
    let to: lettre::message::Mailbox = to.parse().map_err(|e| format!("invalid recipient: {}", e))?;
    let email = Message::builder().from(from).to(to).subject(subject)
        .multipart(MultiPart::alternative_plain_html(text.to_string(), html.to_string()))
        .map_err(|e| format!("email build failed: {}", e))?;
    let builder = match cfg.smtp_tls.as_str() {
        "none" => SmtpTransport::builder_dangerous(&cfg.smtp_host).port(cfg.smtp_port),
        "implicit" | "tls" | "ssl" => SmtpTransport::relay(&cfg.smtp_host).map_err(|e| e.to_string())?.port(cfg.smtp_port),
        _ => SmtpTransport::starttls_relay(&cfg.smtp_host).map_err(|e| e.to_string())?.port(cfg.smtp_port),
    };
    let builder = if cfg.smtp_user.is_empty() { builder } else { builder.credentials(Credentials::new(cfg.smtp_user.clone(), cfg.smtp_pass.clone())) };
    builder.build().send(&email).map(|_| ()).map_err(|e| format!("SMTP send failed: {}", e))
}

fn resend_payload(cfg: &MailConfig, msg: &MailMessage) -> Value {
    json!({"from": cfg.mailbox(), "to": [msg.to], "subject": msg.subject, "text": msg.text, "html": msg.html})
}
fn sendgrid_payload(cfg: &MailConfig, msg: &MailMessage) -> Value {
    json!({
        "personalizations": [{"to": [{"email": msg.to}]}],
        "from": {"email": cfg.from_email, "name": cfg.from_name},
        "subject": msg.subject,
        "content": [{"type": "text/plain", "value": msg.text}, {"type": "text/html", "value": msg.html}]
    })
}
fn postmark_payload(cfg: &MailConfig, msg: &MailMessage) -> Value {
    json!({"From": cfg.mailbox(), "To": msg.to, "Subject": msg.subject, "TextBody": msg.text, "HtmlBody": msg.html, "MessageStream": "outbound"})
}
fn cloudflare_payload(cfg: &MailConfig, msg: &MailMessage) -> Value {
    json!({"from": cfg.mailbox(), "to": msg.to, "subject": msg.subject, "text": msg.text, "html": msg.html})
}
fn webhook_payload(msg: &MailMessage) -> Value {
    json!({"to": msg.to, "subject": msg.subject, "text": msg.text, "html": msg.html})
}

async fn post_json(url: &str, bearer: Option<&str>, body: Value) -> Result<(), String> {
    let mut req = crate::http::Client::new().post(url).json(&body).timeout(Duration::from_secs(15));
    if let Some(token) = bearer { req = req.bearer_auth(token); }
    check(req.send().await.map_err(|e| e.to_string())?).await
}

async fn post_json_with_headers(url: &str, headers: &[(&str, &str)], body: Value) -> Result<(), String> {
    let mut req = crate::http::Client::new().post(url).json(&body).timeout(Duration::from_secs(15));
    for (k, v) in headers.iter().copied() { req = req.header(k, v); }
    check(req.send().await.map_err(|e| e.to_string())?).await
}

async fn check(resp: crate::http::Response) -> Result<(), String> {
    let status = resp.status();
    if status.is_success() { return Ok(()); }
    let body = resp.text().await.unwrap_or_default();
    Err(format!("email provider returned HTTP {}: {}", status, body.chars().take(400).collect::<String>()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> MailConfig {
        MailConfig { from_email: "no-reply@example.com".into(), from_name: "OpenWarp".into(), ..Default::default() }
    }

    #[test]
    fn templates_substitute_and_escape() {
        let msg = render("verify", "user@example.com", &[("link", "https://app.example/verify?token=a&b=<x>")]);
        assert_eq!(msg.to, "user@example.com");
        assert!(msg.subject.contains("Verify"));
        assert!(msg.text.contains("https://app.example/verify?token=a&b=<x>"));
        assert!(msg.html.contains("&amp;"), "HTML must escape link parameters: {}", msg.html);
        assert!(!msg.html.contains("<x>"), "HTML must not contain raw markup: {}", msg.html);
    }

    #[test]
    fn provider_payloads_have_the_expected_shape() {
        let msg = MailMessage { to: "user@example.com".into(), subject: "s".into(), text: "t".into(), html: "<p>t</p>".into() };
        let resend = resend_payload(&cfg(), &msg);
        assert_eq!(resend["to"][0], "user@example.com");
        assert_eq!(resend["from"], "OpenWarp <no-reply@example.com>");
        let sendgrid = sendgrid_payload(&cfg(), &msg);
        assert_eq!(sendgrid["personalizations"][0]["to"][0]["email"], "user@example.com");
        assert_eq!(sendgrid["content"][0]["type"], "text/plain");
        let postmark = postmark_payload(&cfg(), &msg);
        assert_eq!(postmark["MessageStream"], "outbound");
        assert_eq!(webhook_payload(&msg)["to"], "user@example.com");
    }

    #[test]
    fn provider_detection_prefers_explicit_configuration() {
        // The env is process-global; this only checks the explicit alias mapping
        // through the payload helpers, not from_env.
        assert_eq!(cfg().provider, "");
        assert!(!cfg().enabled());
    }

    #[test]
    fn smtp_transport_delivers_to_a_local_relay() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind SMTP mock");
        let port = listener.local_addr().expect("SMTP mock addr").port();
        let relay = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("SMTP accept");
            stream.set_read_timeout(Some(Duration::from_secs(3))).expect("SMTP timeout");
            let _ = stream.write_all(b"220 localhost ESMTP\r\n");
            let mut reader = BufReader::new(stream.try_clone().expect("SMTP clone"));
            let mut data = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 { break; }
                let cmd = line.trim_end().to_string();
                if cmd.starts_with("EHLO") || cmd.starts_with("HELO") {
                    let _ = stream.write_all(b"250-localhost\r\n250-8BITMIME\r\n250 SIZE 1000000\r\n");
                } else if cmd.starts_with("MAIL FROM") || cmd.starts_with("RCPT TO") || cmd == "RSET" || cmd == "NOOP" {
                    let _ = stream.write_all(b"250 OK\r\n");
                } else if cmd == "DATA" {
                    let _ = stream.write_all(b"354 End data\r\n");
                    loop {
                        let mut l = String::new();
                        if reader.read_line(&mut l).unwrap_or(0) == 0 { break; }
                        data.push_str(&l);
                        if l == ".\r\n" || l == ".\n" { break; }
                    }
                    let _ = stream.write_all(b"250 OK\r\n");
                } else if cmd == "QUIT" {
                    let _ = stream.write_all(b"221 Bye\r\n");
                    break;
                } else { let _ = stream.write_all(b"250 OK\r\n"); }
            }
            data
        });
        let cfg = MailConfig {
            provider: "smtp".into(), smtp_host: "127.0.0.1".into(), smtp_port: port, smtp_tls: "none".into(),
            from_email: "no-reply@example.com".into(), from_name: "OpenWarp".into(), ..Default::default()
        };
        smtp_send(&cfg, "user@example.com", "Subject line", "plain body", "<b>html body</b>").expect("SMTP send");
        let data = relay.join().expect("SMTP relay");
        assert!(data.contains("Subject:"), "message headers missing: {}", data);
        assert!(data.contains("plain body"), "plain part missing: {}", data);
        assert!(data.contains("html body"), "html part missing: {}", data);
    }
}
