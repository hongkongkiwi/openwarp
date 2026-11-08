use openwarp_server::kms::Kms;
use serde_json::{json, Value};
use std::process::Command;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// Each case owns a fresh process: Kms configuration reads the process environment.
fn isolated(name: &str) -> bool {
    if std::env::var("OPENWARP_KMS_REVIEW_CASE").ok().as_deref() == Some(name) { return false; }
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env("OPENWARP_KMS_REVIEW_CASE", name).env("NO_PROXY", "*").env("no_proxy", "*");
    for key in ["OPENWARP_KMS_URL", "OPENWARP_KMS_TOKEN", "OPENWARP_KMS_KEY_ID", "OPENWARP_ENV", "OPENWARP_ALLOW_PRIVATE_EGRESS", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] { command.env_remove(key); }
    let output = command.output().expect("start isolated KMS test");
    assert!(output.status.success(), "isolated case {name} failed:\n{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    true
}
fn configured(url: &str) -> Kms {
    std::env::set_var("OPENWARP_KMS_URL", url);
    std::env::set_var("OPENWARP_KMS_KEY_ID", "review-primary");
    std::env::set_var("OPENWARP_KMS_TOKEN", "dummy-kms-token");
    std::env::set_var("OPENWARP_ALLOW_PRIVATE_EGRESS", "1");
    Kms::from_env().expect("local KMS configuration must be valid").expect("KMS must be configured")
}
async fn request(socket: &mut TcpStream) -> (String, Value) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut bytes = Vec::new();
        loop {
            let mut chunk = [0; 4096];
            let n = socket.read(&mut chunk).await.unwrap();
            assert!(n > 0, "mock must receive the complete request");
            bytes.extend_from_slice(&chunk[..n]);
            assert!(bytes.len() < 65536, "mock KMS request must stay small");
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8(bytes[..end].to_vec()).unwrap();
                let length = headers.lines().find_map(|line| line.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap())).unwrap();
                if bytes.len() >= end + 4 + length {
                    return (headers, serde_json::from_slice(&bytes[end + 4..end + 4 + length]).unwrap());
                }
            }
        }
    }).await.expect("mock request deadline")
}
async fn respond(socket: &mut TcpStream, body: &str) {
    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
}

#[test]
fn remote_plaintext_kms_configuration_is_rejected_in_production() {
    if isolated("remote_plaintext_kms_configuration_is_rejected_in_production") { return; }
    std::env::set_var("OPENWARP_ENV", "production");
    std::env::set_var("OPENWARP_KMS_URL", "http://kms.test.invalid/bridge");
    assert!(Kms::from_env().is_err(), "production KMS configuration must reject remote plaintext HTTP before sending keys");
}

#[test]
fn https_and_explicit_loopback_kms_configuration_remain_supported() {
    if isolated("https_and_explicit_loopback_kms_configuration_remain_supported") { return; }
    std::env::set_var("OPENWARP_ENV", "production");
    for url in ["https://kms.test.invalid/bridge", "http://127.0.0.1:12345/bridge"] {
        assert_eq!(configured(url).key_id(), "review-primary");
    }
    std::env::remove_var("OPENWARP_KMS_URL");
    assert!(Kms::from_env().unwrap().is_none(), "KMS remains optional when not configured");
}

async fn redirect_case(status: u16) {
    let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let kms = configured(&format!("http://{}/bridge", source.local_addr().unwrap()));
    let target = destination.local_addr().unwrap();
    let source_task = tokio::spawn(async move {
        let (mut socket, _) = source.accept().await.unwrap();
        let (headers, body) = request(&mut socket).await;
        assert!(headers.starts_with("POST /bridge/wrap "));
        assert!(headers.to_ascii_lowercase().contains("authorization: bearer dummy-kms-token"));
        assert_eq!(body["plaintext"], openwarp_crypto::b64(b"dummy-root-key"));
        socket.write_all(format!("HTTP/1.1 {status} Redirect\r\nLocation: http://{target}/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    });
    let destination_task = tokio::spawn(async move {
        if let Ok(Ok((mut socket, _))) = tokio::time::timeout(Duration::from_secs(1), destination.accept()).await {
            let (_, body) = request(&mut socket).await;
            let forwarded = body["plaintext"] == openwarp_crypto::b64(b"dummy-root-key");
            respond(&mut socket, r#"{"wrapped":"dummy-forwarded-envelope"}"#).await;
            forwarded
        } else { false }
    });
    let result = kms.wrap(b"dummy-root-key", "master").await;
    source_task.await.unwrap();
    assert!(!destination_task.await.unwrap(), "KMS must not forward plaintext key material to a redirect destination");
    assert!(result.is_err(), "a KMS redirect must fail closed");
}

#[tokio::test]
async fn kms_307_does_not_forward_plaintext_to_another_listener() {
    if isolated("kms_307_does_not_forward_plaintext_to_another_listener") { return; }
    redirect_case(307).await;
}

#[tokio::test]
async fn kms_308_does_not_forward_plaintext_to_another_listener() {
    if isolated("kms_308_does_not_forward_plaintext_to_another_listener") { return; }
    redirect_case(308).await;
}

#[tokio::test]
async fn kms_wrap_and_unwrap_preserve_context_and_payload_key_id() {
    if isolated("kms_wrap_and_unwrap_preserve_context_and_payload_key_id") { return; }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let kms = configured(&format!("http://{}/bridge", listener.local_addr().unwrap()));
    let server = tokio::spawn(async move {
        for op in ["wrap", "unwrap"] {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (headers, body) = request(&mut socket).await;
            assert!(headers.starts_with(&format!("POST /bridge/{op} ")));
            assert_eq!(body["context"], "env:dummy");
            if op == "wrap" {
                assert_eq!(body["key_id"], "review-primary");
                assert_eq!(body["plaintext"], openwarp_crypto::b64(b"dummy-key"));
                respond(&mut socket, &json!({"wrapped": "opaque-envelope"}).to_string()).await;
            } else {
                assert_eq!(body["key_id"], "historical-key");
                assert_eq!(body["wrapped"], "opaque-envelope");
                respond(&mut socket, &json!({"plaintext": openwarp_crypto::b64(b"dummy-key")}).to_string()).await;
            }
        }
    });
    assert_eq!(kms.wrap(b"dummy-key", "env:dummy").await.unwrap(), "owkms:review-primary:opaque-envelope");
    assert_eq!(kms.unwrap("owkms:historical-key:opaque-envelope", "env:dummy").await.unwrap(), b"dummy-key");
    server.await.unwrap();
}

#[tokio::test]
async fn kms_accepts_a_json_response_exactly_one_mib() {
    if isolated("kms_accepts_a_json_response_exactly_one_mib") { return; }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let kms = configured(&format!("http://{}/bridge", listener.local_addr().unwrap()));
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        request(&mut socket).await;
        let mut body = r#"{"wrapped":"opaque-envelope","padding":""}"#.to_string();
        body.insert_str(body.len() - 2, &"x".repeat(1024 * 1024 - body.len()));
        assert_eq!(body.len(), 1024 * 1024);
        respond(&mut socket, &body).await;
    });
    assert_eq!(kms.wrap(b"dummy-key", "master").await.unwrap(), "owkms:review-primary:opaque-envelope");
    server.await.unwrap();
}

#[tokio::test]
async fn kms_rejects_oversized_chunked_json_before_response_eof() {
    if isolated("kms_rejects_oversized_chunked_json_before_response_eof") { return; }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let kms = configured(&format!("http://{}/bridge", listener.local_addr().unwrap()));
    let (sent, received) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        request(&mut socket).await;
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
        let prefix = b"{\"wrapped\":\"opaque-envelope\",\"padding\":\"";
        let mut bytes = prefix.to_vec();
        bytes.resize(1024 * 1024 + 1, b'x');
        socket.write_all(format!("{:x}\r\n", bytes.len()).as_bytes()).await.unwrap();
        socket.write_all(&bytes).await.unwrap();
        socket.write_all(b"\r\n").await.unwrap();
        sent.send(()).unwrap();
        // No terminal chunk: a size guard must reject without waiting for EOF.
        let mut byte = [0];
        let _ = socket.read(&mut byte).await;
    });
    let call = tokio::spawn(async move { kms.wrap(b"dummy-key", "master").await });
    received.await.expect("mock sent more than the one MiB budget");
    let result = tokio::time::timeout(Duration::from_secs(3), call).await;
    server.abort();
    let result = result.expect("oversized KMS response must be rejected before response EOF, not wait for the request timeout").unwrap();
    assert!(result.is_err(), "oversized KMS response must fail closed");
    let error = result.unwrap_err();
    assert!(error.to_ascii_lowercase().contains("too large"), "oversized response must report a size-limit error");
    assert!(!error.contains("opaque-envelope") && !error.contains("dummy-kms-token"), "KMS diagnostics must not dump response material or credentials");
}
