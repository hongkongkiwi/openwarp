use openwarp_sdk::{Client, Error};
use reqwest::Method;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::Duration;

struct Mock {
    base: String,
    calls: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Mock {
    fn new(status: u16, body: &str, location: Option<&str>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(Mutex::new(Vec::new()));
        let captured = calls.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let response = format!("HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n{}\r\n{body}", body.len(), location.map(|l| format!("Location: {l}\r\n")).unwrap_or_default());
        let thread = std::thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                        let mut bytes = Vec::new();
                        let mut chunk = [0u8; 4096];
                        loop {
                            let n = stream.read(&mut chunk).unwrap_or(0);
                            if n == 0 { break; }
                            bytes.extend_from_slice(&chunk[..n]);
                            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                                let header = String::from_utf8_lossy(&bytes[..end]);
                                let len = header.lines().find_map(|l| {
                                    let (key, value) = l.split_once(':')?;
                                    if key.eq_ignore_ascii_case("content-length") { value.trim().parse::<usize>().ok() } else { None }
                                }).unwrap_or(0);
                                if bytes.len() >= end + 4 + len { break; }
                            }
                        }
                        captured.lock().unwrap().push(String::from_utf8(bytes).unwrap());
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(5)),
                    Err(e) => panic!("mock accept: {e}"),
                }
            }
        });
        Self { base, calls, stop, thread: Some(thread) }
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}

#[tokio::test]
async fn generic_api_encodes_segments_query_and_body() {
    let mock = Mock::new(200, "{\"ok\":true}", None);
    let client = Client::new(&mock.base, "test-token").unwrap();
    let query = vec![("search".into(), "a&b=雪 +/?#".into()), ("tag".into(), "one".into()), ("tag".into(), "two".into())];
    let body: Value = client.api(Method::PATCH, &["orgs", "a/b ?#雪", "settings"], Some(json!({"name":"雪"})), &query).await.unwrap();
    assert_eq!(body, json!({"ok":true}));
    let calls = mock.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (head, raw) = calls[0].split_once("\r\n\r\n").unwrap();
    let target = head.lines().next().unwrap().split_whitespace().nth(1).unwrap();
    let url = reqwest::Url::parse(&format!("{}{}", mock.base, target)).unwrap();
    assert_eq!(url.path(), "/api/orgs/a%2Fb%20%3F%23%E9%9B%AA/settings");
    assert_eq!(url.query_pairs().map(|(k,v)| (k.into_owned(),v.into_owned())).collect::<Vec<_>>(), query);
    assert!(head.to_ascii_lowercase().contains("authorization: bearer test-token\r\n"));
    assert_eq!(serde_json::from_str::<Value>(raw).unwrap(), json!({"name":"雪"}));
}

#[tokio::test]
async fn generic_api_supports_methods_and_empty_success() {
    let mock = Mock::new(204, "", None);
    let client = Client::new(&mock.base, "test-token").unwrap();
    for method in [Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE, Method::HEAD, Method::OPTIONS] {
        let result: Value = client.api(method.clone(), &["orgs"], None, &[]).await.unwrap();
        assert_eq!(result, Value::Null);
        assert!(mock.calls.lock().unwrap().last().unwrap().starts_with(&format!("{method} /api/orgs HTTP/1.1\r\n")));
    }
}

#[tokio::test]
async fn generic_api_rejects_unsafe_inputs_before_network() {
    let mock = Mock::new(200, "{}", None);
    let client = Client::new(&mock.base, "test-token").unwrap();
    for segment in [".","..","%2e","%2E%2e",".%2e","%252e%252e","a/../b","a%2f..%2fb","a%252f%252e%252e%252fb","bad%","%GG","back\\slash","bad\n","bad\0","bad\u{7f}","https://example.invalid/api/me","//example.invalid/api/me"] {
        let result = client.api::<Value>(Method::GET, &["orgs", segment], None, &[]).await;
        assert!(result.is_err(), "accepted {segment:?}");
    }
    for method in [Method::TRACE, Method::CONNECT, Method::from_bytes(b"BREW").unwrap()] {
        assert!(client.api::<Value>(method, &["me"], None, &[]).await.is_err());
    }
    assert!(mock.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn generic_api_preserves_http_errors() {
    for status in [400,401,403,404,409,429,500,503] {
        for (raw, expected) in [("{\"error\":\"denied\"}", json!({"error":"denied"})), ("provider unavailable", json!("provider unavailable"))] {
            let mock = Mock::new(status, raw, None);
            let client = Client::new(&mock.base, "test-token").unwrap();
            match client.api::<Value>(Method::GET, &["orgs"], None, &[]).await {
                Err(Error::Api { status: actual, body, .. }) => { assert_eq!(actual, status); assert_eq!(body, expected); }
                other => panic!("HTTP error lost: {other:?}"),
            }
        }
    }
}

#[tokio::test]
async fn generic_api_never_follows_redirects() {
    let target = Mock::new(200, "{}", None);
    let source = Mock::new(307, "", Some(&format!("{}/capture", target.base)));
    let client = Client::new(&source.base, "private-test-token").unwrap();
    assert!(client.api::<Value>(Method::POST, &["orgs"], Some(json!({"name":"private"})), &[]).await.is_err());
    assert!(target.calls.lock().unwrap().is_empty());
    assert_eq!(source.calls.lock().unwrap().len(), 1);
    let same = Mock::new(307, "", Some("/capture"));
    let client = Client::new(&same.base, "private-test-token").unwrap();
    assert!(client.api::<Value>(Method::GET, &["orgs"], None, &[]).await.is_err());
    assert_eq!(same.calls.lock().unwrap().len(), 1);
}
