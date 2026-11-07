use openwarp_sdk::Client;
use reqwest::Method;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpListener;

#[tokio::test]
async fn explicit_grant_sets_header_and_original_api_remains_compatible() {
    let listener=TcpListener::bind("127.0.0.1:0").unwrap(); let base=format!("http://{}",listener.local_addr().unwrap());
    let thread=std::thread::spawn(move || {
        let mut requests=Vec::new();
        for _ in 0..2 {
            let (mut stream,_)=listener.accept().unwrap(); stream.set_read_timeout(Some(std::time::Duration::from_secs(3))).unwrap();
            let mut bytes=Vec::new(); let mut buf=[0;4096];
            while !bytes.windows(4).any(|w|w==b"\r\n\r\n") {let n=stream.read(&mut buf).unwrap(); assert_ne!(n,0); bytes.extend_from_slice(&buf[..n]);}
            requests.push(String::from_utf8(bytes).unwrap().to_ascii_lowercase());
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").unwrap();
        }
        requests
    });
    let client=Client::new(&base,"original-bearer").unwrap();
    let _:Value=client.api_with_step_up(Method::GET,&["me"],None,&[],"stepupg_safe-grant").await.unwrap();
    let _:Value=client.api(Method::GET,&["me"],None,&[]).await.unwrap();
    let requests=thread.join().unwrap();
    assert!(requests[0].contains("x-openwarp-step-up: stepupg_safe-grant\r\n"));
    assert!(!requests[1].contains("x-openwarp-step-up:"));
    for request in requests {assert!(request.contains("authorization: bearer original-bearer\r\n"));}
}

#[tokio::test]
async fn invalid_grants_fail_before_network() {
    let listener=TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
    let client=Client::new(&format!("http://{}",listener.local_addr().unwrap()),"original-bearer").unwrap();
    let long="x".repeat(513);
    for grant in ["","x\r\nAuthorization: forged","x\0","x\u{1f}","x\u{7f}","é",long.as_str()] {
        let result=tokio::time::timeout(std::time::Duration::from_secs(2),client.api_with_step_up::<Value>(Method::GET,&["me"],None,&[],grant)).await.expect("invalid grant reached network");
        assert!(result.is_err(),"accepted grant {grant:?}");
        assert!(matches!(listener.accept(),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock),"invalid grant made a connection");
    }
}
