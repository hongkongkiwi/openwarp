use openwarp_server::http::read_bounded;

#[tokio::test]
async fn provider_response_limit_accepts_exactly_the_budget() {
    let bytes = vec![b'x'; 1024];
    let response = reqwest::Response::from(axum::http::Response::new(bytes.clone()));
    assert_eq!(read_bounded(response, bytes.len()).await.unwrap(), bytes);
}

#[tokio::test]
async fn provider_response_limit_rejects_one_byte_over_the_budget() {
    let response = reqwest::Response::from(axum::http::Response::new(vec![b'x'; 1025]));
    assert_eq!(read_bounded(response, 1024).await.unwrap_err(), "provider response is too large");
}

#[tokio::test]
async fn zero_response_budget_accepts_only_an_empty_body() {
    let empty = reqwest::Response::from(axum::http::Response::new(Vec::<u8>::new()));
    assert!(read_bounded(empty, 0).await.unwrap().is_empty());
    let nonempty = reqwest::Response::from(axum::http::Response::new(vec![b'x']));
    assert_eq!(read_bounded(nonempty, 0).await.unwrap_err(), "provider response is too large");
}
