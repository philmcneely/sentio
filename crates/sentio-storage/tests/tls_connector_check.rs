//! Guards the narrowed aws-sdk-s3 feature set.
//!
//! `default-features = false` drops the SDK's legacy rustls 0.21 stack and
//! leaves HTTPS to `default-https-client` (rustls 0.23, aws-lc). If that
//! feature is ever lost, the failure is invisible at compile time and appears
//! in production as a dispatch error with no HTTP connector, so this asserts
//! the connector exists and completes a TLS handshake.
//!
//! Ignored by default: it makes one anonymous, unauthenticated request to
//! s3.amazonaws.com, which S3 rejects. Run it with:
//!
//!     cargo test -p sentio-storage --test tls_connector_check -- --ignored

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "makes one outbound HTTPS request"]
async fn s3_client_has_a_working_https_connector() {
    let conf = aws_sdk_s3::config::Builder::new()
        .behavior_version(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-east-1"))
        .endpoint_url("https://s3.amazonaws.com")
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            "probe", "probe", None, None, "test",
        ))
        .build();
    let client = aws_sdk_s3::Client::from_conf(conf);

    let err = client
        .head_bucket()
        .bucket("tls-connector-probe")
        .send()
        .await
        .expect_err("anonymous head_bucket must be rejected");

    let msg = format!("{err:?}");
    println!(
        "  error kind: {}",
        msg.chars().take(200).collect::<String>()
    );

    assert!(
        !msg.contains("NoHttpConnector") && !msg.contains("no HTTP client"),
        "the SDK has no HTTPS connector: {msg}"
    );
    // A ServiceError means TLS completed and S3 answered. A DispatchFailure
    // means we never got an HTTP response out of the connector.
    assert!(
        msg.contains("ServiceError"),
        "expected an HTTP-level rejection from S3, got: {msg}"
    );
}
