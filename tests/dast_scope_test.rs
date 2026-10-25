use bug_killer::dast::{DastProber, DastScopeConfig};
use bug_killer::types::Severity;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

#[test]
fn test_dast_denies_cloud_metadata_ip() {
    let res = DastProber::probe("http://169.254.169.254/latest/meta-data/", 5);
    assert!(
        res.is_err(),
        "Probing link-local cloud metadata must fail closed"
    );
    let err = res.unwrap_err();
    assert!(
        err.contains("Scope Violation") || err.contains("Prohibited Destination"),
        "Error must indicate scope violation, got: {}",
        err
    );
}

#[test]
fn test_dast_denies_ipv4_mapped_metadata_even_with_internal_permission() {
    let config = DastScopeConfig {
        authorized: true,
        allow_private_targets: true,
        ..DastScopeConfig::default()
    };
    let result = DastProber::probe_with_config("http://[::ffff:169.254.169.254]/", &config);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Prohibited Destination"));
}

#[test]
fn test_dast_sensitive_paths_use_authorized_origin_not_url_path_or_query() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://{}/dashboard?status=1",
        listener.local_addr().unwrap()
    );
    let handler = thread::spawn(move || {
        let mut paths = Vec::new();
        for _ in 0..5 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let count = stream.read(&mut buf).unwrap();
            let line = String::from_utf8_lossy(&buf[..count]);
            paths.push(line.lines().next().unwrap().to_string());
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        }
        paths
    });
    let config = DastScopeConfig {
        authorized: true,
        allow_sensitive_paths: true,
        ..DastScopeConfig::default()
    };
    let result = DastProber::probe_with_config(&url, &config);
    let paths = handler.join().unwrap();
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(paths[0], "GET /dashboard?status=1 HTTP/1.1");
    assert_eq!(paths[1], "GET /.env HTTP/1.1");
    assert_eq!(paths[2], "GET /.git/HEAD HTTP/1.1");
}

#[test]
fn test_dast_denies_unsupported_scheme() {
    let res = DastProber::probe("file:///etc/passwd", 5);
    assert!(res.is_err(), "Non-HTTP schemes must be denied");
    let err = res.unwrap_err();
    assert!(err.contains("Unsupported Scheme") || err.contains("Protocol"));
}

#[test]
fn test_dast_denies_embedded_userinfo_credentials() {
    let res = DastProber::probe("http://admin:supersecret@127.0.0.1:8080", 5);
    assert!(res.is_err(), "Embedded credentials in URL must be denied");
    let err = res.unwrap_err();
    assert!(err.contains("Credentials") || err.contains("Userinfo"));
}

#[test]
fn test_dast_does_not_follow_redirects_outside_the_approved_url() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let destination = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let redirected_url = format!("http://{}", destination.local_addr().unwrap());
    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
        stream
            .write_all(
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\n\r\n",
                    redirected_url
                )
                .as_bytes(),
            )
            .unwrap();
    });
    destination.set_nonblocking(true).unwrap();
    let destination_handle = thread::spawn(move || {
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_secs(3) {
            if let Ok((mut stream, _)) = destination.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                return true;
            }
            thread::sleep(std::time::Duration::from_millis(10));
        }
        false
    });

    let result = DastProber::probe(&url, 2);
    server_handle.join().unwrap();
    let _destination_contacted = destination_handle.join().unwrap();
    assert!(
        result.is_err(),
        "Redirects must never be followed as in-scope DAST evidence"
    );
    assert!(
        result.unwrap_err().to_lowercase().contains("redirect"),
        "Redirect rejection must be explicit"
    );
}

#[test]
fn test_dast_sensitive_paths_are_disabled_by_default() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{}", port);

    let requests_received = Arc::new(AtomicUsize::new(0));
    let req_counter = Arc::clone(&requests_received);

    let server_handle = thread::spawn(move || {
        // Default mode should only perform 1 root request (or HEAD/GET root)
        // If sensitive paths were probed, it would attempt 5 requests.
        listener.set_nonblocking(false).unwrap();
        if let Ok((mut stream, _)) = listener.accept() {
            req_counter.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Security-Policy: default-src 'self'\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Length: 7\r\n\r\n<h1>OK</h1>";
            let _ = stream.write_all(resp.as_bytes());
        }
    });

    let config = DastScopeConfig {
        authorized: true,
        allow_private_targets: false,
        allow_sensitive_paths: false, // Default is OFF
        timeout_seconds: 5,
        max_response_bytes: 1024 * 1024,
    };

    let report = DastProber::probe_with_config(&url, &config)
        .expect("Default DAST probe should succeed on authorized loopback");

    assert_eq!(
        requests_received.load(Ordering::SeqCst),
        1,
        "Default DAST probe must NOT send requests to /.env or other sensitive paths"
    );

    assert_eq!(report.endpoints_audited, 1);
    let _ = server_handle.join();
}

#[test]
fn test_dast_json_api_does_not_falsely_flag_missing_html_csp() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{}", port);

    let server_handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            // Pure JSON API response
            let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";
            let _ = stream.write_all(resp.as_bytes());
        }
    });

    let config = DastScopeConfig {
        authorized: true,
        allow_private_targets: false,
        allow_sensitive_paths: false,
        timeout_seconds: 5,
        max_response_bytes: 1024 * 1024,
    };

    let report = DastProber::probe_with_config(&url, &config)
        .expect("Probe of JSON endpoint should succeed");

    // JSON responses do not render HTML scripts, so missing CSP must not be flagged as High severity finding!
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "DAST-HDR-CSP-MISSING" && f.severity == Severity::High),
        "JSON API response must not be flagged with High severity for missing HTML CSP"
    );

    let _ = server_handle.join();
}
