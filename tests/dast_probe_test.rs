use bug_killer::dast::{DastProber, DastScopeConfig};
use bug_killer::types::Severity;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

#[test]
fn test_dast_probe_against_mock_server() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{}", port);

    // Spawn mock HTTP server thread (1 root request + 4 sensitive path probes = 5 requests total)
    let server_handle = thread::spawn(move || {
        for _ in 0..5 {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0u8; 1024];
                let _ = stream.read(&mut buffer);

                let req_str = String::from_utf8_lossy(&buffer);
                if req_str.contains("GET /.env ") {
                    let response =
                        "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nSECRET_KEY=123456789\n";
                    let _ = stream.write_all(response.as_bytes());
                } else if req_str.contains("GET /.git/HEAD ") {
                    let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                    let _ = stream.write_all(response.as_bytes());
                } else {
                    // Root request leaking X-Powered-By and missing CSP
                    let response = "HTTP/1.1 200 OK\r\nX-Powered-By: Express/4.18.2\r\nServer: Apache/2.4.52\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n<h1>Hello</h1>";
                    let _ = stream.write_all(response.as_bytes());
                }
            }
        }
    });

    let config = DastScopeConfig {
        authorized: true,
        allow_private_targets: false,
        allow_sensitive_paths: true,
        timeout_seconds: 5,
        max_response_bytes: 1024 * 1024,
    };

    let report = DastProber::probe_with_config(&url, &config)
        .expect("DAST probe should complete successfully");

    assert!(
        report.is_vulnerable,
        "Mock server should be flagged as vulnerable"
    );
    assert_eq!(report.status_code, 200);

    // Verify missing CSP finding
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "DAST-HDR-CSP-MISSING" && f.severity == Severity::High)
    );

    // Verify information disclosure findings
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "DAST-LEAK-X-POWERED-BY")
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "DAST-LEAK-SERVER-VERSION")
    );

    // Verify exposed /.env finding
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "DAST-EXPOSURE-ENV" && f.severity == Severity::Critical)
    );

    let _ = server_handle.join();
}
