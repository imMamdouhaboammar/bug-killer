use std::path::PathBuf;
use std::time::Duration;
use tokio::time::sleep;

use bug_killer_inspector::binary_audit::BinaryAuditor;
use bug_killer_inspector::ebpf_tracer::EbpfTracer;
use bug_killer_inspector::omni_proto::omni_binary_inspector_client::OmniBinaryInspectorClient;
use bug_killer_inspector::omni_proto::omni_binary_inspector_server::{
    OmniBinaryInspector, OmniBinaryInspectorServer,
};
use bug_killer_inspector::omni_proto::{
    BinaryInspectionRequest, PacketStreamInspectionRequest, RuntimeEventSubscription,
};
use hyper_util::rt::tokio::TokioIo;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

struct TestServer {
    tracer: std::sync::Arc<EbpfTracer>,
}

#[tonic::async_trait]
impl OmniBinaryInspector for TestServer {
    async fn inspect_binary(
        &self,
        request: tonic::Request<BinaryInspectionRequest>,
    ) -> Result<
        tonic::Response<bug_killer_inspector::omni_proto::BinaryInspectionResponse>,
        tonic::Status,
    > {
        let req = request.into_inner();
        let resp = BinaryAuditor::audit_binary_proto(&req);
        Ok(tonic::Response::new(resp))
    }

    async fn inspect_packet_stream(
        &self,
        request: tonic::Request<PacketStreamInspectionRequest>,
    ) -> Result<
        tonic::Response<bug_killer_inspector::omni_proto::PacketStreamInspectionResponse>,
        tonic::Status,
    > {
        let req = request.into_inner();
        let text = String::from_utf8_lossy(&req.raw_payload);
        let malicious =
            text.contains("Content-Encoding: br") && text.contains("Transfer-Encoding: chunked");
        Ok(tonic::Response::new(
            bug_killer_inspector::omni_proto::PacketStreamInspectionResponse {
                capture_session_id: req.capture_session_id,
                malicious_intent_detected: malicious,
                matched_signature: if malicious {
                    "CVE-2026-109618".into()
                } else {
                    "".into()
                },
                severity: if malicious { 4 } else { 1 },
                recommended_waf_action: if malicious {
                    "DROP_415".into()
                } else {
                    "ALLOW".into()
                },
                sanitized_payload: Vec::new(),
            },
        ))
    }

    type StreamRuntimeEventsStream = std::pin::Pin<
        Box<
            dyn tokio_stream::Stream<
                    Item = Result<bug_killer_inspector::omni_proto::RuntimeEvent, tonic::Status>,
                > + Send
                + 'static,
        >,
    >;

    async fn stream_runtime_events(
        &self,
        request: tonic::Request<RuntimeEventSubscription>,
    ) -> Result<tonic::Response<Self::StreamRuntimeEventsStream>, tonic::Status> {
        let sub = request.into_inner();
        let stream = self
            .tracer
            .subscribe(sub.filter_types, sub.target_pid_filter);
        Ok(tonic::Response::new(Box::pin(stream)))
    }
}

#[tokio::test]
async fn test_grpc_uds_inspection_roundtrip() {
    let socket_path = PathBuf::from(format!("/tmp/test_uds_{}.sock", std::process::id()));
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    let socket_clone = socket_path.clone();
    let tracer = std::sync::Arc::new(EbpfTracer::new());
    let server_tracer = tracer.clone();

    // Spawn server on UDS
    tokio::spawn(async move {
        let listener = tokio::net::UnixListener::bind(&socket_clone).unwrap();
        let incoming = async_stream::stream! {
            loop {
                let item = listener.accept().await.map(|(s, _)| s);
                yield item;
            }
        };

        let svc = TestServer {
            tracer: server_tracer,
        };
        tonic::transport::Server::builder()
            .add_service(OmniBinaryInspectorServer::new(svc))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    sleep(Duration::from_millis(150)).await;

    // Connect client over UDS
    let socket_for_client = socket_path.clone();
    let channel = Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = socket_for_client.clone();
            async move {
                tokio::net::UnixStream::connect(path)
                    .await
                    .map(TokioIo::new)
            }
        }))
        .await
        .expect("Failed to connect client to UDS server");

    let mut client = OmniBinaryInspectorClient::new(channel);

    // 1. Test Binary Inspection with synthetic binary payload
    let synthetic_payload = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x3e\x00X-Powered-By: PHP/8.2.10\x00brotli\x00longjmp";
    let bin_req = BinaryInspectionRequest {
        request_id: "req-test-1".into(),
        file_path: "/usr/local/bin/php".into(),
        binary_payload: synthetic_payload.to_vec(),
        expected_arch: 0,
        extract_symbols: true,
        verify_hardening_flags: true,
    };

    let bin_resp = client.inspect_binary(bin_req).await.unwrap().into_inner();
    assert_eq!(bin_resp.request_id, "req-test-1");
    assert_eq!(bin_resp.binary_format, "ELF");
    assert!(bin_resp.hardening_flags.is_some());

    // 2. Test Packet Stream Inspection
    let pkt_payload =
        b"POST /api HTTP/1.1\r\nContent-Encoding: br\r\nTransfer-Encoding: chunked\r\n\r\n";
    let pkt_req = PacketStreamInspectionRequest {
        capture_session_id: "sess-1".into(),
        network_interface: "lo0".into(),
        source_endpoint: "127.0.0.1:4444".into(),
        destination_endpoint: "127.0.0.1:80".into(),
        protocol: "TCP".into(),
        raw_payload: pkt_payload.to_vec(),
        extracted_headers: std::collections::HashMap::new(),
    };

    let pkt_resp = client
        .inspect_packet_stream(pkt_req)
        .await
        .unwrap()
        .into_inner();
    assert!(pkt_resp.malicious_intent_detected);
    assert_eq!(pkt_resp.recommended_waf_action, "DROP_415");

    let _ = std::fs::remove_file(&socket_path);
}
