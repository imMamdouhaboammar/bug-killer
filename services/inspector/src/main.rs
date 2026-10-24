#![allow(
    clippy::collapsible_if,
    clippy::manual_flatten,
    clippy::result_large_err,
    clippy::derivable_impls
)]

use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use serde::{Deserialize, Serialize};

use bug_killer_inspector::omni_proto;
use bug_killer_inspector::agent::{
    AgentModelConfig, AgenticSecuritySupervisor, IncidentContext, ModelProvider,
};
use bug_killer_inspector::binary_audit::{BinaryAuditor, DeepBinaryFinding};
use bug_killer_inspector::mem_audit::{ProcessMemoryAuditor, ProcessMemoryFinding};
use bug_killer_inspector::ebpf_tracer::EbpfTracer;
use omni_proto::omni_binary_inspector_server::{OmniBinaryInspector, OmniBinaryInspectorServer};
use omni_proto::{
    BinaryInspectionRequest, BinaryInspectionResponse, PacketStreamInspectionRequest,
    PacketStreamInspectionResponse, RuntimeEvent, RuntimeEventSubscription, Severity,
};
use tonic::{Request, Response, Status};

#[derive(Parser, Debug)]
#[command(name = "bug-killer-inspector")]
#[command(about = "Bug Killer Deep Binary Inspector & eBPF Runtime Engine", version = "0.1.0")]
struct Cli {
    /// Start UDS gRPC server listening on socket path
    #[arg(long, default_value = "/tmp/omni_inspector.sock")]
    socket: PathBuf,

    /// Run as persistent background gRPC server
    #[arg(long, default_value_t = false)]
    serve: bool,

    /// Path to input coverage-ledger.json
    #[arg(short, long)]
    ledger: Option<PathBuf>,

    /// Output findings JSON path
    #[arg(short, long, default_value = "findings.json")]
    out: PathBuf,

    /// Direct single binary audit path
    #[arg(long)]
    binary: Option<PathBuf>,

    /// Direct single PID memory audit
    #[arg(long)]
    pid: Option<i32>,

    /// Run Agentic Security Supervisor investigation
    #[arg(long, default_value_t = false)]
    agent: bool,

    /// Agent LLM provider: deepseek, kimi, minimax, claude, gemini, openai, ollama, openweights, heuristic
    #[arg(long, default_value = "heuristic")]
    agent_provider: String,

    /// Agent model name override
    #[arg(long)]
    agent_model: Option<String>,

    /// Agent custom base URL for open-weights / vLLM / Ollama
    #[arg(long)]
    agent_base_url: Option<String>,

    /// Incident identifier
    #[arg(long, default_value = "INC-OMNI-001")]
    incident_id: String,

    /// Anomaly description for agent investigation
    #[arg(
        long,
        default_value = "Runtime memory anomaly detected by Tier-1 kernel probe"
    )]
    anomaly: String,
}

#[derive(Debug, Deserialize)]
struct LedgerAsset {
    #[serde(rename = "type")]
    _asset_type: String,
    path: String,
    #[allow(dead_code)]
    source: String,
    associated_pid: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct CoverageLedgerInput {
    host_id: String,
    total_assets: usize,
    assets: Vec<LedgerAsset>,
}

#[derive(Debug, Serialize)]
struct ComprehensiveAuditReport {
    host_id: String,
    audit_timestamp: String,
    total_assets_inspected: usize,
    critical_findings_count: usize,
    high_findings_count: usize,
    binary_findings: Vec<DeepBinaryFinding>,
    process_findings: Vec<ProcessMemoryFinding>,
}

pub struct OmniBinaryInspectorImpl {
    tracer: Arc<EbpfTracer>,
}

#[tonic::async_trait]
impl OmniBinaryInspector for OmniBinaryInspectorImpl {
    async fn inspect_binary(
        &self,
        request: Request<BinaryInspectionRequest>,
    ) -> Result<Response<BinaryInspectionResponse>, Status> {
        let req = request.into_inner();
        let resp = BinaryAuditor::audit_binary_proto(&req);
        Ok(Response::new(resp))
    }

    async fn inspect_packet_stream(
        &self,
        request: Request<PacketStreamInspectionRequest>,
    ) -> Result<Response<PacketStreamInspectionResponse>, Status> {
        let req = request.into_inner();
        let payload = &req.raw_payload;

        let mut malicious = false;
        let mut sig = String::new();
        let mut sev = Severity::Low;
        let mut waf_action = "ALLOW".to_string();

        let text = String::from_utf8_lossy(payload);
        if text.contains("Content-Encoding: br") && text.contains("Transfer-Encoding: chunked") {
            malicious = true;
            sig = "CVE-2026-109618_BROTLI_CHUNKED_CORRUPTION".to_string();
            sev = Severity::Critical;
            waf_action = "DROP_415_UNSUPPORTED_MEDIA_TYPE".to_string();
        } else if text.contains("eval(base64_decode") {
            malicious = true;
            sig = "YARA_WEBSHELL_EVAL_BASE64".to_string();
            sev = Severity::Critical;
            waf_action = "DROP_AND_TERMINATE_CONNECTION".to_string();
        }

        Ok(Response::new(PacketStreamInspectionResponse {
            capture_session_id: req.capture_session_id,
            malicious_intent_detected: malicious,
            matched_signature: sig,
            severity: sev as i32,
            recommended_waf_action: waf_action,
            sanitized_payload: Vec::new(),
        }))
    }

    type StreamRuntimeEventsStream =
        std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<RuntimeEvent, Status>> + Send + 'static>>;

    async fn stream_runtime_events(
        &self,
        request: Request<RuntimeEventSubscription>,
    ) -> Result<Response<Self::StreamRuntimeEventsStream>, Status> {
        let sub = request.into_inner();
        let stream = self.tracer.subscribe(sub.filter_types, sub.target_pid_filter);
        Ok(Response::new(Box::pin(stream)))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // 0. Agentic Security Supervisor mode
    if cli.agent {
        let provider = ModelProvider::from_str_loose(&cli.agent_provider);
        let default_model = match provider {
            ModelProvider::DeepSeek => "deepseek-chat".to_string(),
            ModelProvider::Kimi => "kimi-k3".to_string(),
            ModelProvider::MiniMax => "MiniMax-M3".to_string(),
            ModelProvider::Claude => "claude-3-5-sonnet-20241022".to_string(),
            ModelProvider::Gemini => "gemini-2.5-flash".to_string(),
            ModelProvider::OpenAi => "gpt-4o".to_string(),
            ModelProvider::Ollama => "llama3.3".to_string(),
            ModelProvider::OpenWeightsCompatible => "default-model".to_string(),
            ModelProvider::DeterministicHeuristic => "heuristic-v1".to_string(),
        };

        let model_name = cli.agent_model.unwrap_or(default_model);
        let config = AgentModelConfig {
            provider,
            model_name,
            base_url: cli.agent_base_url,
            api_key: None, // Will default from environment if available
            temperature: 0.1,
        };

        let supervisor = AgenticSecuritySupervisor::new(config);
        let incident = IncidentContext {
            incident_id: cli.incident_id,
            alert_source: "CLI-OmniAgent".to_string(),
            target_binary: cli.binary.map(|p| p.to_string_lossy().to_string()),
            target_pid: cli.pid,
            anomaly_description: cli.anomaly,
            cve_hint: None,
        };

        match supervisor.investigate_incident(&incident).await {
            Ok(report) => {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            }
            Err(e) => {
                eprintln!("[-] Agent investigation failed: {}", e);
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    // 1. Direct single target binary mode
    if let Some(ref bin_path) = cli.binary {
        match BinaryAuditor::audit_binary(bin_path) {
            Ok(finding) => {
                println!("{}", serde_json::to_string_pretty(&finding).unwrap());
            }
            Err(e) => {
                eprintln!("[-] Error inspecting {:?}: {}", bin_path, e);
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    // 2. Direct single target PID mode
    if let Some(pid) = cli.pid {
        match ProcessMemoryAuditor::audit_process(pid) {
            Ok(finding) => {
                println!("{}", serde_json::to_string_pretty(&finding).unwrap());
            }
            Err(e) => {
                eprintln!("[-] Error inspecting PID {}: {}", pid, e);
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    // 3. Ledger mode if ledger option given
    if let Some(ref ledger_path) = cli.ledger {
        if !ledger_path.exists() {
            eprintln!("[-] Coverage ledger {:?} not found.", ledger_path);
            std::process::exit(1);
        }

        let ledger_data = fs::read_to_string(ledger_path)?;
        let ledger: CoverageLedgerInput = serde_json::from_str(&ledger_data)?;

        println!("[+] Aegis Inspector: Ingested ledger from '{}' (Total Assets: {})", ledger.host_id, ledger.total_assets);
        let mut binary_findings = Vec::new();
        let mut process_findings = Vec::new();

        for asset in ledger.assets {
            if asset.path.contains("bin") || asset.path.contains("opt") {
                if let Ok(finding) = BinaryAuditor::audit_binary(Path::new(&asset.path)) {
                    binary_findings.push(finding);
                }
            }
            if let Some(pid) = asset.associated_pid {
                if let Ok(finding) = ProcessMemoryAuditor::audit_process(pid) {
                    process_findings.push(finding);
                }
            }
        }

        let report = ComprehensiveAuditReport {
            host_id: ledger.host_id,
            audit_timestamp: chrono::Utc::now().to_rfc3339(),
            total_assets_inspected: binary_findings.len() + process_findings.len(),
            critical_findings_count: binary_findings.iter().filter(|b| b.severity == "CRITICAL").count(),
            high_findings_count: binary_findings.iter().filter(|b| b.severity == "HIGH").count(),
            binary_findings,
            process_findings,
        };

        fs::write(&cli.out, serde_json::to_string_pretty(&report)?)?;
        println!("[✓] Inspector written comprehensive audit report to {:?}", cli.out);
        return Ok(());
    }

    // 4. Default: Launch Tonic UDS gRPC Server
    let socket_path = cli.socket.clone();
    if socket_path.exists() {
        let _ = fs::remove_file(&socket_path);
    }

    println!("[+] Omni-Inspector: Initializing UDS gRPC server at {:?}", socket_path);
    let uds_listener = tokio::net::UnixListener::bind(&socket_path)?;

    let tracer = Arc::new(EbpfTracer::new());
    tracer.start_kernel_probe_loop();

    let service = OmniBinaryInspectorImpl { tracer };
    let incoming = async_stream::stream! {
        loop {
            let item = uds_listener.accept().await.map(|(sock, _)| sock);
            yield item;
        }
    };

    println!("[✓] Omni-Inspector: Listening on UDS socket {:?} (Aya eBPF & Goblin Ready)", socket_path);
    tonic::transport::Server::builder()
        .add_service(OmniBinaryInspectorServer::new(service))
        .serve_with_incoming_shutdown(incoming, async {
            let _ = tokio::signal::ctrl_c().await;
            println!("\n[*] Omni-Inspector: Shutdown signal received. Cleaning up socket...");
        })
        .await?;

    if socket_path.exists() {
        let _ = fs::remove_file(&socket_path);
    }

    Ok(())
}
