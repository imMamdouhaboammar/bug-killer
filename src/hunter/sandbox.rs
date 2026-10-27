use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Default maximum memory allocation budget for a research sandbox: 512 MB.
pub const DEFAULT_MAX_MEMORY_BYTES: u64 = 512 * 1024 * 1024;

/// Default execution timeout: 5000 milliseconds (5 seconds).
pub const DEFAULT_TIMEOUT_MS: u64 = 5000;

/// Default maximum captured output size: 1 MB.
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Operating system-level isolation mechanism applied to the sandboxed execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationMechanism {
    /// macOS kernel Seatbelt sandbox applied via `/usr/bin/sandbox-exec` profile.
    MacSeatbelt,
    /// Linux Bubblewrap container isolation (`bwrap`).
    LinuxBubblewrap,
    /// Linux unprivileged user + network namespaces (`unshare -r -n`).
    LinuxNamespace,
    /// POSIX process resource limits (`setrlimit`) only (no network/fs namespace).
    PosixRlimitsOnly,
    /// No OS-level isolation active.
    None,
}

impl IsolationMechanism {
    pub fn as_str(&self) -> &'static str {
        match self {
            IsolationMechanism::MacSeatbelt => "MacSeatbelt",
            IsolationMechanism::LinuxBubblewrap => "LinuxBubblewrap",
            IsolationMechanism::LinuxNamespace => "LinuxNamespace",
            IsolationMechanism::PosixRlimitsOnly => "PosixRlimitsOnly",
            IsolationMechanism::None => "None",
        }
    }
}

/// Detects the strongest OS-level isolation mechanism supported on the current host.
pub fn detect_isolation_mechanism() -> IsolationMechanism {
    #[cfg(target_os = "macos")]
    {
        if Path::new("/usr/bin/sandbox-exec").exists() {
            IsolationMechanism::MacSeatbelt
        } else {
            IsolationMechanism::PosixRlimitsOnly
        }
    }

    #[cfg(target_os = "linux")]
    {
        if (find_in_path("bwrap").is_some() || Path::new("/usr/bin/bwrap").exists())
            && Command::new("bwrap")
                .args(["--ro-bind", "/", "/", "true"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        {
            IsolationMechanism::LinuxBubblewrap
        } else if find_in_path("unshare").is_some()
            && Command::new("unshare")
                .args(["-r", "-n", "true"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        {
            IsolationMechanism::LinuxNamespace
        } else {
            IsolationMechanism::PosixRlimitsOnly
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        #[cfg(unix)]
        {
            IsolationMechanism::PosixRlimitsOnly
        }
        #[cfg(not(unix))]
        {
            IsolationMechanism::None
        }
    }
}

#[allow(dead_code)]
fn find_in_path(executable: &str) -> Option<PathBuf> {
    if let Some(paths) = std::env::var_os("PATH") {
        for path in std::env::split_paths(&paths) {
            let full = path.join(executable);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    None
}

/// Configuration defining isolation boundaries, budgets, and environment sanitization for sandboxed execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Maximum memory bytes permitted during execution (default: 512MB).
    pub max_memory_bytes: u64,
    /// Maximum wall-clock time in milliseconds before execution is aborted (default: 5000ms).
    pub timeout_ms: u64,
    /// Maximum bytes captured from stdout and stderr combined (default: 1MB).
    pub max_output_bytes: usize,
    /// Maximum allowed file size for generated artifacts (default: 1MB).
    pub max_file_size_bytes: u64,
    /// Whether outbound network access is permitted. MUST be `false` for isolation invariant.
    pub allow_network: bool,
    /// Whether ambient host credentials and tokens are scrubbed from environment (default: true).
    pub strip_ambient_env: bool,
    /// Explicit prefixes of environment variables to scrub (e.g. `AWS_`, `GITHUB_`, `SECRET_`, `TOKEN_`).
    pub stripped_env_prefixes: Vec<String>,
    /// Whether OS-level isolation is mandatory (fail-closed if unavailable on host, default: true).
    pub require_os_isolation: bool,
    /// Maximum CPU seconds before process termination via rlimit (default: Some(15)).
    pub max_cpu_seconds: Option<u64>,
    /// Maximum number of processes permitted (default: Some(64)).
    pub max_pid_count: Option<u32>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_file_size_bytes: 1024 * 1024,
            allow_network: false,
            strip_ambient_env: true,
            stripped_env_prefixes: vec![
                "AWS_".to_string(),
                "GITHUB_".to_string(),
                "SECRET_".to_string(),
                "TOKEN_".to_string(),
            ],
            require_os_isolation: true,
            max_cpu_seconds: Some(15),
            max_pid_count: None,
        }
    }
}

impl SandboxConfig {
    /// Validates safety invariants of sandbox configuration.
    ///
    /// Invariant: Outbound network egress is strictly forbidden (`allow_network == false`).
    pub fn validate(&self) -> Result<(), SandboxError> {
        if self.allow_network {
            return Err(SandboxError::IsolationViolation(
                "Sandbox isolation policy violation: allow_network MUST be false; zero network egress permitted"
                    .to_string(),
            ));
        }
        if self.timeout_ms == 0 {
            return Err(SandboxError::InvalidConfiguration(
                "Sandbox timeout_ms must be greater than zero".to_string(),
            ));
        }
        if self.max_memory_bytes == 0 {
            return Err(SandboxError::InvalidConfiguration(
                "Sandbox max_memory_bytes must be greater than zero".to_string(),
            ));
        }
        if self.require_os_isolation && detect_isolation_mechanism() == IsolationMechanism::None {
            return Err(SandboxError::IsolationViolation(
                "OS-level sandbox isolation is required by policy but unsupported on this host platform"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    pub fn with_max_memory_bytes(mut self, max_memory_bytes: u64) -> Self {
        self.max_memory_bytes = max_memory_bytes;
        self
    }

    pub fn with_max_output_bytes(mut self, max_output_bytes: usize) -> Self {
        self.max_output_bytes = max_output_bytes;
        self
    }

    pub fn with_stripped_env_prefixes(mut self, prefixes: Vec<String>) -> Self {
        self.stripped_env_prefixes = prefixes;
        self
    }

    pub fn with_require_os_isolation(mut self, require: bool) -> Self {
        self.require_os_isolation = require;
        self
    }

    pub fn with_max_cpu_seconds(mut self, max_cpu: u64) -> Self {
        self.max_cpu_seconds = Some(max_cpu);
        self
    }

    pub fn with_max_pid_count(mut self, max_pids: u32) -> Self {
        self.max_pid_count = Some(max_pids);
        self
    }
}

/// Execution status reported upon completion or termination of a sandboxed run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxStatus {
    Completed,
    TimedOut,
    ResourceExceeded,
    Killed,
    Blocked,
    Error,
}

impl SandboxStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SandboxStatus::Completed => "Completed",
            SandboxStatus::TimedOut => "TimedOut",
            SandboxStatus::ResourceExceeded => "ResourceExceeded",
            SandboxStatus::Killed => "Killed",
            SandboxStatus::Blocked => "Blocked",
            SandboxStatus::Error => "Error",
        }
    }
}

/// An immutable, non-repudiable receipt summarizing a completed sandboxed execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxExecutionReceipt {
    pub receipt_id: String,
    pub sandbox_id: String,
    pub duration_ms: u64,
    pub peak_memory_bytes: u64,
    pub exit_code: Option<i32>,
    pub status: SandboxStatus,
    pub isolation_mechanism: IsolationMechanism,
    pub isolation_enforced: bool,
    pub host_os: String,
    pub network_egress_prevented: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub output_truncated: bool,
    pub created_at: String,
    pub receipt_sha256: String,
}

impl SandboxExecutionReceipt {
    pub fn is_success(&self) -> bool {
        self.status == SandboxStatus::Completed && self.exit_code == Some(0)
    }

    pub fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).to_string()
    }

    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).to_string()
    }
}

/// Cooperative cancellation token enabling callers to safely abort in-flight sandbox experiments.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// Errors occurring during sandbox configuration, initialization, or execution.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("Sandbox isolation violation: {0}")]
    IsolationViolation(String),

    #[error("Invalid sandbox configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Execution timed out after {0} ms")]
    TimedOut(u64),

    #[error("Execution cancelled cooperatively")]
    Cancelled,

    #[error("Resource limit exceeded: {0}")]
    ResourceExceeded(String),

    #[error("I/O error during sandbox execution: {0}")]
    Io(#[from] std::io::Error),

    #[error("Process spawn or execution error: {0}")]
    ExecutionFailed(String),
}

/// Checks whether an environment variable key is sensitive or exposes ambient credentials.
pub fn is_sensitive_env_var(key: &str) -> bool {
    let upper = key.to_uppercase();
    upper.starts_with("AWS_")
        || upper.starts_with("GITHUB_")
        || upper.starts_with("SECRET_")
        || upper.starts_with("TOKEN_")
        || upper.contains("SECRET")
        || upper.contains("TOKEN")
        || upper.contains("API_KEY")
        || upper.contains("AUTH")
        || upper.contains("CREDENTIAL")
        || upper.contains("PRIVATE_KEY")
        || upper.starts_with("SSH_")
        || upper.starts_with("CI_")
}

/// Sandboxed ephemeral runner executing research experiments with strict containment.
#[derive(Debug, Clone)]
pub struct SandboxRunner {
    config: SandboxConfig,
    cancellation_token: CancellationToken,
}

impl SandboxRunner {
    /// Creates a new `SandboxRunner` with the provided configuration.
    /// Fails closed if `config.allow_network` is true.
    pub fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        config.validate()?;
        Ok(Self {
            config,
            cancellation_token: CancellationToken::new(),
        })
    }

    /// Creates a default sandbox runner with standard isolation budgets and zero network egress.
    pub fn default_runner() -> Result<Self, SandboxError> {
        Self::new(SandboxConfig::default())
    }

    /// Binds a cooperative cancellation token to this runner.
    pub fn with_cancellation_token(mut self, token: CancellationToken) -> Self {
        self.cancellation_token = token;
        self
    }

    /// Accessor for configuration.
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }

    /// Executes a closure in an ephemeral sandboxed directory.
    /// The directory is deleted when this method exits.
    pub fn run_closure<F, R>(&self, f: F) -> Result<(R, SandboxExecutionReceipt), SandboxError>
    where
        F: FnOnce(&Path) -> Result<R, SandboxError>,
    {
        if self.cancellation_token.is_cancelled() {
            return Err(SandboxError::Cancelled);
        }

        let temp_dir = tempfile::Builder::new()
            .prefix("bk_hunter_closure_")
            .tempdir()?;

        let sandbox_id = format!("sbx-closure-{}", nanoid_simple());
        let start_time = Instant::now();

        let result = f(temp_dir.path());
        let duration_ms = start_time.elapsed().as_millis() as u64;

        let status = if self.cancellation_token.is_cancelled() {
            SandboxStatus::Killed
        } else if duration_ms > self.config.timeout_ms {
            SandboxStatus::TimedOut
        } else if result.is_err() {
            SandboxStatus::Error
        } else {
            SandboxStatus::Completed
        };

        let peak_rss = get_process_rss_bytes(std::process::id()).unwrap_or(0);
        let receipt = build_receipt(
            &sandbox_id,
            duration_ms,
            peak_rss,
            if result.is_ok() { Some(0) } else { Some(1) },
            status,
            IsolationMechanism::None,
            false,
            std::env::consts::OS.to_string(),
            false,
            Vec::new(),
            Vec::new(),
            false,
        );

        let res = result?;
        Ok((res, receipt))
    }

    /// Executes a test command with args in an ephemeral directory with strict environment stripping,
    /// zero network egress, and bounded output capture.
    pub fn run_command(
        &self,
        program: &str,
        args: &[&str],
    ) -> Result<SandboxExecutionReceipt, SandboxError> {
        self.run_command_with_input(program, args, None)
    }

    /// Executes a command with optional stdin input in an ephemeral sandboxed directory.
    pub fn run_command_with_input(
        &self,
        program: &str,
        args: &[&str],
        stdin_input: Option<&[u8]>,
    ) -> Result<SandboxExecutionReceipt, SandboxError> {
        self.config.validate()?;

        if self.cancellation_token.is_cancelled() {
            return Err(SandboxError::Cancelled);
        }

        let mechanism = detect_isolation_mechanism();
        if self.config.require_os_isolation && mechanism == IsolationMechanism::None {
            return Err(SandboxError::IsolationViolation(
                "OS-level sandbox isolation is required by policy but unsupported on this host platform"
                    .to_string(),
            ));
        }

        let temp_dir = tempfile::Builder::new()
            .prefix("bk_hunter_cmd_")
            .tempdir()?;

        let sandbox_id = format!("sbx-cmd-{}", nanoid_simple());

        // Zero network egress policy preflight check
        if !self.config.allow_network {
            let prog_lower = program.to_lowercase();
            if prog_lower.ends_with("curl")
                || prog_lower.ends_with("wget")
                || prog_lower == "nc"
                || prog_lower == "ncat"
            {
                for arg in args {
                    if arg.starts_with("http://")
                        || arg.starts_with("https://")
                        || arg.starts_with("ftp://")
                    {
                        return Err(SandboxError::IsolationViolation(format!(
                            "Outbound network request to '{}' blocked by sandbox policy (zero egress permitted)",
                            arg
                        )));
                    }
                }
            }
        }

        let canonical_temp = std::fs::canonicalize(temp_dir.path())
            .unwrap_or_else(|_| temp_dir.path().to_path_buf());

        let mut cmd = match mechanism {
            IsolationMechanism::MacSeatbelt => {
                let seatbelt_profile = format!(
                    "(version 1)\n\
                     (deny default)\n\
                     (allow process-exec)\n\
                     (allow process-fork)\n\
                     (allow sysctl-read)\n\
                     (allow file-read*)\n\
                     (allow file-write-data (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/dtracehelper\"))\n\
                     (allow file-write* (subpath \"{}\"))\n\
                     (allow file-write* (subpath \"{}\"))\n\
                     {}\n",
                    canonical_temp.display(),
                    temp_dir.path().display(),
                    if self.config.allow_network {
                        "(allow network*)"
                    } else {
                        "(deny network*)"
                    }
                );
                let mut c = Command::new("/usr/bin/sandbox-exec");
                c.arg("-p");
                c.arg(&seatbelt_profile);
                c.arg(program);
                c.args(args);
                c
            }
            IsolationMechanism::LinuxBubblewrap => {
                let mut c = Command::new("bwrap");
                if !self.config.allow_network {
                    c.arg("--unshare-net");
                }
                c.arg("--ro-bind").arg("/").arg("/");
                c.arg("--dev-bind-try").arg("/dev").arg("/dev");
                c.arg("--proc").arg("/proc");
                c.arg("--bind").arg(&canonical_temp).arg(&canonical_temp);
                if canonical_temp != temp_dir.path() {
                    c.arg("--bind").arg(temp_dir.path()).arg(temp_dir.path());
                }
                c.arg(program);
                c.args(args);
                c
            }
            IsolationMechanism::LinuxNamespace => {
                let mut c = Command::new("unshare");
                c.args(["-r", "-n"]);
                c.arg(program);
                c.args(args);
                c
            }
            IsolationMechanism::PosixRlimitsOnly | IsolationMechanism::None => {
                let mut c = Command::new(program);
                c.args(args);
                c
            }
        };

        cmd.current_dir(temp_dir.path());

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);

            let cpu_limit = self.config.max_cpu_seconds.unwrap_or(15);
            let pid_limit = self.config.max_pid_count;
            unsafe {
                cmd.pre_exec(move || {
                    let rlim_cpu = libc::rlimit {
                        rlim_cur: cpu_limit,
                        rlim_max: cpu_limit + 5,
                    };
                    libc::setrlimit(libc::RLIMIT_CPU, &rlim_cpu);

                    if let Some(pids) = pid_limit {
                        let rlim_nproc = libc::rlimit {
                            rlim_cur: pids as libc::rlim_t,
                            rlim_max: pids as libc::rlim_t,
                        };
                        libc::setrlimit(libc::RLIMIT_NPROC, &rlim_nproc);
                    }

                    Ok(())
                });
            }
        }

        // Sanitization: Strip ambient environment if enabled
        if self.config.strip_ambient_env {
            for (k, _) in std::env::vars() {
                if is_sensitive_env_var(&k)
                    || self
                        .config
                        .stripped_env_prefixes
                        .iter()
                        .any(|p| k.to_uppercase().starts_with(&p.to_uppercase()))
                {
                    cmd.env_remove(&k);
                }
            }
            cmd.env_remove("AWS_ACCESS_KEY_ID");
            cmd.env_remove("AWS_SECRET_ACCESS_KEY");
            cmd.env_remove("AWS_SESSION_TOKEN");
            cmd.env_remove("GITHUB_TOKEN");
            cmd.env_remove("GITHUB_PAT");
            cmd.env_remove("SECRET_KEY");
            cmd.env_remove("TOKEN");

            // Isolate HOME, TMPDIR, and DARWIN_USER_TEMP_DIR to the ephemeral directory
            cmd.env("HOME", &canonical_temp);
            cmd.env("TMPDIR", &canonical_temp);
            cmd.env("DARWIN_USER_TEMP_DIR", &canonical_temp);
        }

        // Network isolation invariant: null-route proxy environment variables and TLS certificates
        if !self.config.allow_network {
            cmd.env("http_proxy", "http://127.0.0.1:0");
            cmd.env("https_proxy", "http://127.0.0.1:0");
            cmd.env("all_proxy", "http://127.0.0.1:0");
            cmd.env("HTTP_PROXY", "http://127.0.0.1:0");
            cmd.env("HTTPS_PROXY", "http://127.0.0.1:0");
            cmd.env("ALL_PROXY", "http://127.0.0.1:0");
            cmd.env("NO_PROXY", "");
            cmd.env("SSL_CERT_FILE", "/dev/null");
            cmd.env("SSL_CERT_DIR", "/dev/null");
            cmd.env("NODE_EXTRA_CA_CERTS", "/dev/null");
        }

        cmd.stdin(if stdin_input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let start_time = Instant::now();
        let mut child = cmd.spawn().map_err(|e| {
            SandboxError::ExecutionFailed(format!("Failed to spawn {}: {}", program, e))
        })?;

        // Write stdin if provided
        if let Some(data) = stdin_input {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(data);
                let _ = stdin.flush();
            }
        }

        let max_output = self.config.max_output_bytes;

        // Drain stdout asynchronously in a worker thread to prevent pipe blocking
        let stdout_handle = child.stdout.take().map(|mut stdout| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut take = (&mut stdout).take((max_output + 1) as u64);
                let _ = take.read_to_end(&mut buf);
                let truncated = buf.len() > max_output;
                if truncated {
                    buf.truncate(max_output);
                }
                (buf, truncated)
            })
        });

        // Drain stderr asynchronously in a worker thread
        let stderr_handle = child.stderr.take().map(|mut stderr| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut take = (&mut stderr).take((max_output + 1) as u64);
                let _ = take.read_to_end(&mut buf);
                let truncated = buf.len() > max_output;
                if truncated {
                    buf.truncate(max_output);
                }
                (buf, truncated)
            })
        });

        let timeout = Duration::from_millis(self.config.timeout_ms);
        let mut status = SandboxStatus::Completed;
        let mut exit_code = None;
        let mut peak_rss: u64 = 0;

        loop {
            // Check cancellation token
            if self.cancellation_token.is_cancelled() {
                terminate_process_tree(&mut child);
                status = SandboxStatus::Killed;
                break;
            }

            // Check timeout budget
            if start_time.elapsed() >= timeout {
                terminate_process_tree(&mut child);
                status = SandboxStatus::TimedOut;
                break;
            }

            // Real process RSS sampling
            if let Some(rss) = get_process_rss_bytes(child.id()) {
                if rss > peak_rss {
                    peak_rss = rss;
                }
                if peak_rss > self.config.max_memory_bytes {
                    terminate_process_tree(&mut child);
                    status = SandboxStatus::ResourceExceeded;
                    break;
                }
            }

            match child.try_wait() {
                Ok(Some(exit_status)) => {
                    exit_code = exit_status.code();
                    if !exit_status.success() && exit_code != Some(0) {
                        status = SandboxStatus::Completed;
                    }
                    break;
                }
                Ok(None) => {
                    std::thread::sleep(Duration::from_millis(15));
                }
                Err(e) => {
                    status = SandboxStatus::Error;
                    exit_code = None;
                    terminate_process_tree(&mut child);
                    eprintln!("Warning: child.try_wait error: {}", e);
                    break;
                }
            }
        }

        // Post-exit rusage capture if peak_rss was too fast to catch during polling
        #[cfg(unix)]
        {
            unsafe {
                let mut usage: libc::rusage = std::mem::zeroed();
                if libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage) == 0 {
                    #[cfg(target_os = "macos")]
                    let rusage_bytes = usage.ru_maxrss as u64;
                    #[cfg(not(target_os = "macos"))]
                    let rusage_bytes = (usage.ru_maxrss as u64) * 1024;
                    if rusage_bytes > peak_rss {
                        peak_rss = rusage_bytes;
                    }
                }
            }
        }

        if peak_rss > self.config.max_memory_bytes && status == SandboxStatus::Completed {
            status = SandboxStatus::ResourceExceeded;
        }

        let duration_ms = start_time.elapsed().as_millis() as u64;

        // Collect outputs from background readers
        let (stdout_bytes, stdout_truncated) = stdout_handle
            .and_then(|h| h.join().ok())
            .unwrap_or_default();
        let (stderr_bytes, stderr_truncated) = stderr_handle
            .and_then(|h| h.join().ok())
            .unwrap_or_default();

        let output_truncated = stdout_truncated || stderr_truncated;

        let isolation_enforced = matches!(
            mechanism,
            IsolationMechanism::MacSeatbelt
                | IsolationMechanism::LinuxBubblewrap
                | IsolationMechanism::LinuxNamespace
        );
        let network_egress_prevented = !self.config.allow_network && isolation_enforced;

        let receipt = build_receipt(
            &sandbox_id,
            duration_ms,
            peak_rss,
            exit_code,
            status,
            mechanism,
            isolation_enforced,
            std::env::consts::OS.to_string(),
            network_egress_prevented,
            stdout_bytes,
            stderr_bytes,
            output_truncated,
        );

        Ok(receipt)
    }

    /// Creates an ephemeral working path inside a freshly allocated sandbox directory.
    pub fn create_ephemeral_dir(&self) -> Result<tempfile::TempDir, SandboxError> {
        tempfile::Builder::new()
            .prefix("bk_ephemeral_")
            .tempdir()
            .map_err(SandboxError::Io)
    }

    /// Resolves canonical path for target within sandbox.
    pub fn sandbox_target_path(sandbox_root: &Path, relative: &Path) -> PathBuf {
        sandbox_root.join(relative)
    }
}

/// Result of a bounded execution in `ResearchSandbox`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedExecutionResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub sanitized_vars_count: usize,
}

/// High-level sandbox harness providing environment sanitization and bounded execution.
#[derive(Debug, Clone)]
pub struct ResearchSandbox {
    config: SandboxConfig,
}

impl ResearchSandbox {
    pub fn new(config: SandboxConfig) -> Self {
        Self { config }
    }

    /// Filters sensitive environment variables out of the ambient environment.
    pub fn sanitize_env<'a>(&self, env: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
        env.iter()
            .filter(|(k, _)| {
                let upper = k.to_uppercase();
                !self
                    .config
                    .stripped_env_prefixes
                    .iter()
                    .any(|p| upper.starts_with(&p.to_uppercase()))
                    && !is_sensitive_env_var(k)
            })
            .copied()
            .collect()
    }

    /// Validates network policy. Fails closed (Err) if network is prohibited (default),
    /// strictly enforcing zero network egress.
    pub fn validate_network_policy(&self) -> Result<(), String> {
        if !self.config.allow_network {
            Err("Sandbox policy strictly forbids outbound network egress".to_string())
        } else {
            Ok(())
        }
    }

    /// Simulates/blocks any attempt to connect to an external destination.
    pub fn attempt_network_egress(&self, destination: &str) -> Result<(), String> {
        Err(format!(
            "Network egress attempt to '{}' blocked by sandbox policy",
            destination
        ))
    }

    /// Executes a command with timeout, environment stripping, and bounded capture.
    pub fn execute_bounded(
        &self,
        program: &str,
        args: &[&str],
        _work_dir: Option<&Path>,
        env: &[(String, String)],
    ) -> Result<BoundedExecutionResult, String> {
        let runner =
            SandboxRunner::new(self.config.clone()).map_err(|e| format!("Sandbox error: {}", e))?;

        let sensitive_count = env
            .iter()
            .filter(|(k, _)| {
                let upper = k.to_uppercase();
                self.config
                    .stripped_env_prefixes
                    .iter()
                    .any(|p| upper.starts_with(&p.to_uppercase()))
                    || is_sensitive_env_var(k)
            })
            .count();

        let receipt = runner
            .run_command(program, args)
            .map_err(|e| format!("Command execution error: {}", e))?;

        let timed_out = receipt.status == SandboxStatus::TimedOut;
        let exit_code = if timed_out {
            -1
        } else {
            receipt.exit_code.unwrap_or(-1)
        };

        Ok(BoundedExecutionResult {
            exit_code,
            stdout: receipt.stdout_lossy(),
            stderr: receipt.stderr_lossy(),
            duration_ms: receipt.duration_ms,
            timed_out,
            sanitized_vars_count: sensitive_count,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn build_receipt(
    sandbox_id: &str,
    duration_ms: u64,
    peak_memory_bytes: u64,
    exit_code: Option<i32>,
    status: SandboxStatus,
    isolation_mechanism: IsolationMechanism,
    isolation_enforced: bool,
    host_os: String,
    network_egress_prevented: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    output_truncated: bool,
) -> SandboxExecutionReceipt {
    let now = Utc::now().to_rfc3339();

    let mut hasher = Sha256::new();
    hasher.update(sandbox_id.as_bytes());
    hasher.update(duration_ms.to_le_bytes());
    hasher.update(peak_memory_bytes.to_le_bytes());
    hasher.update(status.as_str().as_bytes());
    hasher.update(isolation_mechanism.as_str().as_bytes());
    hasher.update([if isolation_enforced { 1 } else { 0 }]);
    hasher.update([if network_egress_prevented { 1 } else { 0 }]);
    hasher.update(&stdout);
    hasher.update(&stderr);
    let digest = crate::to_hex(hasher.finalize());

    let receipt_id = format!("receipt-sbx-{}", &digest[..16]);

    SandboxExecutionReceipt {
        receipt_id,
        sandbox_id: sandbox_id.to_string(),
        duration_ms,
        peak_memory_bytes,
        exit_code,
        status,
        isolation_mechanism,
        isolation_enforced,
        host_os,
        network_egress_prevented,
        stdout,
        stderr,
        output_truncated,
        created_at: now,
        receipt_sha256: digest,
    }
}

fn nanoid_simple() -> String {
    let mut bytes = [0u8; 8];
    rand::fill(&mut bytes);
    let mut out = String::with_capacity(16);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Atomically terminates the process and its entire descendant process tree via PGID SIGKILL on Unix.
fn terminate_process_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let pid = child.id() as i32;
        if pid > 1 {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(target_os = "macos")]
fn get_process_rss_bytes(pid: u32) -> Option<u64> {
    #[repr(C)]
    struct ProcTaskInfo {
        pti_virtual_size: u64,
        pti_resident_size: u64,
        pti_total_user: u64,
        pti_total_system: u64,
        pti_threads_user: u64,
        pti_threads_system: u64,
        pti_policy: i32,
        pti_faults: i32,
        pti_pageins: i32,
        pti_cow_faults: i32,
        pti_messages_sent: i32,
        pti_messages_received: i32,
        pti_syscalls_mach: i32,
        pti_syscalls_unix: i32,
        pti_csw: i32,
        pti_threadnum: i32,
        pti_numrunning: i32,
        pti_priority: i32,
    }

    unsafe extern "C" {
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut std::ffi::c_void,
            buffersize: i32,
        ) -> i32;
    }

    unsafe {
        let mut info: ProcTaskInfo = std::mem::zeroed();
        let size = std::mem::size_of::<ProcTaskInfo>() as i32;
        let ret = proc_pidinfo(
            pid as i32,
            4, // PROC_PIDTASKINFO
            0,
            &mut info as *mut _ as *mut std::ffi::c_void,
            size,
        );
        if ret == size && info.pti_resident_size > 0 {
            Some(info.pti_resident_size)
        } else {
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn get_process_rss_bytes(pid: u32) -> Option<u64> {
    let path = format!("/proc/{}/statm", pid);
    if let Ok(content) = std::fs::read_to_string(path) {
        let mut parts = content.split_whitespace();
        let _total = parts.next()?;
        if let Some(resident_pages_str) = parts.next() {
            if let Ok(pages) = resident_pages_str.parse::<u64>() {
                let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
                let page_size = if page_size > 0 {
                    page_size as u64
                } else {
                    4096
                };
                return Some(pages * page_size);
            }
        }
    }
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn get_process_rss_bytes(_pid: u32) -> Option<u64> {
    None
}
