use crate::healer::backup::BackupManager;
use crate::types::*;
use std::fs;
use std::path::Path;

pub struct VirtualPatcher;

impl VirtualPatcher {
    pub const NGINX_PATCH_HEADER: &'static str =
        "# --- BEGIN BUG KILLER VIRTUAL PATCH (CVE-2026-111497: Node2Shell Brotli Mitigation) ---";
    pub const NGINX_PATCH_FOOTER: &'static str = "# --- END BUG KILLER VIRTUAL PATCH ---";

    pub fn plan_nginx_patch(path: &Path) -> Option<PatchAction> {
        let content = fs::read_to_string(path).ok()?;
        if content.contains(Self::NGINX_PATCH_HEADER)
            || content.contains("BEGIN AEGIS VIRTUAL PATCH")
        {
            return None; // Already patched (Idempotency)
        }

        let sha256 = BackupManager::compute_sha256(path).ok()?;

        let patch_block = format!(
            "\n    {}\n    # Drop or reject request bodies with Brotli encoding before hitting vulnerable Node.js runtimes\n    if ($http_content_encoding ~* \"br\") {{\n        return 415 \"Unsupported Media Type: Brotli request body blocked by Bug Killer (CVE-2026-111497)\";\n    }}\n    {}\n",
            Self::NGINX_PATCH_HEADER,
            Self::NGINX_PATCH_FOOTER
        );

        // Inject inside server { ... } or before proxy_pass
        let mut modified = String::new();
        let mut injected = false;

        for line in content.lines() {
            if !injected
                && (line.trim().starts_with("location /") || line.trim().starts_with("proxy_pass"))
            {
                modified.push_str(&patch_block);
                injected = true;
            }
            modified.push_str(line);
            modified.push('\n');
        }

        if !injected {
            // Append right before closing brace if server block
            if let Some(last_brace_idx) = content.rfind('}') {
                let mut c = content[..last_brace_idx].to_string();
                c.push_str(&patch_block);
                c.push_str(&content[last_brace_idx..]);
                modified = c;
            } else {
                modified.push_str(&patch_block);
            }
        }

        Some(PatchAction {
            action_type: PatchActionType::NginxVirtualPatch,
            target_file: path.to_path_buf(),
            original_checksum: sha256,
            diff_description:
                "Inject Nginx HTTP 415 guard against Brotli compressed request bodies".into(),
            replacement_content: modified,
        })
    }
}
