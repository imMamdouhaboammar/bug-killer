use crate::healer::backup::BackupManager;
use crate::types::*;
use std::fs;
use std::path::Path;

pub struct SourcePatcher;

impl SourcePatcher {
    pub const GUARD_COMMENT: &'static str =
        "// [BUG-KILLER-GUARD] Brotli Request Body Protection (CVE-2026-111497)";

    /// Injects an Express / Connect middleware guard before body parsing routes in an entrypoint file (like `index.js`, `app.js`, `server.ts`).
    pub fn plan_express_guard_patch(path: &Path) -> Option<PatchAction> {
        let content = fs::read_to_string(path).ok()?;
        if content.contains(Self::GUARD_COMMENT) || content.contains("// [AEGIS-GUARD]") {
            return None; // Idempotent
        }

        let sha256 = BackupManager::compute_sha256(path).ok()?;

        let guard_code = format!(
            r#"
{}
if (typeof app !== 'undefined' && app.use) {{
  app.use((req, res, next) => {{
    const encoding = (req.headers['content-encoding'] || '').toLowerCase();
    if (encoding.includes('br')) {{
      return res.status(415).json({{
        error: 'Unsupported Media Type',
        message: 'Brotli-compressed request bodies rejected by Bug Killer (CVE-2026-111497 mitigation)'
      }});
    }}
    next();
  }});
}}
"#,
            Self::GUARD_COMMENT
        );

        // Inject right after app = express() or near top
        let mut modified = String::new();
        let mut injected = false;

        for line in content.lines() {
            modified.push_str(line);
            modified.push('\n');
            if !injected
                && (line.contains("const app = express()")
                    || line.contains("let app = express()")
                    || line.contains("var app = express()"))
            {
                modified.push_str(&guard_code);
                injected = true;
            }
        }

        if !injected {
            return None;
        }

        Some(PatchAction {
            action_type: PatchActionType::NodeMiddlewareGuard,
            target_file: path.to_path_buf(),
            original_checksum: sha256,
            diff_description:
                "Inject Express middleware guard rejecting Brotli-compressed request bodies".into(),
            replacement_content: modified,
        })
    }
}
