use super::{DetectorResult, ScanContext, SecurityDetector};
use crate::scanner::FleetScanner;
use crate::types::*;
use chrono::Utc;

pub struct AgentSkillDetector;

impl SecurityDetector for AgentSkillDetector {
    fn id(&self) -> &'static str {
        "agent-skill"
    }

    fn name(&self) -> &'static str {
        "AI Agent Skill & MCP Configuration Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-LLM-001",
            "BK-AI-LLM-003",
            "BK-AI-LLM-004",
            "BK-AI-LLM-008",
            "BK-AI-LLM-014",
            "BK-AI-LLM-017",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &["markdown", "json", "python", "javascript", "typescript"]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[
            TargetKind::AgentSkillManifest,
            TargetKind::McpServerConfig,
            TargetKind::GenericConfigFile,
            TargetKind::GenericSourceFile,
            TargetKind::NodeSourceFile,
        ]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let agent_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| {
                f.detector_id == "agent-security-scanner"
                    || f.detector_id == "agent-skill-scanner"
                    || f.detector_id == "agent-mcp-scanner"
                    || f.target_kind == TargetKind::AgentSkillManifest
                    || f.target_kind == TargetKind::McpServerConfig
            })
            .cloned()
            .collect();

        let rules_run = self
            .supported_rule_ids()
            .iter()
            .map(|s| s.to_string())
            .collect();
        let receipt = CoverageReceipt {
            scanner_id: self.id().to_string(),
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            target_id: ctx.root.display().to_string(),
            status: CoverageStatus::Complete,
            items_examined: report.total_files_scanned as u64,
            skipped_reasons: Vec::new(),
            errors: Vec::new(),
            completed_at: Utc::now().to_rfc3339(),
        };

        DetectorResult {
            findings: agent_findings,
            receipt,
            rules_run,
        }
    }
}

pub struct DynamicRulesDetector;

impl SecurityDetector for DynamicRulesDetector {
    fn id(&self) -> &'static str {
        "dynamic-rules"
    }

    fn name(&self) -> &'static str {
        "Pluggable Dynamic Vulnerability Rules Engine"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "CVE-2024-5480",
            "CVE-2023-44487",
            "SEC-001-EXPOSED-ENV-SECRETS",
            "SEC-002-PYTHON-UNSAFE-EVAL",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &[
            "generic",
            "python",
            "nginx",
            "javascript",
            "typescript",
            "go",
            "php",
        ]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[TargetKind::GenericSourceFile, TargetKind::NginxConfig]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let rules = crate::rules::RuleEngine::load_rules(None, &ctx.root);
        let mut rules_run: Vec<String> = self
            .supported_rule_ids()
            .iter()
            .map(|s| s.to_string())
            .collect();
        for r in &rules {
            if !rules_run.contains(&r.id) {
                rules_run.push(r.id.clone());
            }
        }

        let report = FleetScanner::scan_directory_with_rules(&ctx.root, false, &rules);
        let dynamic_findings: Vec<Finding> = report
            .findings
            .into_iter()
            .filter(|f| f.detector_id == "dynamic-rules")
            .collect();

        let receipt = CoverageReceipt {
            scanner_id: self.id().to_string(),
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            target_id: ctx.root.display().to_string(),
            status: CoverageStatus::Complete,
            items_examined: report.total_files_scanned as u64,
            skipped_reasons: Vec::new(),
            errors: Vec::new(),
            completed_at: Utc::now().to_rfc3339(),
        };

        DetectorResult {
            findings: dynamic_findings,
            receipt,
            rules_run,
        }
    }
}

pub struct AiAgentExtDetector;

impl SecurityDetector for AiAgentExtDetector {
    fn id(&self) -> &'static str {
        "ai-agent-ext"
    }

    fn name(&self) -> &'static str {
        "LLM, Autonomous Agent & AI Assistant Flaws Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-LLM-001",
            "BK-AI-LLM-002",
            "BK-AI-LLM-003",
            "BK-AI-LLM-005",
            "BK-AI-LLM-006",
            "BK-AI-LLM-007",
            "BK-AI-LLM-008",
            "BK-AI-LLM-009",
            "BK-AI-LLM-010",
            "BK-AI-LLM-011",
            "BK-AI-LLM-012",
            "BK-AI-LLM-013",
            "BK-AI-LLM-014",
            "BK-AI-LLM-015",
            "BK-AI-LLM-016",
            "BK-AI-LLM-018",
            "BK-AI-LLM-020",
            "BK-AI-LLM-022",
            "BK-AI-AIC-001",
            "BK-AI-AIC-002",
            "BK-AI-AIC-003",
            "BK-AI-AIC-005",
            "BK-AI-AIC-006",
            "BK-AI-AIC-007",
            "BK-AI-AIC-008",
            "BK-AI-AIC-009",
            "BK-AI-AIC-010",
            "BK-AI-AIC-011",
            "BK-AI-AIC-012",
            "BK-AI-AIC-013",
            "BK-AI-AIC-014",
            "BK-AI-AIC-015",
            "BK-AI-AIC-016",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &[
            "javascript",
            "typescript",
            "python",
            "go",
            "rust",
            "generic",
        ]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[
            TargetKind::GenericSourceFile,
            TargetKind::NodeSourceFile,
            TargetKind::AgentSkillManifest,
        ]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let agent_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "ai-agent-ext")
            .cloned()
            .collect();

        let rules_run = self
            .supported_rule_ids()
            .iter()
            .map(|s| s.to_string())
            .collect();
        let receipt = CoverageReceipt {
            scanner_id: self.id().to_string(),
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            target_id: ctx.root.display().to_string(),
            status: CoverageStatus::Complete,
            items_examined: report.total_files_scanned as u64,
            skipped_reasons: Vec::new(),
            errors: Vec::new(),
            completed_at: Utc::now().to_rfc3339(),
        };

        DetectorResult {
            findings: agent_findings,
            receipt,
            rules_run,
        }
    }
}
