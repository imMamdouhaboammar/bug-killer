use crate::cli::DiscloseCommands;
use crate::disclosure;
use crate::engine;
use crate::identity;
use crate::scanner::FleetScanner;
use sha2::{Digest, Sha256};

pub fn handle_disclose(cmd: DiscloseCommands) -> i32 {
    match cmd {
        DiscloseCommands::Draft {
            finding_id,
            path,
            private: _,
            output,
            json,
        } => {
            let report = FleetScanner::scan_directory(&path, false);
            let matching = report
                .findings
                .iter()
                .find(|f| f.id == finding_id || f.cve.as_str() == finding_id);
            let dummy_sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            let packet_res = if let Some(f) = matching {
                let f_v1 =
                    engine::converter::to_normalized_finding(f, "run-cli-disclosure", dummy_sha);
                disclosure::DisclosureDraftBuilder::from_finding(&f_v1)
                    .contact_channel(disclosure::draft::ContactChannel {
                        channel_type: "email".to_string(),
                        contact_target: "security@vendor.local".to_string(),
                        security_policy_url: None,
                    })
                    .safe_reproduction(disclosure::draft::SafeReproduction {
                        test_type: "offline_regression_test".to_string(),
                        harness_code: format!("// Defensive test for {}", f.cve.as_str()),
                        sanitized_input: "defensive_verification_payload".to_string(),
                        expected_behavior: "Safe handling under defensive security policy"
                            .to_string(),
                        observed_behavior: f.description.clone(),
                    })
                    .build()
            } else {
                let f_hash = identity::to_hex(Sha256::digest(finding_id.as_bytes()));
                disclosure::DisclosureDraftBuilder::new()
                    .finding_id(&finding_id)
                    .draft_id(format!("draft-{}", finding_id))
                    .packet_id(format!("packet-{}", &f_hash[..16]))
                    .title(format!("Defensive Vulnerability Report: {}", finding_id))
                    .vulnerability_type("Security Weakness / Vulnerability")
                    .affected_target(disclosure::draft::AffectedTarget {
                        package: "workspace-target".to_string(),
                        commit_range: "HEAD".to_string(),
                        repository: path.display().to_string(),
                        source_snapshot_sha256: dummy_sha.to_string(),
                    })
                    .contact_channel(disclosure::draft::ContactChannel {
                        channel_type: "email".to_string(),
                        contact_target: "security@vendor.local".to_string(),
                        security_policy_url: None,
                    })
                    .safe_reproduction(disclosure::draft::SafeReproduction {
                        test_type: "offline_reproduction".to_string(),
                        harness_code: "// Isolated test harness".to_string(),
                        sanitized_input: "synthetic_input".to_string(),
                        expected_behavior: "Safe operation".to_string(),
                        observed_behavior: "Security invariant violated".to_string(),
                    })
                    .build()
            };

            match packet_res {
                Ok(packet) => {
                    let markdown = packet.to_github_pvr_markdown();
                    if let Some(ref out_path) = output {
                        if let Err(e) = std::fs::write(out_path, &markdown) {
                            eprintln!(
                                "❌ Failed to write disclosure draft to {}: {}",
                                out_path.display(),
                                e
                            );
                            return 1;
                        }
                        println!("✅ Disclosure draft written to: {}", out_path.display());
                    }
                    if json {
                        println!("{}", serde_json::to_string_pretty(&packet).unwrap());
                    } else if output.is_none() {
                        println!("{}", markdown);
                    }
                    0
                }
                Err(e) => {
                    eprintln!("❌ Failed to build disclosure draft: {:?}", e);
                    1
                }
            }
        }
    }
}
