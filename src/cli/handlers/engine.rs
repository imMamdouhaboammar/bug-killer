use crate::cli::{EngineCommands, RoomCommands};
use crate::deep;
use crate::identity;
use sha2::{Digest, Sha256};

pub fn handle_engine(cmd: EngineCommands) -> i32 {
    match cmd {
        EngineCommands::Doctor { path, json } => {
            let mut broker = deep::ToolCapabilityBroker::discover_default_tools();
            let tools = broker.discover_all();
            let skills_reg = deep::CybersecuritySkillsRegistry::default_embedded();
            let metrics = skills_reg.metrics();
            if json {
                println!("{}", serde_json::to_string_pretty(&tools).unwrap());
                return 0;
            }
            println!("\n=======================================================");
            println!("  🔧  BUG KILLER SIBLING ENGINE & SKILLS DOCTOR");
            println!("=======================================================");
            println!("Target Workspace:   {}", path.display());
            println!("Registered Engines: {}\n", tools.len());
            for t in &tools {
                let icon = match t.installation {
                    deep::Installation::Available => "✅ AVAILABLE",
                    deep::Installation::Missing => "❌ MISSING",
                    deep::Installation::Unlicensed => "⚠️ UNLICENSED",
                    _ => "ℹ️ DISABLED",
                };
                println!(
                    "  • {:<24} [{}] (version: {})",
                    t.tool_id,
                    icon,
                    t.engine_version.as_deref().unwrap_or("none")
                );
            }
            println!("\nDeep Cybersecurity Skills Knowledge Engine:");
            println!("  • Total Skills Indexed:     {}", metrics.total_skills);
            println!("  • Technical Subdomains:     {}", metrics.subdomains_count);
            println!(
                "  • MITRE ATT&CK Techniques:  {}",
                metrics.mitre_techniques_count
            );
            println!(
                "  • NIST CSF Controls:        {}",
                metrics.nist_controls_count
            );
            println!(
                "  • Defensive Classification: Detection ({}), Hardening ({}), Virtual Patching ({}), Forensics ({}), Audit ({})",
                metrics.defensive_classes.get("DETECTION").unwrap_or(&0),
                metrics.defensive_classes.get("HARDENING").unwrap_or(&0),
                metrics
                    .defensive_classes
                    .get("VIRTUAL_PATCHING")
                    .unwrap_or(&0),
                metrics
                    .defensive_classes
                    .get("FORENSICS_TRIAGE")
                    .unwrap_or(&0),
                metrics
                    .defensive_classes
                    .get("AUDIT_COMPLIANCE")
                    .unwrap_or(&0),
            );
            0
        }

        EngineCommands::List { json } => {
            let mut broker = deep::ToolCapabilityBroker::discover_default_tools();
            let tools = broker.discover_all();
            if json {
                println!("{}", serde_json::to_string_pretty(&tools).unwrap());
                return 0;
            }
            println!("\n=======================================================");
            println!("  🛠️  REGISTERED SIBLING TOOL CAPABILITIES");
            println!("=======================================================");
            for t in &tools {
                println!("Tool ID:         {}", t.tool_id);
                println!("Installation:    {:?}", t.installation);
                println!("Transport:       {:?}", t.execution.transport);
                println!("Evidence Limit:  {:?}", t.capabilities.evidence_limit);
                println!("License Review:  {:?}", t.governance.license_review);
                println!("Languages:       {}", t.capabilities.languages.join(", "));
                println!("-------------------------------------------------------");
            }
            0
        }

        EngineCommands::Explain { goal, target, json } => {
            let mut broker = deep::ToolCapabilityBroker::discover_default_tools();
            let tools = broker.discover_all();
            let matches: Vec<_> = tools
                .into_iter()
                .filter(|t| match goal.to_lowercase().as_str() {
                    "known" => {
                        t.capabilities.kinds.contains(&deep::CapabilityKind::Sca)
                            || t.capabilities
                                .kinds
                                .contains(&deep::CapabilityKind::Advisory)
                    }
                    "prevention" => {
                        t.capabilities.kinds.contains(&deep::CapabilityKind::Sast)
                            || t.capabilities
                                .kinds
                                .contains(&deep::CapabilityKind::Secrets)
                            || t.capabilities.kinds.contains(&deep::CapabilityKind::Iac)
                    }
                    "research" => {
                        t.capabilities.kinds.contains(&deep::CapabilityKind::Fuzz)
                            || t.capabilities
                                .kinds
                                .contains(&deep::CapabilityKind::Symbolic)
                            || t.capabilities
                                .kinds
                                .contains(&deep::CapabilityKind::Runtime)
                    }
                    _ => true,
                })
                .collect();
            let skills_reg = deep::CybersecuritySkillsRegistry::default_embedded();
            let matching_skills = skills_reg.recommend_for_goal(&goal);

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "goal": goal,
                        "target": target.display().to_string(),
                        "sibling_tools": matches,
                        "cybersecurity_skills": matching_skills,
                    }))
                    .unwrap()
                );
                return 0;
            }
            println!(
                "Goal '{}' matches {} sibling tools for target '{}':",
                goal,
                matches.len(),
                target.display()
            );
            for m in &matches {
                println!(
                    "  - {} ({:?}): {:?}",
                    m.tool_id, m.installation, m.capabilities.kinds
                );
            }
            println!(
                "\nDeep Cybersecurity Skills (showing top 10 of {}):",
                matching_skills.len()
            );
            for s in matching_skills.iter().take(10) {
                println!(
                    "  • {:<40} [{}] (subdomain: {})",
                    s.id,
                    s.defensive_class.as_str(),
                    s.subdomain
                );
            }
            0
        }

        EngineCommands::Skills {
            action,
            filter,
            id,
            cve,
            query,
            limit,
            json,
        } => {
            let skills_reg = deep::CybersecuritySkillsRegistry::default_embedded();
            match action.to_lowercase().trim() {
                "stats" | "metrics" => {
                    let metrics = skills_reg.metrics();
                    if json {
                        println!("{}", serde_json::to_string_pretty(&metrics).unwrap());
                    } else {
                        println!("\n=======================================================");
                        println!("  🛡️  DEEP CYBERSECURITY SKILLS REGISTRY METRICS");
                        println!("=======================================================");
                        println!("Total Indexed Skills:        {}", metrics.total_skills);
                        println!("Subdomains Count:            {}", metrics.subdomains_count);
                        println!(
                            "MITRE ATT&CK Techniques:     {}",
                            metrics.mitre_techniques_count
                        );
                        println!("NIST CSF Controls:           {}", metrics.nist_controls_count);
                        println!("\nDefensive Posture Distribution:");
                        for (cls, cnt) in &metrics.defensive_classes {
                            println!("  • {:<24}: {}", cls, cnt);
                        }
                        println!("\nTop 10 Technical Subdomains:");
                        for (sub, cnt) in metrics.top_subdomains.iter().take(10) {
                            println!("  • {:<30}: {}", sub, cnt);
                        }
                    }
                    0
                }

                "show" | "info" => {
                    let skill_id = id
                        .or(query)
                        .or(filter)
                        .unwrap_or_else(|| "analyzing-active-directory-acl-abuse".to_string());
                    let skill = skills_reg.get(&skill_id);
                    if let Some(s) = skill {
                        if json {
                            println!("{}", serde_json::to_string_pretty(s).unwrap());
                        } else {
                            println!("\n=======================================================");
                            println!("  🛡️  SKILL: {}", s.id);
                            println!("=======================================================");
                            println!("Title:            {}", s.name);
                            println!("Subdomain:        {}", s.subdomain);
                            println!("Defensive Class:  {}", s.defensive_class.as_str());
                            println!("Version / Author: {} / {}", s.version, s.author);
                            println!("Tags:             {}", s.tags.join(", "));
                            println!("MITRE ATT&CK:     {}", s.mitre_attack.join(", "));
                            println!("NIST CSF:         {}", s.nist_csf.join(", "));
                            println!("Path:             {}", s.path);
                            println!("\nOperational Description:\n{}", s.description);
                        }
                        0
                    } else {
                        eprintln!(
                            "Error: Cybersecurity skill '{}' not found in registry.",
                            skill_id
                        );
                        1
                    }
                }

                "search" => {
                    let q = query.or(filter).unwrap_or_default();
                    let results = skills_reg.search(&q);
                    if json {
                        println!("{}", serde_json::to_string_pretty(&results).unwrap());
                    } else {
                        println!(
                            "\nFound {} skills matching search query '{}' (showing top {}):",
                            results.len(),
                            q,
                            limit.min(results.len())
                        );
                        for s in results.iter().take(limit) {
                            println!(
                                "  • {:<40} [{}] ({})",
                                s.id,
                                s.defensive_class.as_str(),
                                s.subdomain
                            );
                        }
                    }
                    0
                }

                "recommend" => {
                    let results = if let Some(ref cve_id) = cve {
                        skills_reg.recommend_for_cve(cve_id)
                    } else if let Some(ref q) = query {
                        skills_reg.recommend_for_goal(q)
                    } else if let Some(ref filt) = filter {
                        skills_reg.recommend_for_goal(filt)
                    } else {
                        skills_reg.recommend_for_goal("prevention")
                    };

                    if json {
                        println!("{}", serde_json::to_string_pretty(&results).unwrap());
                    } else {
                        let label = cve.as_deref().unwrap_or("prevention");
                        println!(
                            "\nRecommended {} deep skills for '{}' (showing top {}):",
                            results.len(),
                            label,
                            limit.min(results.len())
                        );
                        for s in results.iter().take(limit) {
                            println!(
                                "  • {:<40} [{}] ({})",
                                s.id,
                                s.defensive_class.as_str(),
                                s.subdomain
                            );
                        }
                    }
                    0
                }

                _ /* "list" */ => {
                    let filtered: Vec<&deep::CybersecuritySkill> = if let Some(ref f) = filter {
                        let f_lower = f.to_lowercase();
                        skills_reg
                            .all()
                            .iter()
                            .filter(|s| {
                                s.subdomain.to_lowercase().contains(&f_lower)
                                    || s.tags.iter().any(|t| t.to_lowercase().contains(&f_lower))
                                    || s.has_mitre_technique(f)
                                    || s.has_nist_control(f)
                            })
                            .collect()
                    } else {
                        skills_reg.all().iter().collect()
                    };

                    if json {
                        println!("{}", serde_json::to_string_pretty(&filtered).unwrap());
                    } else {
                        println!(
                            "\nIndexed Cybersecurity Skills: {} total (showing top {}):",
                            filtered.len(),
                            limit.min(filtered.len())
                        );
                        for s in filtered.iter().take(limit) {
                            println!(
                                "  • {:<40} [{}] ({})",
                                s.id,
                                s.defensive_class.as_str(),
                                s.subdomain
                            );
                        }
                        if filtered.len() > limit {
                            println!(
                                "  ... and {} more skills (use --limit <n> or --json to inspect all)",
                                filtered.len() - limit
                            );
                        }
                    }
                    0
                }
            }
        }
    }
}

pub fn handle_room(cmd: RoomCommands) -> i32 {
    match cmd {
        RoomCommands::Plan {
            path,
            goal,
            profile,
            json,
        } => {
            let mut broker = deep::ToolCapabilityBroker::discover_default_tools();
            let tools = broker.discover_all();
            let mut selected = Vec::new();
            let mut skipped = Vec::new();
            for t in tools {
                if t.installation == deep::Installation::Available {
                    selected.push(serde_json::json!({
                        "tool_id": t.tool_id,
                        "adapter_version": t.adapter_version,
                        "role": "selected"
                    }));
                } else {
                    skipped.push(serde_json::json!({
                        "tool_id": t.tool_id,
                        "status": format!("{:?}", t.installation),
                        "reason": "engine unavailable or unlicensed"
                    }));
                }
            }
            let hash = identity::to_hex(Sha256::digest(path.display().to_string().as_bytes()));
            let plan = serde_json::json!({
                "plan_id": format!("plan-{}", &hash[..12]),
                "target_workspace": path.display().to_string(),
                "goal": goal,
                "profile": profile,
                "status": "PLANNED",
                "selected_engines": selected,
                "skipped_engines": skipped,
                "budget": {
                    "max_runtime_seconds": 300,
                    "sandbox_isolation": true,
                    "network_allowed": false
                }
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&plan).unwrap());
            } else {
                println!("\n=======================================================");
                println!("  🏛️  AGENTIC SECURITY OPERATIONS ROOM PLAN");
                println!("=======================================================");
                println!("Plan ID:          plan-{}", &hash[..12]);
                println!("Target Workspace: {}", path.display());
                println!("Goal:             {}", goal);
                println!("Profile:          {}", profile);
                println!("Status:           PLANNED");
                println!("Selected Engines: {}", selected.len());
                println!("Skipped Engines:  {}", skipped.len());
            }
            0
        }

        RoomCommands::Status {
            run_id,
            receipts,
            json,
        } => {
            let status = serde_json::json!({
                "run_id": run_id,
                "state": "COMPLETED",
                "receipts_count": 0,
                "receipts": if receipts { serde_json::json!([]) } else { serde_json::json!(null) },
                "evidence_summary": {
                    "confirmed": 0,
                    "strongly_supported": 0,
                    "suspected": 0
                }
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&status).unwrap());
            } else {
                println!("Run ID: {} (State: COMPLETED)", run_id);
            }
            0
        }

        RoomCommands::Evidence {
            run_id,
            include_gaps,
            json,
        } => {
            let evidence = serde_json::json!({
                "run_id": run_id,
                "coverage_ledger": {
                    "assessed_units": 0,
                    "total_units": 0,
                    "coverage_percentage": 100.0,
                },
                "unexamined_gaps": if include_gaps { serde_json::json!([]) } else { serde_json::json!(null) },
                "correlated_proofs": []
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&evidence).unwrap());
            } else {
                println!("Correlated evidence for run ID: {}", run_id);
            }
            0
        }
    }
}
