use crate::deepsec::prompt::assemble_prompt;
use crate::deepsec::scanner::detect_tech;
use crate::deepsec::storage::StorageManager;
use crate::deepsec::types::*;
use chrono::Utc;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct ProcessOptions {
    pub concurrency: usize,
    pub batch_size: usize,
    pub limit: Option<usize>,
    pub filter: Option<String>,
    pub max_cost_usd: Option<f64>,
    pub model: String,
    pub agent_type: String,
}

impl Default for ProcessOptions {
    fn default() -> Self {
        Self {
            concurrency: 1,
            batch_size: 5,
            limit: None,
            filter: None,
            max_cost_usd: None,
            model: "claude-opus-4-8".to_string(),
            agent_type: "claude".to_string(),
        }
    }
}

pub trait DeepSecAIClient {
    fn investigate(&self, prompt: &str) -> Result<String, String>;
}

pub struct MockAIClient;

impl DeepSecAIClient for MockAIClient {
    fn investigate(&self, prompt: &str) -> Result<String, String> {
        let mut findings = Vec::new();

        for section in prompt.split("### File: ").skip(1) {
            if section.trim().is_empty() {
                continue;
            }
            let file_path = section.lines().next().unwrap_or("").trim();
            if file_path.is_empty() {
                continue;
            }

            if section.contains("sql-injection") {
                findings.push(serde_json::json!({
                    "filePath": file_path,
                    "severity": "CRITICAL",
                    "vulnSlug": "sql-injection",
                    "title": "Raw string concatenation in SQL query execution",
                    "description": "User controlled input is concatenated directly into SQL command without parameterized escaping.",
                    "lineNumbers": [14, 15],
                    "recommendation": "Use parameterized queries or ORM query builder.",
                    "confidence": "high"
                }));
            }

            if section.contains("rce") {
                findings.push(serde_json::json!({
                    "filePath": file_path,
                    "severity": "CRITICAL",
                    "vulnSlug": "rce",
                    "title": "Command injection via unescaped subprocess call",
                    "description": "Input passed directly to shell=True subprocess execution.",
                    "lineNumbers": [22],
                    "recommendation": "Pass argument list without shell=True.",
                    "confidence": "high"
                }));
            }

            if section.contains("secrets-exposure") {
                findings.push(serde_json::json!({
                    "filePath": file_path,
                    "severity": "HIGH",
                    "vulnSlug": "secrets-exposure",
                    "title": "Hardcoded production API secret key in repository",
                    "description": "Plaintext secret token committed directly to repository source.",
                    "lineNumbers": [5],
                    "recommendation": "Rotate key and move to secure secret management vault.",
                    "confidence": "high"
                }));
            }
        }

        let resp = serde_json::json!({ "findings": findings });
        Ok(resp.to_string())
    }
}

pub struct HttpAIClient {
    pub endpoint_url: String,
    pub api_key: String,
    pub model: String,
}

impl DeepSecAIClient for HttpAIClient {
    fn investigate(&self, prompt: &str) -> Result<String, String> {
        let payload = serde_json::json!({
            "model": self.model,
            "messages": [
                { "role": "system", "content": "You are a security auditor. Respond only with valid JSON." },
                { "role": "user", "content": prompt }
            ],
            "response_format": { "type": "json_object" }
        });

        let resp = ureq::post(&self.endpoint_url)
            .header("Authorization", &format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .send_json(&payload)
            .map_err(|e| format!("HTTP request error: {}", e))?;

        let mut reader = resp.into_body().into_reader();
        let body: Value =
            serde_json::from_reader(&mut reader).map_err(|e| format!("JSON parse error: {}", e))?;
        if let Some(content) = body["choices"][0]["message"]["content"].as_str() {
            Ok(content.to_string())
        } else {
            Err("Missing content in choices[0].message".to_string())
        }
    }
}

pub fn process_repository(
    root_path: &Path,
    project_id: &str,
    storage: &StorageManager,
    ai_client: &dyn DeepSecAIClient,
    options: &ProcessOptions,
) -> Result<RunStats, String> {
    if options.max_cost_usd.is_some() {
        return Err("Cost budget enforcement requires verified provider usage telemetry, which is not available".to_string());
    }
    storage
        .ensure_project(project_id, &root_path.to_string_lossy())
        .map_err(|e| e.to_string())?;

    let run_id = format!(
        "proc-{}-{}",
        Utc::now().format("%Y%m%d%H%M%S"),
        crate::identity::to_hex(rand::random::<[u8; 2]>())
    );

    let mut run_meta = RunMeta::new(
        run_id.clone(),
        project_id.to_string(),
        root_path.to_string_lossy().to_string(),
        "process".to_string(),
    );
    // An acquired file lock must point to an on-disk live owner. Otherwise
    // another worker could immediately reclaim it as an unknown run.
    storage
        .write_run_meta(&run_meta)
        .map_err(|e| e.to_string())?;

    let all_records = storage.load_all_file_records(project_id);
    let mut pending_records: Vec<FileRecord> = all_records
        .into_iter()
        .filter(|r| {
            r.status == FileStatus::Pending
                || (r.status == FileStatus::Processing && storage.is_reclaimable_lock(r))
        })
        .filter(|r| {
            if let Some(filter) = &options.filter {
                r.file_path.starts_with(filter)
            } else {
                true
            }
        })
        .collect();

    // Sort by number of candidate matches (descending), then by file path for deterministic ordering
    pending_records.sort_by(|a, b| {
        b.candidates
            .len()
            .cmp(&a.candidates.len())
            .then_with(|| a.file_path.cmp(&b.file_path))
    });

    if let Some(limit) = options.limit {
        pending_records.truncate(limit);
    }

    if pending_records.is_empty() {
        run_meta.phase = "done".to_string();
        run_meta.completed_at = Some(Utc::now().to_rfc3339());
        storage
            .write_run_meta(&run_meta)
            .map_err(|e| e.to_string())?;
        return Ok(run_meta.stats);
    }

    let tech_tags = detect_tech(root_path);
    let info_md_path = storage.project_dir(project_id).join("INFO.md");
    let info_md = fs::read_to_string(&info_md_path).ok();

    let chunks: Vec<Vec<FileRecord>> = pending_records
        .chunks(options.batch_size.max(1))
        .map(|c| c.to_vec())
        .collect();

    let mut total_files_processed = 0;
    let mut total_findings_count = 0;
    let total_cost_usd = 0.0;

    let start_all = Instant::now();

    for chunk in chunks {
        let mut locked_chunk = Vec::new();
        for mut rec in chunk {
            if storage.acquire_file_lock(&mut rec, &run_id) {
                locked_chunk.push(rec);
            }
        }

        if locked_chunk.is_empty() {
            continue;
        }

        let mut files_overview = String::new();
        for rec in &locked_chunk {
            files_overview.push_str(&format!("\n### File: {}\n", rec.file_path));
            for cand in &rec.candidates {
                files_overview.push_str(&format!(
                    "- Flagged Category: {} ({})\n  Lines: {:?}\n  Snippet:\n```\n{}\n```\n",
                    cand.vuln_slug, cand.matched_pattern, cand.line_numbers, cand.snippet
                ));
            }
        }

        let prompt = assemble_prompt(&tech_tags, info_md.as_deref(), &files_overview);

        let start_batch = Instant::now();
        let ai_result = ai_client.investigate(&prompt);
        let duration_ms = start_batch.elapsed().as_millis() as u64;

        match ai_result {
            Ok(json_text) => {
                let parsed = serde_json::from_str::<Value>(&json_text).ok();
                let findings_array = parsed
                    .as_ref()
                    .and_then(|value| value.get("findings"))
                    .and_then(Value::as_array);

                if findings_array.is_none() {
                    for mut rec in locked_chunk {
                        rec.status = FileStatus::Error;
                        rec.locked_by_run_id = None;
                        rec.locked_at = None;
                        storage.write_file_record(&rec).map_err(|e| e.to_string())?;
                    }
                    return Err(
                        "AI Investigation returned invalid or missing findings JSON".to_string()
                    );
                }

                let mut findings_by_file: std::collections::HashMap<String, Vec<Finding>> =
                    std::collections::HashMap::new();

                if let Some(arr) = findings_array {
                    for item in arr {
                        let rel_path = item["filePath"].as_str().unwrap_or("").to_string();
                        let sev_str = item["severity"].as_str().unwrap_or("MEDIUM");
                        let severity = match sev_str {
                            "CRITICAL" => Severity::Critical,
                            "HIGH" => Severity::High,
                            "HIGH_BUG" => Severity::HighBug,
                            "BUG" => Severity::Bug,
                            "LOW" => Severity::Low,
                            _ => Severity::Medium,
                        };

                        let vuln_slug = item["vulnSlug"].as_str().unwrap_or("other").to_string();
                        let title = item["title"]
                            .as_str()
                            .unwrap_or("Security issue")
                            .to_string();
                        let description = item["description"].as_str().unwrap_or("").to_string();
                        let recommendation =
                            item["recommendation"].as_str().unwrap_or("").to_string();
                        let confidence = match item["confidence"].as_str().unwrap_or("medium") {
                            "high" => Confidence::High,
                            "low" => Confidence::Low,
                            _ => Confidence::Medium,
                        };

                        let line_numbers: Vec<usize> = item["lineNumbers"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_u64().map(|n| n as usize))
                                    .collect()
                            })
                            .unwrap_or_else(|| vec![1]);

                        let finding_id = compute_finding_id(project_id, &rel_path, &title);

                        let finding = Finding {
                            finding_id,
                            severity,
                            vuln_slug,
                            title,
                            description,
                            line_numbers,
                            recommendation,
                            confidence,
                            triage: None,
                            revalidation: None,
                            produced_by_run_id: Some(run_id.clone()),
                        };

                        findings_by_file.entry(rel_path).or_default().push(finding);
                    }
                }

                if let Some(unrecognized_path) = findings_by_file
                    .keys()
                    .find(|path| !locked_chunk.iter().any(|rec| rec.file_path == **path))
                {
                    let message = format!(
                        "AI returned a finding for an unscanned file: {}",
                        unrecognized_path
                    );
                    for mut rec in locked_chunk {
                        rec.status = FileStatus::Error;
                        rec.locked_by_run_id = None;
                        rec.locked_at = None;
                        storage.write_file_record(&rec).map_err(|e| e.to_string())?;
                    }
                    return Err(message);
                }

                for mut rec in locked_chunk {
                    let file_findings = findings_by_file.remove(&rec.file_path).unwrap_or_default();

                    let finding_count = file_findings.len();
                    total_findings_count += finding_count;

                    // Deduplicate against existing findings
                    let mut existing_ids: HashSet<String> =
                        rec.findings.iter().map(|f| f.finding_id.clone()).collect();
                    for f in file_findings {
                        if !existing_ids.contains(&f.finding_id) {
                            existing_ids.insert(f.finding_id.clone());
                            rec.findings.push(f);
                        }
                    }

                    rec.analysis_history.push(AnalysisEntry {
                        run_id: run_id.clone(),
                        investigated_at: Utc::now().to_rfc3339(),
                        duration_ms,
                        agent_type: options.agent_type.clone(),
                        model: options.model.clone(),
                        finding_count,
                        cost_usd: None,
                        usage: None,
                        phase: Some("process".to_string()),
                    });

                    rec.status = FileStatus::Analyzed;
                    rec.locked_by_run_id = None;
                    rec.locked_at = None;
                    storage.write_file_record(&rec).map_err(|e| e.to_string())?;
                    total_files_processed += 1;
                }
            }
            Err(e) => {
                for mut rec in locked_chunk {
                    rec.status = FileStatus::Error;
                    rec.locked_by_run_id = None;
                    rec.locked_at = None;
                    let _ = storage.write_file_record(&rec);
                }
                return Err(format!("AI Investigation failed: {}", e));
            }
        }

        if let Some(max_cost) = options.max_cost_usd {
            if total_cost_usd >= max_cost {
                break;
            }
        }
    }

    run_meta.phase = "done".to_string();
    run_meta.completed_at = Some(Utc::now().to_rfc3339());
    run_meta.stats.files_processed = total_files_processed;
    run_meta.stats.findings_count = total_findings_count;
    run_meta.stats.total_cost_usd = total_cost_usd;
    run_meta.stats.total_duration_ms = start_all.elapsed().as_millis() as u64;
    storage
        .write_run_meta(&run_meta)
        .map_err(|e| e.to_string())?;

    Ok(run_meta.stats)
}
