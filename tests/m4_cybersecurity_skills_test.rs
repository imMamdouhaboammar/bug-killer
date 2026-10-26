use bug_killer::deep::{CybersecuritySkillsRegistry, ToolCapabilityBroker};
use std::path::PathBuf;

#[test]
fn test_embedded_cybersecurity_skills_catalog_integrity() {
    let registry = CybersecuritySkillsRegistry::default_embedded();
    assert_eq!(
        registry.len(),
        818,
        "Embedded registry must index exactly 818 cybersecurity skills"
    );
    assert!(!registry.is_empty());

    let metrics = registry.metrics();
    assert_eq!(metrics.total_skills, 818);
    assert!(metrics.subdomains_count >= 30);
    assert!(metrics.mitre_techniques_count >= 100);
    assert!(metrics.nist_controls_count >= 30);

    // Verify defensive classes are well-populated
    assert!(metrics.defensive_classes.contains_key("DETECTION"));
    assert!(metrics.defensive_classes.contains_key("HARDENING"));
    assert!(metrics.defensive_classes.contains_key("VIRTUAL_PATCHING"));
    assert!(metrics.defensive_classes.contains_key("FORENSICS_TRIAGE"));
    assert!(metrics.defensive_classes.contains_key("AUDIT_COMPLIANCE"));
}

#[test]
fn test_skill_retrieval_by_id_and_name() {
    let registry = CybersecuritySkillsRegistry::default_embedded();

    let skill = registry
        .get("analyzing-ethereum-smart-contract-vulnerabilities")
        .expect("Skill must be found by ID");

    assert_eq!(
        skill.id,
        "analyzing-ethereum-smart-contract-vulnerabilities"
    );
    assert_eq!(skill.subdomain, "blockchain-security");
    assert!(skill.tags.contains(&"solidity".to_string()));
    assert!(skill.tags.contains(&"ethereum".to_string()));
    assert!(skill.has_mitre_technique("T1190"));
    assert!(skill.has_mitre_technique("T1059"));
    assert!(skill.has_nist_control("PR.DS-01"));
}

#[test]
fn test_subdomain_indexing_and_filtering() {
    let registry = CybersecuritySkillsRegistry::default_embedded();

    let cloud_skills = registry.find_by_subdomain("cloud-security");
    assert!(
        cloud_skills.len() >= 50,
        "Cloud security subdomain must have at least 50 skills"
    );
    for skill in &cloud_skills {
        assert_eq!(skill.subdomain, "cloud-security");
    }

    let web_skills = registry.find_by_subdomain("web-application-security");
    assert!(
        web_skills.len() >= 30,
        "Web application security subdomain must have at least 30 skills"
    );
    for skill in &web_skills {
        assert_eq!(skill.subdomain, "web-application-security");
    }
}

#[test]
fn test_framework_indexing_mitre_and_nist() {
    let registry = CybersecuritySkillsRegistry::default_embedded();

    // MITRE T1190 (Exploit Public-Facing Application)
    let t1190_skills = registry.find_by_mitre("T1190");
    assert!(
        !t1190_skills.is_empty(),
        "Must find skills mapped to MITRE T1190"
    );
    for skill in &t1190_skills {
        assert!(skill.has_mitre_technique("T1190"));
    }

    // NIST PR.DS-01 (Data-at-rest protection)
    let pr_ds_skills = registry.find_by_nist("PR.DS-01");
    assert!(
        !pr_ds_skills.is_empty(),
        "Must find skills mapped to NIST PR.DS-01"
    );
    for skill in &pr_ds_skills {
        assert!(skill.has_nist_control("PR.DS-01"));
    }
}

#[test]
fn test_search_and_keyword_indexing() {
    let registry = CybersecuritySkillsRegistry::default_embedded();

    let k8s_results = registry.search("kubernetes");
    assert!(
        k8s_results.len() >= 10,
        "Searching for 'kubernetes' must return at least 10 skills"
    );

    let sql_results = registry.search("sql injection");
    assert!(
        !sql_results.is_empty(),
        "Searching for 'sql injection' must return matching skills"
    );

    let memory_results = registry.search("buffer overflow");
    assert!(
        !memory_results.is_empty(),
        "Searching for 'buffer overflow' must return matching skills"
    );
}

#[test]
fn test_cve_skill_recommendations() {
    let registry = CybersecuritySkillsRegistry::default_embedded();

    // PHP2Shell (CVE-2026-109618): Memory corruption and heap exploitation
    let php_recs = registry.recommend_for_cve("CVE-2026-109618");
    assert!(
        !php_recs.is_empty(),
        "Must recommend skills for PHP2Shell CVE-2026-109618"
    );
    assert!(
        php_recs
            .iter()
            .any(|s| s.matches_query("memory") || s.matches_query("heap") || s.matches_query("overflow")),
        "Recommendations for CVE-2026-109618 must include memory/heap vulnerability skills"
    );

    // Node2Shell (CVE-2026-111497): Brotli memory desync
    let node_recs = registry.recommend_for_cve("CVE-2026-111497");
    assert!(
        !node_recs.is_empty(),
        "Must recommend skills for Node2Shell CVE-2026-111497"
    );
}

#[test]
fn test_mission_goal_recommendations() {
    let registry = CybersecuritySkillsRegistry::default_embedded();

    let prevention_skills = registry.recommend_for_goal("prevention");
    assert!(
        !prevention_skills.is_empty(),
        "Must return prevention skills"
    );

    let known_skills = registry.recommend_for_goal("known");
    assert!(!known_skills.is_empty(), "Must return known skills");

    let research_skills = registry.recommend_for_goal("research");
    assert!(
        !research_skills.is_empty(),
        "Must return research skills"
    );
}

#[test]
fn test_tool_broker_skill_association() {
    let broker = ToolCapabilityBroker::new();

    // Sibling Semgrep
    let semgrep_skills = broker.recommend_skills_for_tool("semgrep");
    assert!(
        !semgrep_skills.is_empty(),
        "Tool broker must recommend skills for semgrep"
    );

    // Sibling CodeQL
    let codeql_skills = broker.recommend_skills_for_tool("codeql");
    assert!(
        !codeql_skills.is_empty(),
        "Tool broker must recommend skills for codeql"
    );

    // Sibling Joern
    let joern_skills = broker.recommend_skills_for_tool("joern");
    assert!(
        !joern_skills.is_empty(),
        "Tool broker must recommend skills for joern"
    );

    // Sibling Trivy
    let trivy_skills = broker.recommend_skills_for_tool("trivy");
    assert!(
        !trivy_skills.is_empty(),
        "Tool broker must recommend skills for trivy"
    );
}

#[test]
fn test_disk_catalog_matches_embedded_catalog() {
    let catalog_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("rules/cybersecurity_skills/catalog.json");

    assert!(
        catalog_path.is_file(),
        "rules/cybersecurity_skills/catalog.json must exist"
    );

    let disk_registry = CybersecuritySkillsRegistry::from_file(&catalog_path)
        .expect("Must parse disk catalog.json");

    assert_eq!(
        disk_registry.len(),
        818,
        "Disk catalog must have 818 skills"
    );

    let embedded = CybersecuritySkillsRegistry::default_embedded();
    assert_eq!(disk_registry.len(), embedded.len());

    // Spot check a specific skill between both
    let disk_skill = disk_registry
        .get("analyzing-active-directory-acl-abuse")
        .expect("Skill in disk catalog");
    let embedded_skill = embedded
        .get("analyzing-active-directory-acl-abuse")
        .expect("Skill in embedded catalog");

    assert_eq!(disk_skill.id, embedded_skill.id);
    assert_eq!(disk_skill.subdomain, embedded_skill.subdomain);
    assert_eq!(disk_skill.defensive_class, embedded_skill.defensive_class);
}
