use bug_killer::catalog::{EvidenceKind, RuleLifecycle, SecurityCatalog};
use std::collections::HashSet;

#[test]
fn test_catalog_contains_exactly_373_unique_rules() {
    let catalog = SecurityCatalog::global();
    assert_eq!(catalog.count(), 373, "Catalog must have exactly 373 rules");

    let mut seen_ids = HashSet::new();
    let mut seen_short_ids = HashSet::new();

    for rule in catalog.all_rules() {
        assert!(
            rule.rule_id.starts_with("BK-AI-"),
            "Rule ID {} must start with BK-AI-",
            rule.rule_id
        );
        assert!(
            seen_ids.insert(rule.rule_id.clone()),
            "Duplicate rule ID detected: {}",
            rule.rule_id
        );
        assert!(
            seen_short_ids.insert(rule.short_id.clone()),
            "Duplicate short ID detected: {}",
            rule.short_id
        );
        assert!(!rule.description.trim().is_empty());
        assert!(!rule.category.trim().is_empty());
        assert!(rule.category_number >= 1 && rule.category_number <= 27);
    }
}

#[test]
fn test_catalog_contains_all_27_categories() {
    let catalog = SecurityCatalog::global();
    assert_eq!(
        catalog.category_count(),
        27,
        "Catalog must contain all 27 categories"
    );

    let categories = catalog.categories();
    for num in 1..=27 {
        assert!(
            categories.iter().any(|c| c.number == num),
            "Category number {} missing from categories list",
            num
        );
        let rules_in_cat = catalog.rules_by_category(num);
        assert!(
            !rules_in_cat.is_empty(),
            "Category {} must contain at least one rule",
            num
        );
    }
}

#[test]
fn test_catalog_rule_lookups() {
    let catalog = SecurityCatalog::global();

    // Full ID lookup
    let sql_inj = catalog
        .get_rule("BK-AI-INJ-001")
        .expect("BK-AI-INJ-001 must exist");
    assert_eq!(sql_inj.short_id, "INJ-001");
    assert_eq!(sql_inj.cwe.as_deref(), Some("CWE-89"));
    assert_eq!(sql_inj.status, RuleLifecycle::SupportedStatic);

    // Lookup with/without prefix
    let sql_inj_alt = catalog.get_rule("INJ-001").expect("Lookup without prefix");
    assert_eq!(sql_inj_alt.rule_id, "BK-AI-INJ-001");

    // Short ID lookup
    let by_short = catalog
        .get_rule_by_short_id("QAT-012")
        .expect("QAT-012 must exist");
    assert_eq!(by_short.rule_id, "BK-AI-QAT-012");
    assert_eq!(by_short.category_number, 27);
}

#[test]
fn test_unsupported_rules_honestly_classified() {
    let catalog = SecurityCatalog::global();
    let supported = catalog.supported_rules();
    let unsupported = catalog.unsupported_rules();

    assert!(
        !supported.is_empty(),
        "Must have some operational supported rules"
    );
    assert!(
        !unsupported.is_empty(),
        "Must have unoperational rules classified honestly"
    );
    assert_eq!(supported.len() + unsupported.len(), 373);

    for rule in &unsupported {
        assert!(
            !rule.status.is_supported(),
            "Unsupported rule {} must not have supported status",
            rule.rule_id
        );
        assert!(
            rule.status == RuleLifecycle::Cataloged
                || rule.status == RuleLifecycle::ReviewRequired
                || rule.status == RuleLifecycle::Experimental
                || rule.status == RuleLifecycle::Deprecated
        );
    }
}

#[test]
fn test_evidence_kind_parsing() {
    let catalog = SecurityCatalog::global();
    let sql_inj = catalog.get_rule("BK-AI-INJ-001").unwrap();
    assert!(sql_inj.required_evidence.contains(&EvidenceKind::Flow));
    assert!(sql_inj.required_evidence.contains(&EvidenceKind::Test));

    let osv_rule = catalog.get_rule("BK-AI-SCA-001").unwrap();
    assert!(osv_rule.required_evidence.contains(&EvidenceKind::Sca));
}
