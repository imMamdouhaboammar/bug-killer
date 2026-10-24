use bug_killer::osv::{OsvClient, VersionResolution};
use std::path::Path;

#[test]
fn test_sca_multi_ecosystem_package_discovery() {
    let sca_root = Path::new("tests/fixtures/sca");
    assert!(
        sca_root.exists(),
        "SCA fixtures directory tests/fixtures/sca must exist"
    );

    // 1. NPM Ecosystem
    let npm_pkgs = OsvClient::discover_packages(&sca_root.join("npm"));
    assert!(
        !npm_pkgs.is_empty(),
        "Must discover packages from npm fixtures"
    );
    assert!(
        npm_pkgs.iter().any(|p| p.ecosystem == "npm"),
        "Must find npm ecosystem packages"
    );
    // Verify lockfile exact versions vs package.json range requirements
    let has_exact_npm = npm_pkgs
        .iter()
        .any(|p| p.resolution == VersionResolution::ResolvedExact);
    assert!(
        has_exact_npm,
        "package-lock.json must yield ResolvedExact packages"
    );

    // 2. Composer / PHP Ecosystem
    let composer_pkgs = OsvClient::discover_packages(&sca_root.join("composer"));
    assert!(
        !composer_pkgs.is_empty(),
        "Must discover packages from Composer fixtures"
    );
    assert!(
        composer_pkgs.iter().any(|p| p.ecosystem == "Packagist"),
        "Must find Packagist ecosystem packages"
    );

    // 3. PyPI / Python Ecosystem (requirements.txt & poetry.lock)
    let pypi_pkgs = OsvClient::discover_packages(&sca_root.join("pypi"));
    assert!(
        !pypi_pkgs.is_empty(),
        "Must discover packages from PyPI fixtures"
    );
    assert!(
        pypi_pkgs.iter().any(|p| p.ecosystem == "PyPI"),
        "Must find PyPI ecosystem packages"
    );

    // 4. Cargo / Rust Ecosystem
    let cargo_pkgs = OsvClient::discover_packages(&sca_root.join("cargo"));
    assert!(
        !cargo_pkgs.is_empty(),
        "Must discover packages from Cargo fixtures"
    );
    assert!(
        cargo_pkgs.iter().any(|p| p.ecosystem == "crates.io"),
        "Must find crates.io ecosystem packages"
    );

    // 5. Go Modules Ecosystem
    let go_pkgs = OsvClient::discover_packages(&sca_root.join("gomod"));
    assert!(
        !go_pkgs.is_empty(),
        "Must discover packages from Go fixtures"
    );
    assert!(
        go_pkgs.iter().any(|p| p.ecosystem == "Go"),
        "Must find Go ecosystem packages"
    );

    // 6. NuGet / .NET Ecosystem
    let nuget_pkgs = OsvClient::discover_packages(&sca_root.join("nuget"));
    assert!(
        !nuget_pkgs.is_empty(),
        "Must discover packages from NuGet fixtures"
    );
    assert!(
        nuget_pkgs.iter().any(|p| p.ecosystem == "NuGet"),
        "Must find NuGet ecosystem packages"
    );

    // 7. Ruby / Gemfile Ecosystem
    let ruby_pkgs = OsvClient::discover_packages(&sca_root.join("ruby"));
    assert!(
        !ruby_pkgs.is_empty(),
        "Must discover packages from Ruby fixtures"
    );
    assert!(
        ruby_pkgs.iter().any(|p| p.ecosystem == "RubyGems"),
        "Must find RubyGems ecosystem packages"
    );

    // 8. Maven / Java Ecosystem
    let maven_pkgs = OsvClient::discover_packages(&sca_root.join("maven"));
    assert!(
        !maven_pkgs.is_empty(),
        "Must discover packages from Maven fixtures"
    );
    assert!(
        maven_pkgs.iter().any(|p| p.ecosystem == "Maven"),
        "Must find Maven ecosystem packages"
    );
}

#[test]
fn test_sca_version_resolution_classification() {
    let sca_root = Path::new("tests/fixtures/sca");

    // All packages across the entire fixture corpus
    let all_pkgs = OsvClient::discover_packages(sca_root);
    assert!(
        all_pkgs.len() >= 15,
        "Total discovered packages across all fixtures should be >= 15"
    );

    // Verify that NO package with a range constraint is marked ResolvedExact
    for pkg in &all_pkgs {
        if pkg.resolution == VersionResolution::ResolvedExact {
            assert!(
                !pkg.version.starts_with('^')
                    && !pkg.version.starts_with('~')
                    && !pkg.version.starts_with('>')
                    && !pkg.version.starts_with('<')
                    && !pkg.version.starts_with('*'),
                "Package {} marked ResolvedExact but has range operator: {}",
                pkg.name,
                pkg.version
            );
        } else {
            assert!(
                pkg.declared_requirement.is_some(),
                "Declared requirement packages must preserve declared_requirement string"
            );
        }
    }
}
