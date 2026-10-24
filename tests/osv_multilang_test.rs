use std::fs;
use tempfile::tempdir;
use bug_killer::osv::OsvClient;
use bug_killer::types::*;

#[test]
fn test_multilang_package_discovery() {
    let dir = tempdir().expect("Failed to create tempdir");
    let root = dir.path();

    // 1. go.mod
    let go_mod = root.join("go.mod");
    let go_content = r#"module example.com/test
go 1.22
require (
    golang.org/x/crypto v0.14.0 // indirect
    github.com/gin-gonic/gin v1.9.1
)
"#;
    fs::write(&go_mod, go_content).unwrap();

    // 2. pom.xml (Maven)
    let pom_xml = root.join("pom.xml");
    let pom_content = r#"<project>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
    </dependencies>
</project>"#;
    fs::write(&pom_xml, pom_content).unwrap();

    // 3. app.csproj (.NET NuGet)
    let csproj = root.join("app.csproj");
    let csproj_content = r#"<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
  </ItemGroup>
</Project>"#;
    fs::write(&csproj, csproj_content).unwrap();

    // 4. Gemfile.lock (Ruby)
    let gemfile = root.join("Gemfile.lock");
    let gem_content = r#"GEM
  remote: https://rubygems.org/
  specs:
    actionpack (5.2.0)
      actionview (= 5.2.0)
"#;
    fs::write(&gemfile, gem_content).unwrap();

    // 5. poetry.lock (Python)
    let poetry = root.join("poetry.lock");
    let poetry_content = r#"[[package]]
name = "requests"
version = "2.20.0"
description = "Python HTTP for Humans."
"#;
    fs::write(&poetry, poetry_content).unwrap();

    // Discover packages across all 5 manifests
    let packages = OsvClient::discover_packages(root);

    assert!(packages.iter().any(|p| p.name == "golang.org/x/crypto" && p.version == "v0.14.0" && p.ecosystem == "Go" && p.target_kind == TargetKind::GoModManifest));
    assert!(packages.iter().any(|p| p.name == "github.com/gin-gonic/gin" && p.version == "v1.9.1" && p.ecosystem == "Go"));
    assert!(packages.iter().any(|p| p.name == "org.apache.logging.log4j:log4j-core" && p.version == "2.14.1" && p.ecosystem == "Maven" && p.target_kind == TargetKind::JavaPomManifest));
    assert!(packages.iter().any(|p| p.name == "Newtonsoft.Json" && p.version == "12.0.1" && p.ecosystem == "NuGet" && p.target_kind == TargetKind::DotnetCsprojManifest));
    assert!(packages.iter().any(|p| p.name == "actionpack" && p.version == "5.2.0" && p.ecosystem == "RubyGems" && p.target_kind == TargetKind::RubyGemfileManifest));
    assert!(packages.iter().any(|p| p.name == "requests" && p.version == "2.20.0" && p.ecosystem == "PyPI" && p.target_kind == TargetKind::PythonPoetryManifest));
}
