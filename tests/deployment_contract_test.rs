use std::fs;

#[test]
fn docker_build_includes_proto_and_native_go_requirements() {
    let dockerfile = fs::read_to_string("Dockerfile").unwrap();
    assert!(
        dockerfile.contains("COPY proto/"),
        "Inspector build.rs requires protobuf sources"
    );
    assert!(
        dockerfile.contains("protobuf-compiler"),
        "Inspector requires protoc during build"
    );
    assert!(
        dockerfile.contains("libpcap-dev"),
        "Go orchestrator packet scanner requires libpcap headers"
    );
    assert!(
        dockerfile.contains("CGO_ENABLED=1"),
        "Packet capture integration requires CGO"
    );
    assert!(
        dockerfile.contains("mkdir -p /var/bug-killer"),
        "Named shared volume needs a writable image mount point"
    );
}

#[test]
fn compose_services_use_existing_image_stage_and_own_binary_entrypoints() {
    let compose = fs::read_to_string("docker-compose.yml").unwrap();
    assert!(!compose.contains("target: orchestrator"));
    assert!(!compose.contains("target: inspector"));
    assert_eq!(compose.matches("target: final").count(), 2);
    assert!(compose.contains("entrypoint: [\"/app/bug-killer-orchestrator\"]"));
    assert!(compose.contains("entrypoint: [\"/app/bug-killer-inspector\"]"));
    assert!(
        compose.contains("DOCKER_GID"),
        "Docker inspection must explicitly configure socket group access"
    );
}
