fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../../proto/omni_messaging.proto");
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["../../proto/omni_messaging.proto"], &["../../proto"])?;
    Ok(())
}
