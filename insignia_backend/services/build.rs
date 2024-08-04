fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"));

    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .file_descriptor_set_path(out_dir.join("insignia_integration_service_descriptor.bin"))
        .compile(
            &[
                "../protos/insigniaoss/type/user.proto",
                "../protos/insigniaoss/service/v0/integration.proto",
            ],
            &["../protos"],
        )?;

    Ok(())
}
