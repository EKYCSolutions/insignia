
fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all("./grpc")?;

    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .out_dir("./grpc")
        .file_descriptor_set_path("./grpc/insigniaoss-integration-v0-descriptor.bin")
        .compile(
            &[
                "./protos/type/user.proto",
                "./protos/service/v0/integration.proto",
            ],
            &["./protos"]
        )?;

    Ok(())
}
