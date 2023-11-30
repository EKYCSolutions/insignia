
fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all("./grpc")?;

    tonic_build::configure()
        .build_server(true)
        .out_dir("./grpc")
        .compile(
            &["./protos/server/v0/user_validation.proto"],
            &["./protos"]
        )?;

    Ok(())
}
