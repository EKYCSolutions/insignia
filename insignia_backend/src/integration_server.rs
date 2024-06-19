
use clap::Parser;
use tonic::transport::Server;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(long, required = false, env = "INSIGNIA_INTEGRATION_GRPC_PORT", default_value = "26969", help = "integration grpc service port")]
    pub port: u16,

    #[arg(long, required = false, env = "INSIGNIA_DB_CONN_STR", default_value = "postgresql://insignia:supersecurepw@localhost/insignia", help = "postgres database connection string")]
    pub db_conn_str: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let address = format!("0.0.0.0:{}", args.port)
        .parse()?;

    let db_conn = sea_orm::Database::connect(args.db_conn_str)
        .await?;

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();

    health_reporter
        .set_serving::<services::integration::IntegrationServiceServer<services::integration::IntegrationService>>()
        .await;

    let integration_service = services::integration::IntegrationService{
        db_conn: db_conn.clone(),
        jwt_decoding_key: jsonwebtoken::DecodingKey::from_ed_pem(std::fs::read("./jwt.pub").expect("fail to read jwt.pub").as_slice())
            .expect("fail to read jwt secret key for decoding key"),
        jwt_encoding_key: jsonwebtoken::EncodingKey::from_ed_pem(std::fs::read("./jwt.pem").expect("fail to read jwt.pem").as_slice())
            .expect("fail to read jwt secret key for encoding key"),
    };

    let reflection_server = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(services::integration::INSIGINAOSS_INTEGRATION_V0_DESCRIPTOR)
        .build()?;

    Server::builder()
        .add_service(health_service)
        .add_service(services::integration::IntegrationServiceServer::new(integration_service))
        .add_service(reflection_server)
        .serve(address)
        .await?;

    Ok(())
}
