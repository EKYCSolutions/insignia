
use clap::Parser;
use once_cell::sync::Lazy;
use jsonwebtoken::{EncodingKey, DecodingKey};
use tracing_subscriber::{filter, prelude::*};
use webauthn_rs::{WebauthnBuilder, prelude::Url};
use actix_session::{SessionMiddleware, storage::RedisActorSessionStore};
use actix_web::{HttpServer, App, web, cookie::Key, middleware::Logger, http};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, required = true, env = "INSIGNIA_MODE", value_parser = ["admin", "frontend"], help = "server mode to run in")]
    mode: String,

    #[arg(short, long, required = false, env = "INSIGNIA_PORT", default_value = "6969", help = "server port to listen on")]
    port: u16,

    #[arg(short, long, required = false, env = "INSIGNIA_LISTEN_ADDR", default_value = "127.0.0.1", help = "server address to listen on")]
    listen_addr: String,

    #[arg(long, required = false, env = "INSIGNIA_LOG_LEVEL", value_parser = ["info", "debug"], default_value = "info", help = "set logging level")]
    log_level: String,

    #[arg(long, required = false, env = "INSIGNIA_CORS_ENABLED", default_value = "false", help = "whether to enable cors")]
    is_cors_enabled: bool,

    #[arg(long, required = false, env = "INSIGNIA_CORS_ORIGINS", default_value = "http://localhost:5173,http://localhost:8080", value_delimiter = ',', help = "cors origins for the server")]
    cors_origins: Vec<String>,

    #[arg(
        long,
        required = false,
        env = "INSIGNIA_WEBAUTHN_RP_ID",
        default_value = "localhost",
        help = "unique identifier for relying party",
        long_help = "should be domain of your identity website or root of your identity website"
    )]
    rp_id: String,

    #[arg(
        long,
        required = false,
        env = "INSIGNIA_WEBAUTHN_RP_ORIGIN",
        default_value = "http://localhost:5173",
        help = "origin of the replying party",
        long_help = "should be url to your identity website, the domain should match the root of RP id or within subdomain of it"
    )]
    rp_origin: String,

    #[arg(long, required = false, env = "INSIGNIA_DB_CONN_STR", default_value = "postgresql://insignia:supersecurepw@localhost/insignia", help = "postgres database connection string")]
    db_conn_str: String,

    #[arg(long, required = false, env = "INSIGNIA_DRAGONFLY_CONN_STR", default_value = "localhost:6379", help = "dragonflydb connection string")]
    dragonflydb_conn_str: String,
}

static JWT_SECRET: Lazy<(EncodingKey, DecodingKey)> = Lazy::new(|| {
    (
        EncodingKey::from_ed_pem(std::fs::read("./jwt-secret.pem").expect("fail to read jwt-secret.pem").as_slice())
        .expect("fail to read jwt secret key for encoding key"),
        DecodingKey::from_ed_pem(std::fs::read("./jwt-secret.pub").expect("fail to read jwt-secret.pub").as_slice())
        .expect("fail to read jwt secret key for decoding key")
    )
});

fn setup_logger(mode: &str, log_level: filter::LevelFilter) {
    let stdout_log = tracing_subscriber::fmt::Layer::new()
        .pretty();

    let insignia_log_file_appender = tracing_appender::rolling::minutely(
        "./logs", format!("insignia-{}", mode));

    let (insigia_non_blocking_file_appender, _guard) = tracing_appender::non_blocking(insignia_log_file_appender);

    let insignia_file_logger = tracing_subscriber::fmt::layer::<tracing_subscriber::Registry>()
        .with_writer(insigia_non_blocking_file_appender);

    tracing_subscriber::registry()
        .with(
            stdout_log
                .with_filter(log_level)
                .and_then(insignia_file_logger)
                .with_filter(filter::filter_fn(|metadata| {
                    !metadata.target().starts_with("actix") &&
                    !metadata.target().starts_with("sqlx")
                }))
        )
        .init();
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();

    setup_logger(
        &args.mode,
        match args.log_level.as_str() {
            "debug" => filter::LevelFilter::DEBUG,
            _ => filter::LevelFilter::INFO,
        }
    );

    let db_conn = sea_orm::Database::connect(args.db_conn_str)
        .await
        .expect("fail to connect to postgres");

    if &args.mode == "admin" {
        tracing::info!("starting insignia admin server");
        tracing::info!("listening on {}:{}", args.listen_addr, args.port);

        return HttpServer::new(move || {
            let cors_origins = args.cors_origins.clone();

            App::new()
            .app_data(web::Data::new(db_conn.clone()))
            .wrap(Logger::default())
            .wrap(
                actix_cors::Cors::default()
                .allowed_origin_fn(move |origin, _rh| {
                    if args.is_cors_enabled {
                        if let Ok(origin) = origin.to_str() {
                            return cors_origins.contains(&String::from(origin));
                        }

                        return false;
                    }

                    true
                })
                .allowed_methods(vec!["GET", "PUT", "HEAD", "POST", "PATCH", "DELETE", "OPTIONS"])
                .allowed_headers(vec![http::header::AUTHORIZATION,  http::header::ACCEPT, http::header::CONTENT_TYPE])
            )
        })
        .bind((args.listen_addr, args.port))?
        .run()
        .await;
    }

    tracing::info!("starting insignia frontend server");
    tracing::info!("listening on {}:{}", args.listen_addr, args.port);

    HttpServer::new(move || {
        let dragonflydb_conn_str = args.dragonflydb_conn_str.clone();

        let cors_origins = args.cors_origins.clone();

        App::new()
        .app_data(web::Data::new(db_conn.clone()))
        .wrap(Logger::default())
        .wrap(
        actix_cors::Cors::default()
            .allowed_origin_fn(move |origin, _rh| {
                if args.is_cors_enabled {
                    if let Ok(origin) = origin.to_str() {
                        return cors_origins.contains(&String::from(origin));
                    }

                    return false;
                }

                true
            })
            .allowed_methods(vec!["GET", "PUT", "HEAD", "POST", "PATCH", "DELETE", "OPTIONS"])
            .allowed_headers(vec![http::header::AUTHORIZATION,  http::header::ACCEPT, http::header::CONTENT_TYPE])
            .supports_credentials()
        )
        .app_data(web::Data::new(&JWT_SECRET))
        .app_data(web::Data::new(WebauthnBuilder::new(&args.rp_id, &Url::parse(&args.rp_origin).expect("invalid webauthn rp origin"))
                .expect("invalid webauthn config")
                .build()
                .expect("invalid webauthn config")))
        .wrap(
            SessionMiddleware::new(
                RedisActorSessionStore::new(dragonflydb_conn_str),
                Key::from(std::fs::read("./session.key").expect("fail to read session-key").as_slice())
            )
        )
        .service(web::scope("/users").configure(routes::users::routes))
    })
    .bind((args.listen_addr, args.port))?
    .run()
    .await
}

