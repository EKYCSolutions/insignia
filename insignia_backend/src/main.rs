
use actix::Actor;
use clap::Parser;
use once_cell::sync::Lazy;
use common::SESSION_COOKIE_SETTING;
use jsonwebtoken::{EncodingKey, DecodingKey};
use tracing_subscriber::{filter, prelude::*};
use webauthn_rs::{WebauthnBuilder, prelude::Url};
use actix_session::{SessionMiddleware, storage::RedisActorSessionStore};
use actix_web::{HttpServer, App, web, cookie::Key, middleware::Logger, http};

static JWT_SECRET: Lazy<(EncodingKey, DecodingKey)> = Lazy::new(|| {
    (
        EncodingKey::from_ed_pem(std::fs::read("./jwt.pem").expect("fail to read jwt.pem").as_slice())
        .expect("fail to read jwt secret key for encoding key"),
        DecodingKey::from_ed_pem(std::fs::read("./jwt.pub").expect("fail to read jwt.pub").as_slice())
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
    let args = common::Args::parse();

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

    let sms_otp_service = services::sms_otp::CoreSMSOtp::new_twilio(&args.twilio_account_sid, &args.twilio_auth_token, &args.twilio_verify_sid);

    let sms_otp_service = sms_otp_service.start();

    tracing::info!("cors enabled - {}", args.is_cors_enabled);
    tracing::info!("cors origins - {:?}", args.cors_origins);

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
        let (same_site, is_cookie_secure, _, _) = *SESSION_COOKIE_SETTING;

        let dragonflydb_conn_str = args.dragonflydb_conn_str.clone();

        let cors_origins = args.cors_origins.clone();

        tracing::info!("webauthn rp id - {}", args.rp_id);
        tracing::info!("webauthn rp origin - {}", args.rp_origin);

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
        .app_data(web::Data::new(sms_otp_service.to_owned()))
        .app_data(web::Data::new(&JWT_SECRET))
        .app_data(web::Data::new(WebauthnBuilder::new(&args.rp_id, &Url::parse(&args.rp_origin).expect("invalid webauthn rp origin"))
                .expect("invalid webauthn config")
                .build()
                .expect("invalid webauthn config")))
        .wrap(
            SessionMiddleware::builder(
                RedisActorSessionStore::new(dragonflydb_conn_str),
                Key::from(std::fs::read("./session.key").expect("fail to read session-key").as_slice())
            )
            .cookie_same_site(same_site)
            .cookie_secure(is_cookie_secure)
            .cookie_http_only(is_cookie_secure)
            .build()
        )
        .service(web::scope("/users").configure(routes::users::routes))
        .service(web::scope("/authn").configure(routes::authn::routes))
    })
    .bind((args.listen_addr, args.port))?
    .run()
    .await
}

