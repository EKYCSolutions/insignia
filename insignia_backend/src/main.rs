
use actix::Actor;
use clap::Parser;
use once_cell::sync::Lazy;
use opentelemetry_otlp::WithExportConfig;
use jsonwebtoken::{EncodingKey, DecodingKey};
use tracing_subscriber::{filter, prelude::*};
use webauthn_rs::{WebauthnBuilder, prelude::Url};
use actix_web::{HttpServer, App, web, cookie::Key, http};
use actix_session::{SessionMiddleware, storage::RedisActorSessionStore};

use common::SESSION_COOKIE_SETTING;
use services::dragonfly::DragonflyService;

static JWT_SECRET: Lazy<(EncodingKey, DecodingKey)> = Lazy::new(|| {
    (
        EncodingKey::from_ed_pem(std::fs::read("./etc/jwt.pem").expect("fail to read jwt.pem").as_slice())
        .expect("fail to read jwt secret key for encoding key"),
        DecodingKey::from_ed_pem(std::fs::read("./etc/jwt.pub").expect("fail to read jwt.pub").as_slice())
        .expect("fail to read jwt secret key for decoding key")
    )
});

fn setup_logger(log_level: filter::LevelFilter) {
    let stdout_log = tracing_subscriber::fmt::Layer::new()
        .pretty();

    let otlp_exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(
            std::env::var("OTEL_ENDPOINT")
                .or::<String>(Ok("http://localhost:4317".to_string()))
                .unwrap()
        );

    let otel_trace_config = opentelemetry_sdk::trace::config()
        .with_resource(opentelemetry_sdk::Resource::new(vec![
            opentelemetry::KeyValue::new(
                "service.name",
                std::env::var("OTEL_SERVICE_NAME")
                    .or::<String>(Ok("insignia".to_string()))
                    .unwrap()
            )
        ]));

    let otel_tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(otlp_exporter)
        .with_trace_config(otel_trace_config)
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .unwrap();

    let tracer = tracing_opentelemetry::layer()
        .with_tracer(otel_tracer);

    tracing_subscriber::registry()
        .with(tracer)
        .with(
            stdout_log
                .with_filter(log_level)
                .and_then(filter::filter_fn(|metadata| {
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
        match args.log_level.as_str() {
            "debug" => filter::LevelFilter::DEBUG,
            _ => filter::LevelFilter::INFO,
        }
    );

    let db_conn = sea_orm::Database::connect(args.db_conn_str)
        .await
        .expect("fail to connect to postgres");

    let dragonfly_db_conn_str = &args.dragonflydb_conn_str;

    let dragonfly_actor_addr = DragonflyService::start(DragonflyService {
        client: redis::Client::open(format!("redis://{dragonfly_db_conn_str}")).expect("fail to connect to dragonfly"),
    });

    let sms_otp_service = match args.sms_otp_provider.as_str() {
        "twilio" => services::sms_otp::CoreSMSOtp::new_twilio(
            &args.twilio_account_sid.expect("twilio account sid not set"),
            &args.twilio_auth_token.expect("twilio auth token not set"),
            &args.twilio_verify_sid.expect("twilio verify sid not set")
        ),
        "infobip" => services::sms_otp::CoreSMSOtp::new_infobip(
            &args.infobip_base_url.expect("infobip base url not set"),
            &args.infobip_api_key.expect("infobip api key not set"),
            &args.infobip_twofa_app_id.expect("infobip twofa app id not set"),
            &args.infobip_twofa_message_template_id.expect("infobip twofa message template id not set"),
            dragonfly_actor_addr.clone()
        ),
        "mock" => services::sms_otp::CoreSMSOtp::new_mock(),
        _ => panic!("unsupported sms otp provider"),
    };

    let sms_otp_service = sms_otp_service.start();

    tracing::info!("cors enabled - {}", args.is_cors_enabled);
    tracing::info!("cors origins - {:?}", args.cors_origins);

    if &args.mode == "admin" {
        tracing::info!("starting insignia admin server");
        tracing::info!("listening on {}:{}", args.listen_addr, args.port);

        return HttpServer::new(move || {
            let cors_origins = args.cors_origins.clone();

            App::new()
            .app_data(web::Data::new(dragonfly_actor_addr.clone()))
            .app_data(web::Data::new(db_conn.clone()))
            .wrap(tracing_actix_web::TracingLogger::default())
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
            .service(web::scope("/healthz").configure(routes::system::routes))
            .service(web::scope("/users").configure(routes::users::admin_routes))
            .service(web::scope("/setting").configure(routes::setting::admin_routes))
            .service(web::scope("/configs/oauth").configure(routes::oauth::admin_routes))
            .service(web::scope("/configs/well-knowns").configure(routes::well_known_config::admin_routes))
            .service(web::scope("/configs/webauthn-allow-origins").configure(routes::config::admin_routes))
        })
        .bind((args.listen_addr, args.port))?
        .run()
        .await;
    }

    tracing::info!("starting insignia frontend server");
    tracing::info!("listening on {}:{}", args.listen_addr, args.port);

    let webauthn_allow_origins = services::config::Query::list_webauthn_allow_origin(&db_conn)
        .await
        .expect("fail to list webauthn allow origins");

    HttpServer::new(move || {
        let (same_site, is_cookie_secure, _, _) = *SESSION_COOKIE_SETTING;

        let dragonflydb_conn_str = args.dragonflydb_conn_str.clone();

        let cors_origins = args.cors_origins.clone();

        tracing::info!("webauthn rp id - {}", args.rp_id);
        tracing::info!("webauthn rp origin - {}", args.rp_origin);

        let webauthn_rp_origin = Url::parse(&args.rp_origin).expect("invalid webauthn rp origin");

        let mut webauthn = WebauthnBuilder::new(&args.rp_id, &webauthn_rp_origin)
            .expect("invalid webauthn config");

        for origin in &webauthn_allow_origins {
            let url = Url::parse(origin.origin.as_str()).expect("fail to parse webauthn allow origin");

            webauthn = webauthn.append_allowed_origin(&url);
        }

        App::new()
        .app_data(web::Data::new(dragonfly_actor_addr.clone()))
        .app_data(web::Data::new(db_conn.clone()))
        .wrap(tracing_actix_web::TracingLogger::default())
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
        .app_data(web::Data::new(webauthn.build().expect("fail to build webauthn instance")))
        .wrap(
            SessionMiddleware::builder(
                RedisActorSessionStore::new(dragonflydb_conn_str),
                Key::from(std::fs::read("./etc/session.key").expect("fail to read session-key").as_slice())
            )
            .cookie_same_site(same_site)
            .cookie_secure(is_cookie_secure)
            .build()
        )
        .service(web::scope("/users").configure(routes::users::routes))
        .service(web::scope("/authn").configure(routes::authn::routes))
        .service(web::scope("/oauth").configure(routes::oauth::routes))
        .service(web::scope("/healthz").configure(routes::system::routes))
        .service(web::scope("/.well-known").configure(routes::well_known_config::routes))
    })
    .bind((args.listen_addr, args.port))?
    .run()
    .await
}

