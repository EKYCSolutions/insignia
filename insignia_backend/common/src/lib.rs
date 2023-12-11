use std::{env, ops::Add};

use clap::Parser;
use once_cell::sync::Lazy;
use sea_orm::prelude::Uuid;
use jsonwebtoken::EncodingKey;
use cookie::time::OffsetDateTime;
use chrono::{DateTime, Utc, Duration, Days};
use actix_web::{http::header::HeaderMap, HttpRequest, cookie::Cookie};

use models::users;

pub static OAUTH_ISSUER_URL: Lazy<String> = Lazy::new(|| {
    std::env::var("INSIGNIA_OAUTH_ISSUER_URL")
        .expect("fail to read INSIGNIA_OAUTH_ISSUER_URL env var")
});

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum JwtType {
    Login,
    Refresh,
    OauthAccess,
    OauthRefresh,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct JwtClaims {
    pub id: String,
    pub iat: usize,
    pub nbf: usize,
    pub exp: usize,
    pub aud: Vec<String>,
    pub iss: String,
    pub sub: Uuid,
    pub typ: JwtType,
    pub ctx: Option<String>,
    pub scope: Vec<String>,
}

pub static FRONTEND_URL: Lazy<String> = Lazy::new(|| {
    env::var("INSIGNIA_FRONTEND_URL").expect("fail to read INSIGNIA_FRONTEND_URL from env var")
});

pub static IS_DEV_MODE: Lazy<bool> = Lazy::new(|| {
    env::var("INSIGNIA_DEV_MODE").expect("fail to read INSIGNIA_DEV_MODE from env var") == "true"
});

pub static SESSION_COOKIE_SETTING: Lazy<(actix_web::cookie::SameSite, bool, &str, &str)> = Lazy::new(|| {
    if *IS_DEV_MODE {
        (actix_web::cookie::SameSite::None, true, "Refresh", "Fgp")
    } else {
        (actix_web::cookie::SameSite::Strict, true, "__Host-Refresh", "__Host-Fpg")
    }
});

pub fn build_login_session<'a>(
    user: &'a users::Model,
    jwt_secret: &'a EncodingKey,
    req: &'a HttpRequest,
) -> (String, Cookie<'a>, Cookie<'a>) {
    let now = Utc::now();

    let access_expiry = now.add(Duration::minutes(16));

    let refresh_expiry = now.add(Days::new(8));

    let jwt_id = nanoid::nanoid!(32);

    let fgp = nanoid::nanoid!(32);

    let token_context = build_token_context(user, &req.headers(), &fgp, &now, &access_expiry);

    let (same_site, is_cookie_secure, refresh_cookie_name, fgp_cookie_name) = *SESSION_COOKIE_SETTING;

    let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
            &JwtClaims{
                id: jwt_id,
                sub: user.id,
                iat: now.timestamp() as usize,
                nbf: now.timestamp() as usize,
                exp: access_expiry.timestamp() as usize,
                typ: JwtType::Login,
                aud: vec![FRONTEND_URL.clone()],
                iss: FRONTEND_URL.clone(),
                ctx: Some(token_context.clone()),
                scope: vec![],
            },
            jwt_secret
        ).expect("fail to create jwt token");

    let refresh_token = Cookie::build(
            refresh_cookie_name,
            jsonwebtoken::encode(
                &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
                &JwtClaims{
                    id: nanoid::nanoid!(32),
                    sub: user.id,
                    iat: now.timestamp() as usize,
                    nbf: now.timestamp() as usize,
                    exp: refresh_expiry.timestamp() as usize,
                    typ: JwtType::Refresh,
                    aud: vec![FRONTEND_URL.clone()],
                    iss: FRONTEND_URL.clone(),
                    ctx: Some(token_context),
                    scope: vec![],
                },
                jwt_secret
            ).expect("fail to create jwt token")
        )
        .path("/")
        .expires(OffsetDateTime::from_unix_timestamp(refresh_expiry.timestamp()).unwrap())
        .same_site(same_site)
        .http_only(true)
        .secure(is_cookie_secure)
        .finish();

    let fgp = Cookie::build(
            fgp_cookie_name,
            fgp,
        )
        .path("/")
        .expires(OffsetDateTime::from_unix_timestamp(refresh_expiry.timestamp()).unwrap())
        .same_site(same_site)
        .http_only(true)
        .secure(is_cookie_secure)
        .finish();

    (token, refresh_token, fgp)
}

pub fn build_token_context(
    user: &users::Model,
    headers: &HeaderMap,
    fgp: &str,
    t_iat: &DateTime<Utc>,
    t_exp: &DateTime<Utc>
) -> String {
    let user_agent = headers.get("User-Agent").map_or("abcdefgh", |v| v.to_str().unwrap());

    let random_num = t_iat.timestamp() + t_exp.timestamp();

    blake3::Hasher::new()
    .update(fgp.as_bytes())
    .update(user_agent.as_bytes())
    .update(random_num.to_string().as_bytes())
    .update(user.session_data.clone().as_bytes())
    .finalize()
    .to_string()
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(long, required = false, env = "INSIGNIA_DEV_MODE", default_value = "false", help = "insignia development mode, turn off some security")]
    pub is_dev: bool,

    #[arg(short, long, required = true, env = "INSIGNIA_MODE", value_parser = ["admin", "frontend"], help = "server mode to run in")]
    pub mode: String,

    #[arg(short, long, required = false, env = "INSIGNIA_PORT", default_value = "6969", help = "server port to listen on")]
    pub port: u16,

    #[arg(short, long, required = false, env = "INSIGNIA_LISTEN_ADDR", default_value = "127.0.0.1", help = "server address to listen on")]
    pub listen_addr: String,

    #[arg(long, required = false, env = "INSIGNIA_FRONTEND_URL", default_value = "http://127.0.0.1:6969", help = "frontend url to set as issuer and audience as first party")]
    pub frontend_url: String,

    #[arg(long, required = false, env = "INSIGNIA_JWT_AUDIENCES", default_value = "http://127.0.0.1:6969,http://127.0.0.1:4000", help = "token audiences for first party")]
    pub jwt_audiences: String,

    #[arg(long, required = false, env = "INSIGNIA_LOG_LEVEL", value_parser = ["info", "debug"], default_value = "info", help = "set logging level")]
    pub log_level: String,

    #[arg(long, required = false, env = "INSIGNIA_CORS_ENABLED", default_value = "false", help = "whether to enable cors")]
    pub is_cors_enabled: bool,

    #[arg(long, required = false, env = "INSIGNIA_CORS_ORIGINS", default_value = "http://localhost:5173,http://localhost:8080", value_delimiter = ',', help = "cors origins for the server")]
    pub cors_origins: Vec<String>,

    #[arg(
        long,
        required = false,
        env = "INSIGNIA_WEBAUTHN_RP_ID",
        default_value = "localhost",
        help = "unique identifier for relying party",
        long_help = "should be domain of your identity website or root of your identity website"
    )]
    pub rp_id: String,

    #[arg(
        long,
        required = false,
        env = "INSIGNIA_WEBAUTHN_RP_ORIGIN",
        default_value = "http://localhost:5173",
        help = "origin of the replying party",
        long_help = "should be url to your identity website, the domain should match the root of RP id or within subdomain of it"
    )]
    pub rp_origin: String,

    #[arg(long, required = false, env = "INSIGNIA_DB_CONN_STR", default_value = "postgresql://insignia:supersecurepw@localhost/insignia", help = "postgres database connection string")]
    pub db_conn_str: String,

    #[arg(long, required = false, env = "INSIGNIA_DRAGONFLY_CONN_STR", default_value = "localhost:6379", help = "dragonflydb connection string")]
    pub dragonflydb_conn_str: String,

    #[arg(long, required = false, env = "INSIGNIA_TWILIO_VERIFY_SID", help = "twilio verify sid")]
    pub twilio_verify_sid: String,

    #[arg(long, required = false, env = "INSIGNIA_TWILIO_ACCOUNT_SID", help = "twilio account sid")]
    pub twilio_account_sid: String,

    #[arg(long, required = false, env = "INSIGNIA_TWILIO_AUTH_TOKEN", help = "twilio auth token")]
    pub twilio_auth_token: String,

    #[arg(long, required = false, env = "INSIGNIA_INFOBIP_BASE_URL", help = "infobip baseurl")]
    pub infobip_base_url: String,

    #[arg(long, required = false, env = "INSIGNIA_INFOBIP_API_KEY", help = "infobip api key")]
    pub infobip_api_key: String,

    #[arg(long, required = false, env = "INSIGNIA_INFOBIP_2FA_APP_ID", help = "infobip 2fa application id")]
    pub infobip_twofa_app_id: String,

    #[arg(long, required = false, env = "INSIGNIA_INFOBIP_2FA_MESSAGE_TEMPLATE_ID", help = "infobip 2fa message template id")]
    pub infobip_twofa_message_template_id: String,

    #[arg(long, required = false, env = "INSIGNIA_SMS_OTP_PROVIDER", help = "sms one time passcode provider")]
    pub sms_otp_provider: String,
}
