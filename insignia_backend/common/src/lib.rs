use std::{pin::Pin, str::FromStr, env, ops::Add};

use clap::Parser;
use futures_util::Future;
use once_cell::sync::Lazy;
use sea_orm::prelude::Uuid;
use cookie::time::OffsetDateTime;
use jsonwebtoken::{EncodingKey, DecodingKey, TokenData};
use chrono::{DateTime, Utc, NaiveDateTime, Duration, Days};
use actix_web::{http::{Error, header::HeaderMap}, FromRequest, HttpRequest, cookie::Cookie};

use models::{users, users_webauthn_credentials};

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum JwtType {
    Login,
    Refresh,
    OauthAccess,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct JwtClaims {
    pub id: String,
    pub iat: usize,
    pub nbf: usize,
    pub exp: usize,
    pub aud: String,
    pub iss: String,
    pub sub: String,
    pub typ: JwtType,
    pub ctx: Option<String>,
    pub scope: Option<String>
}

pub struct UserContext {
    pub is_jwt_verified: bool,
    pub user: Option<users::Model>,
    pub webauthn_credentials: Vec<users_webauthn_credentials::Model>
}

impl FromRequest for UserContext {
    type Error = Error;

    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload
    ) -> Self::Future {
        let auth_data =
            match (req.cookie("__Host-Fgp"), req.headers().get("authorization")) {
                (Some(fgp), Some(token_value)) => {
                    let token_value = token_value.to_str().unwrap().replace("Bearer ", "");

                    let key =
                        req
                        .app_data::<actix_web::web::Data<&Lazy<(EncodingKey, DecodingKey)>>>()
                        .expect("fail to get jwt secret key for user context");

                    if let Ok(TokenData{ claims, header: _ }) = jsonwebtoken::decode::<JwtClaims>(
                        &token_value,
                        &key.1,
                        &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA)
                    ) {
                        Some((fgp, claims))
                    } else {
                        None
                    }
                }
                _ => None,
            };

        if auth_data.is_some() {
            let (fgp, claims) = auth_data.unwrap();

            let db_conn = req.app_data::<actix_web::web::Data<sea_orm::DatabaseConnection>>().unwrap().clone();

            let headers = req.headers().clone();

            return Box::pin(async move {
                let user = services::user::Query::get_user_info_by_id(
                    &db_conn,
                    Uuid::from_str(&claims.sub).unwrap()
                ).await.unwrap();

                let token_ctx = build_token_context(
                    &user[0].0,
                    &headers,
                    fgp.value(),
                    &DateTime::<Utc>::from_naive_utc_and_offset(NaiveDateTime::from_timestamp_opt(claims.iat as i64, 0).unwrap(), Utc),
                    &DateTime::<Utc>::from_naive_utc_and_offset(NaiveDateTime::from_timestamp_opt(claims.exp as i64, 0).unwrap(), Utc)
                );

                Ok(UserContext {
                    user: Some(user[0].0.to_owned()),
                    webauthn_credentials: user[0].1.to_owned(),
                    is_jwt_verified: claims.typ == JwtType::Login && claims.ctx.unwrap() == token_ctx,
                })
            });
        }

        Box::pin(async move {
            Ok(UserContext { user: None, webauthn_credentials: vec![], is_jwt_verified: false })
        })
    }
}

pub static FRONTEND_URL: Lazy<String> = Lazy::new(|| {
    env::var("INSIGNIA_FRONTEND_URL").expect("fail to read INSIGNIA_FRONTEND_URL from env var")
});

pub static IS_DEV_MODE: Lazy<bool> = Lazy::new(|| {
    env::var("INSIGNIA_DEV_MODE").expect("fail to read INSIGNIA_DEV_MODE from env var") == "true"
});

pub static SESSION_COOKIE_SETTING: Lazy<(actix_web::cookie::SameSite, bool, &str, &str)> = Lazy::new(|| {
    if *IS_DEV_MODE {
        (actix_web::cookie::SameSite::None, false, "Refresh", "Fgp")
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
                sub: user.id.to_string(),
                iat: now.timestamp() as usize,
                nbf: now.timestamp() as usize,
                exp: access_expiry.timestamp() as usize,
                typ: JwtType::Login,
                aud: FRONTEND_URL.clone(),
                iss: FRONTEND_URL.clone(),
                ctx: Some(token_context.clone()),
                scope: None,
            },
            jwt_secret
        ).expect("fail to create jwt token");

    let refresh_token = Cookie::build(
            refresh_cookie_name,
            jsonwebtoken::encode(
                &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
                &JwtClaims{
                    id: nanoid::nanoid!(32),
                    sub: user.id.to_string(),
                    iat: now.timestamp() as usize,
                    nbf: now.timestamp() as usize,
                    exp: refresh_expiry.timestamp() as usize,
                    typ: JwtType::Refresh,
                    aud: FRONTEND_URL.clone(),
                    iss: FRONTEND_URL.clone(),
                    ctx: Some(token_context),
                    scope: None,
                },
                jwt_secret
            ).expect("fail to create jwt token")
        )
        .path("/")
        .expires(OffsetDateTime::from_unix_timestamp(refresh_expiry.timestamp()).unwrap())
        .same_site(same_site)
        .http_only(is_cookie_secure)
        .secure(is_cookie_secure)
        .finish();

    let fgp = Cookie::build(
            fgp_cookie_name,
            fgp,
        )
        .path("/")
        .expires(OffsetDateTime::from_unix_timestamp(refresh_expiry.timestamp()).unwrap())
        .same_site(same_site)
        .http_only(is_cookie_secure)
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
}
