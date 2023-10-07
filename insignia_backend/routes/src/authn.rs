
use std::{ops::Add, env};

use once_cell::sync::Lazy;
use actix_session::Session;
use sea_orm::prelude::Uuid;
use cookie::time::OffsetDateTime;
use chrono::{Utc, Days, Duration};
use jsonwebtoken::{EncodingKey, DecodingKey};
use actix_web::{web, HttpRequest, HttpResponse, cookie::Cookie};
use webauthn_rs::{Webauthn, prelude::{RegisterPublicKeyCredential, PasskeyRegistration, PublicKeyCredential, Passkey, PasskeyAuthentication}};

use models::users;
use common::{JwtClaims, UserContext};
use services::user_webauthn_credential::UserWebauthnCredData;

#[derive(serde::Deserialize)]
struct UserWebauthnRegiserReqDto {
    display_name: String,
}

#[derive(serde::Deserialize)]
struct WebauthnLoginReqDto {
    user_id: Uuid,
}

#[derive(serde::Serialize)]
struct LoginRespDto {
    access_token: String,
}

async fn register_webauthn_initialize(
    session: Session,
    user_context: UserContext,
    webauthn: web::Data<Webauthn>,
    db_conn: web::Data<sea_orm::DatabaseConnection>,
    body: web::Json<UserWebauthnRegiserReqDto>
) -> HttpResponse {
    let register_session = session.get::<String>("register").unwrap();

    if !user_context.is_jwt_verified || register_session.is_none() {
        return HttpResponse::Unauthorized().finish();
    }

    let user_id =
        match (user_context.user, register_session) {
            (Some(user), _) => Some(user.id),
            (_, Some(user_id)) => Some(Uuid::from_slice(user_id.as_bytes()).unwrap()),
            _ => None
        };

    session.remove("webauthn-register");

    if let Ok(u) = services::user::Query::get_user_info_by_id(&db_conn, user_id.unwrap()).await {
        if u.len() > 0 {
            let (user, webauthn_creds) = &u[0];

            let Ok((challenge, registration)) = webauthn.start_passkey_registration(
                user.id,
                &user.name,
                &body.display_name,
                webauthn_creds
                    .iter()
                    .map(|wc| {
                        Some(webauthn_rs::prelude::Base64UrlSafeData::from(wc.credential_id.clone().into_bytes()))
                    })
                    .collect()
            ) else {
                return HttpResponse::InternalServerError().finish();
            };

            session
            .insert("webauthn-register", (&user.name, &body.display_name, user.id, registration))
            .expect("fail to save webauthn-register session");

            return HttpResponse::Ok().json(challenge);
        }
    }

    HttpResponse::Unauthorized().finish()
}

async fn register_webauthn_finalize(
    req: HttpRequest,
    session: Session,
    webauthn: web::Data<Webauthn>,
    db_conn: web::Data<sea_orm::DatabaseConnection>,
    jwt_secret: web::Data<&Lazy<(EncodingKey, DecodingKey)>>,
    body: web::Json<RegisterPublicKeyCredential>,
) -> HttpResponse {
    if let Some((_, passkey_display_name, user_id, registration)) = session.get::<(String, String, Uuid, PasskeyRegistration)>("webauthn-register").unwrap() {
        session.remove("webauthn-register");

        let res = webauthn.finish_passkey_registration(&body, &registration);

        if let Ok(passkey) = res {
            let wc =
                services::user_webauthn_credential::Mutation::save_webauthn_credential(
                    &db_conn,
                    user_id,
                    passkey,
                    passkey_display_name
                ).await;

            if let Ok(_) = wc {
                let user =
                    services::user::Query::get_user_info_by_id(&db_conn, user_id)
                    .await
                    .expect("fail to get user info by id");

                let (token, refresh_token, fgp) = build_login_session(&user[0].0, &jwt_secret.0, &req);

                return HttpResponse::Ok()
                    .cookie(fgp)
                    .cookie(refresh_token)
                    .json(LoginRespDto{ access_token: token });
            }
        }
    }

    HttpResponse::UnprocessableEntity().finish()
}

async fn login_webauthn_initialize(
    session: Session,
    webauthn: web::Data<Webauthn>,
    db_conn: web::Data<sea_orm::DatabaseConnection>,
    body: web::Json<WebauthnLoginReqDto>
) -> HttpResponse {
    session.remove("webauthn-login");

    if let Ok(creds) = services::user_webauthn_credential::Query::list_user_webauthn_cred(&db_conn, body.user_id).await {
        let psk_creds = creds
            .iter()
            .map(|cred| {
                serde_json::from_value(serde_json::from_value::<sea_orm::JsonValue>(cred.credential_data.clone()).unwrap()).unwrap()
            })
            .collect::<Vec<Passkey>>();

        let Ok((challenge, auth)) =
            webauthn.start_passkey_authentication(
                psk_creds.as_slice()
            ) else {
                return HttpResponse::UnprocessableEntity().finish();
            };

        let creds: Vec<UserWebauthnCredData> =
            creds
            .iter()
            .map(|c| UserWebauthnCredData::from(c.to_owned()))
            .collect();
        
        session
        .insert("webauthn-login", (body.user_id, creds, auth))
        .expect("fail to save webauthn-login session");

        return HttpResponse::Ok().json(challenge);
    }

    HttpResponse::UnprocessableEntity().finish()
}

async fn login_webauthn_finalize(
    req: HttpRequest,
    session: Session,
    webauthn: web::Data<Webauthn>,
    db_conn: web::Data<sea_orm::DatabaseConnection>,
    jwt_secret: web::Data<&Lazy<(EncodingKey, DecodingKey)>>,
    body: web::Json<PublicKeyCredential>
) -> HttpResponse {
    if let Some((user_id, creds, auth)) = session.get::<(Uuid, Vec<UserWebauthnCredData>, PasskeyAuthentication)>("webauthn-login").unwrap() {
        session.remove("webauthn-login");

        if let Ok(auth_result) = webauthn.finish_passkey_authentication(&body, &auth) {
            let creds: Vec<(UserWebauthnCredData, Passkey)> =
                creds
                .iter()
                .cloned()
                .map(|cred| {
                    let mut psk: Passkey = serde_json::from_value(cred.credential_data.clone()).unwrap();

                    psk.update_credential(&auth_result);

                    (cred, psk)
                })
                .collect();

            if let Ok(true) = services::user_webauthn_credential::Mutation::update_webauthn_credentials_counter(&db_conn, creds).await {
                let user =
                    services::user::Query::get_user_info_by_id(&db_conn, user_id)
                    .await
                    .expect("fail to get user info by id");

                let (token, refresh_token, fgp) = build_login_session(&user[0].0, &jwt_secret.0, &req);

                return HttpResponse::Ok()
                    .cookie(fgp)
                    .cookie(refresh_token)
                    .json(LoginRespDto{ access_token: token });
            }
        }
    }

    HttpResponse::UnprocessableEntity().finish()
}

pub fn routes(cfg: &mut web::ServiceConfig) {
    tracing::info!("registering authn routes");

    cfg.route("webauthn/register", web::post().to(register_webauthn_initialize));
    cfg.route("webauthn/register", web::patch().to(register_webauthn_finalize));

    cfg.route("webauthn/login", web::post().to(login_webauthn_initialize));
    cfg.route("webauthn/login", web::patch().to(login_webauthn_finalize));

    tracing::info!("authn routes registered");
}

fn build_login_session<'a>(user: &'a users::Model, jwt_secret: &'a EncodingKey, req: &'a HttpRequest) -> (String, Cookie<'a>, Cookie<'a>) {
    let now = Utc::now();

    let access_expiry = now.add(Duration::minutes(16));

    let refresh_expiry = now.add(Days::new(8));

    let jwt_id = nanoid::nanoid!(32);

    let fgp = nanoid::nanoid!(32);

    let token_context = common::build_token_context(user, &req.headers(), &fgp, &now, &access_expiry);

    let frontend_url = env::var("INSIGNIA_FRONTEND_URL").expect("fail to read from env var");

    let aud = frontend_url.clone();
    let iss = aud.clone();

    let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
            &JwtClaims{
                id: jwt_id,
                sub: user.id.to_string(),
                iat: now.timestamp() as usize,
                nbf: now.timestamp() as usize,
                exp: access_expiry.timestamp() as usize,
                typ: common::JwtType::Login,
                aud: aud.clone(),
                iss: iss.clone(),
                ctx: Some(token_context.clone()),
                scope: None,
            },
            jwt_secret
        ).expect("fail to create jwt token");

    let refresh_token = Cookie::build(
            "__Host-Refresh",
            jsonwebtoken::encode(
                &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
                &JwtClaims{
                    id: nanoid::nanoid!(32),
                    sub: user.id.to_string(),
                    iat: now.timestamp() as usize,
                    nbf: now.timestamp() as usize,
                    exp: refresh_expiry.timestamp() as usize,
                    typ: common::JwtType::Refresh,
                    aud: aud,
                    iss: iss,
                    ctx: Some(token_context),
                    scope: None,
                },
                jwt_secret
            ).expect("fail to create jwt token")
        )
        .path("/")
        .expires(OffsetDateTime::from_unix_timestamp(refresh_expiry.timestamp()).unwrap())
        .same_site(actix_web::cookie::SameSite::Strict)
        .http_only(true)
        .secure(true)
        .finish();

    let fgp = Cookie::build(
            "__Host-Fgp",
            fgp,
        )
        .path("/")
        .expires(OffsetDateTime::from_unix_timestamp(refresh_expiry.timestamp()).unwrap())
        .same_site(actix_web::cookie::SameSite::Strict)
        .http_only(true)
        .secure(true)
        .finish();

    (token, refresh_token, fgp)
}
