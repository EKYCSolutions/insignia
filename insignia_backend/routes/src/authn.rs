
use std::{ops::Add, env};

use common::JwtClaims;
use once_cell::sync::Lazy;
use actix_session::Session;
use sea_orm::prelude::Uuid;
use cookie::time::OffsetDateTime;
use chrono::{Utc, Days, Duration};
use jsonwebtoken::{EncodingKey, DecodingKey};
use actix_web::{web, HttpRequest, HttpResponse, cookie::Cookie};
use webauthn_rs::{Webauthn, prelude::{RegisterPublicKeyCredential, PasskeyRegistration}};

use models::users;

#[derive(serde::Deserialize)]
struct UserWebauthnCredAuthReqDto {
    user_id: Uuid,
    display_name: String,
}

async fn register_webauthn_initialize(
    session: Session,
    webauthn: web::Data<Webauthn>,
    db_conn: web::Data<sea_orm::DatabaseConnection>,
    body: web::Json<UserWebauthnCredAuthReqDto>
) -> HttpResponse {
    session.remove("webauthn-register");

    if let Ok(u) = services::user::Query::get_user_info_by_id(&db_conn, body.user_id).await {
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
                return HttpResponse::UnprocessableEntity().finish();
            };

            session
            .insert("webauthn-register", (&user.name, &body.display_name, user.id, registration))
            .expect("fail to save webauthn-register session");

            return HttpResponse::Ok().json(challenge);
        }
    }

    HttpResponse::UnprocessableEntity().finish()
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
                    .body(token);
            }
        }
    }

    HttpResponse::UnprocessableEntity().finish()
}

pub fn routes(cfg: &mut web::ServiceConfig) {
    tracing::info!("registering authn routes");

    cfg.route("webauthn/register", web::patch().to(register_webauthn_finalize));
    cfg.route("webauthn/register", web::post().to(register_webauthn_initialize));

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
            "__Secure-Refresh",
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
            "__Secure-Fgp",
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
