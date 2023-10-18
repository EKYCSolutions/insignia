
use chrono::Utc;
use once_cell::sync::Lazy;
use actix_session::Session;
use sea_orm::prelude::Uuid;
use argon2::PasswordVerifier;
use jsonwebtoken::{EncodingKey, DecodingKey};
use actix_web::{web, HttpRequest, HttpResponse};
use webauthn_rs::{Webauthn, prelude::{RegisterPublicKeyCredential, PasskeyRegistration, PublicKeyCredential, Passkey, PasskeyAuthentication}};

use common::build_login_session;
use super::extractors::user_context::UserContext;
use services::{user_webauthn_credential::UserWebauthnCredData, sms_otp::CoreSMSOtp};

#[derive(serde::Deserialize)]
struct UserWebauthnRegiserReqDto {
    display_name: String,
}

#[derive(serde::Deserialize)]
struct WebauthnLoginReqDto {
    user_id: Uuid,
}

#[derive(serde::Deserialize)]
struct PhoneOtpLoginReqDto {
    user_id: Uuid,
}

#[derive(serde::Deserialize)]
struct VerifyPhoneOtpReqDto {
    code: String,
    phone: String,
}

#[derive(serde::Deserialize)]
struct PasswordLoginReqDto {
    user_id: Uuid,
    password: String,
}

async fn register_webauthn_initialize(
    session: Session,
    user_context: UserContext,
    webauthn: web::Data<Webauthn>,
    db_conn: web::Data<sea_orm::DatabaseConnection>,
    body: web::Json<UserWebauthnRegiserReqDto>
) -> HttpResponse {
    let register_session = session.get::<Uuid>("register").unwrap();

    if !user_context.is_jwt_verified && register_session.is_none() {
        return HttpResponse::Unauthorized().finish();
    }

    let user =
        match (user_context.user, register_session) {
            (Some(user), _) => Some((user, user_context.webauthn_credentials)),
            (_, Some(user_id)) => {
                if let Ok(u) = services::user::Query::get_user_info_by_id(&db_conn, user_id).await {
                    Some(u[0].to_owned())
                } else {
                    None
                }
            }
            _ => None
        };

    session.remove("webauthn-register");

    if user.is_some() {
        let (user, webauthn_creds) = user.unwrap();

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
                    .json(models::login::LoginRespDto{ access_token: token });
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

                let (token, refresh_token, fgp) = common::build_login_session(&user[0].0, &jwt_secret.0, &req);

                return HttpResponse::Ok()
                    .cookie(fgp)
                    .cookie(refresh_token)
                    .json(models::login::LoginRespDto{ access_token: token });
            }
        }
    }

    HttpResponse::UnprocessableEntity().finish()
}

async fn verify_phone_otp_attempt(
    session: Session,
    user_context: UserContext,
    db_conn: web::Data<sea_orm::DatabaseConnection>,
    sms_otp_service: web::Data<actix::Addr<CoreSMSOtp>>
) -> HttpResponse {
    let register_session = session.get::<Uuid>("register").unwrap();

    if !user_context.is_jwt_verified && register_session.is_none() {
        return HttpResponse::Unauthorized().finish();
    }

    let phone =
        match (user_context.user, register_session) {
            (Some(u), _) => u.phone,
            (_, Some(user_id)) => {
                let user = services::user::Query::get_user_info_by_id(&db_conn, user_id)
                    .await
                    .expect("fail to read user from database");

                let user = user[0].0.to_owned();

                user.phone
            },
            _ => None
        };

    if let Some(phone) = phone {
        let _ =
            sms_otp_service
                .send(services::sms_otp::CoreSMSOtpCommand::Send(phone))
                .await
                .expect("fail to send sms otp");
    }

    HttpResponse::NoContent().finish()
}

async fn verify_phone_otp(
    body: web::Form<VerifyPhoneOtpReqDto>,
    db_conn: web::Data::<sea_orm::DatabaseConnection>,
    sms_otp_service: web::Data<actix::Addr<CoreSMSOtp>>
) -> HttpResponse {
    let result = sms_otp_service
        .send(services::sms_otp::CoreSMSOtpCommand::Verify(body.phone.to_owned(), body.code.to_owned()))
        .await
        .expect("fail to verify sms otp");

    if let Ok(result) = result {
        return match result {
            services::sms_otp::SMSOtpResult::VerifyResult(true) => {
                let user = services::user::Query::get_user_info(&db_conn, &body.phone)
                    .await
                    .expect("fail to get user info");

                let user = user[0].0.to_owned();

                let result =
                    services::user::Mutation::update_user(
                        &db_conn,
                        user,
                        services::user::UserUpdate{
                            name: None,
                            phone: None,
                            email: None,
                            password: None,
                            session_data: None,
                            email_verified_at: None,
                            phone_verified_at: Some(Utc::now().fixed_offset()),
                        }
                    )
                    .await;

                if let Ok(()) = result {
                    return HttpResponse::NoContent().finish();
                }

                HttpResponse::UnprocessableEntity().finish()
            },
            _ =>
                HttpResponse::UnprocessableEntity().finish()
        };
    }

    HttpResponse::Unauthorized().finish()
}

async fn login_phone_otp_attempt(
    db_conn: web::Data<sea_orm::DatabaseConnection>,
    body: web::Form<PhoneOtpLoginReqDto>,
    sms_otp_service: web::Data<actix::Addr<CoreSMSOtp>>
) -> HttpResponse {
    let user = services::user::Query::get_user_info_by_id(&db_conn, body.user_id)
        .await
        .expect("fail to get user by id");

    let user = user[0].0.to_owned();

    if user.phone.is_some() && user.phone_verified_at.is_some() {
        let _ =
            sms_otp_service
                .send(services::sms_otp::CoreSMSOtpCommand::Send(user.phone.unwrap()))
                .await
                .expect("fail to send sms otp");
    }

    HttpResponse::NoContent().finish()
}

async fn login_phone_otp(
    req: HttpRequest,
    body: web::Form::<VerifyPhoneOtpReqDto>,
    db_conn: web::Data::<sea_orm::DatabaseConnection>,
    sms_otp_service: web::Data<actix::Addr<CoreSMSOtp>>,
    jwt_secret: web::Data<&Lazy<(EncodingKey, DecodingKey)>>
) -> HttpResponse {
    let result =
        sms_otp_service
            .send(services::sms_otp::CoreSMSOtpCommand::Verify(body.phone.clone(), body.code.to_owned()))
            .await
            .expect("fail to verify sms otp");

    if let Ok(result) = result {
        return match result {
            services::sms_otp::SMSOtpResult::VerifyResult(true) => {
                let user =
                    services::user::Query::get_user_info(&db_conn, &body.phone)
                    .await
                    .expect("fail to get user info by id");

                let (token, refresh_token, fgp) = build_login_session(&user[0].0, &jwt_secret.0, &req);

                return HttpResponse::Ok()
                    .cookie(fgp)
                    .cookie(refresh_token)
                    .json(models::login::LoginRespDto{ access_token: token });
            },
            _ =>
                HttpResponse::Unauthorized().finish()
        }
    }

    HttpResponse::Unauthorized().finish()
}

async fn login_password(
    req: HttpRequest,
    body: web::Form::<PasswordLoginReqDto>,
    db_conn: web::Data::<sea_orm::DatabaseConnection>,
    jwt_secret: web::Data<&Lazy<(EncodingKey, DecodingKey)>>
) -> HttpResponse {
    let user = services::user::Query::get_user_info_by_id(&db_conn, body.user_id)
        .await
        .expect("fail to get user info by id");

    if user.len() > 0 {
        let user = user[0].0.to_owned();

        if let Some(password) = user.password.clone() {
            let hashed_password = argon2::password_hash::PasswordHash::new(&password).unwrap();

            if argon2::Argon2::default().verify_password(body.password.as_bytes(), &hashed_password).is_ok() {
                let (token, refresh_token, fgp) = build_login_session(&user, &jwt_secret.0, &req);

                return HttpResponse::Ok()
                    .cookie(fgp)
                    .cookie(refresh_token)
                    .json(models::login::LoginRespDto{ access_token: token });
            }
        }
    }

    HttpResponse::Unauthorized().finish()
}

pub fn routes(cfg: &mut web::ServiceConfig) {
    tracing::info!("registering authn routes");

    cfg.route("password/login", web::post().to(login_password));

    cfg.route("phone-otp/login", web::patch().to(login_phone_otp));
    cfg.route("phone-otp/login", web::post().to(login_phone_otp_attempt));

    cfg.route("verify-phone", web::patch().to(verify_phone_otp));
    cfg.route("verify-phone", web::post().to(verify_phone_otp_attempt));

    cfg.route("webauthn/register", web::post().to(register_webauthn_initialize));
    cfg.route("webauthn/register", web::patch().to(register_webauthn_finalize));

    cfg.route("webauthn/login", web::post().to(login_webauthn_initialize));
    cfg.route("webauthn/login", web::patch().to(login_webauthn_finalize));

    tracing::info!("authn routes registered");
}
