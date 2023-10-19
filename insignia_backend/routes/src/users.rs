
use std::ops::Add;

use once_cell::sync::Lazy;
use sea_orm::prelude::Uuid;
use actix_session::Session;
use argon2::{PasswordHasher, PasswordVerifier};
use actix_web::{web, HttpResponse, HttpRequest};
use chrono::{DateTime, Utc, NaiveDateTime, Duration};
use jsonwebtoken::{TokenData, EncodingKey, DecodingKey};

use super::extractors::user_context::UserContext;

use common::{JwtClaims, build_login_session, SESSION_COOKIE_SETTING};
use models::{user_info::{UserInfoRespDto, UserSessionRespDto}, http_error::{AppHttpError, AppHttpErrorResponseDto}};

#[derive(serde::Deserialize)]
struct UserQueryDto {
    identifier: String,
}

#[derive(serde::Deserialize)]
struct SetRecoveryDataReqDto {
    salt: String,
    part: String,
    recovery_data: Option<String>,
}

#[derive(serde::Deserialize)]
struct UserCreateReqDto {
    name: String,
    phone: Option<String>,
    email: Option<String>,
    password: Option<String>,
}

#[derive(serde::Serialize)]
struct UserCreateRespDto {
    id: Uuid,
}

async fn check_user(query: web::Query<UserQueryDto>, db_conn: web::Data<sea_orm::DatabaseConnection>) -> HttpResponse {
    if let Ok(Some(_)) = services::user::Query::get_existence(&db_conn, &query.identifier).await {
        return HttpResponse::NoContent().finish();
    }

    HttpResponse::NotFound().finish()
}

async fn get_user_info(query: web::Query<UserQueryDto>, db_conn: web::Data<sea_orm::DatabaseConnection>) -> HttpResponse {
    if let Ok(u) = services::user::Query::get_user_info(&db_conn, &query.identifier).await {
        if u.len() > 0 {
            return HttpResponse::Ok().json(UserInfoRespDto::from(u[0].clone()));
        }
    }

    HttpResponse::NotFound().finish()
}

async fn create_user(
    session: Session,
    body: web::Form<UserCreateReqDto>,
    db_conn: web::Data<sea_orm::DatabaseConnection>
) -> HttpResponse {
    if let Ok(user_id) = services::user::Mutation::create_user(&db_conn, &body.name, body.phone.to_owned(), body.email.to_owned(), body.password.to_owned()).await {
        if body.password.is_some() {
            return HttpResponse::NoContent().finish();
        }

        session
        .insert("register", user_id)
        .expect("fail to save register session");
    }

    HttpResponse::NoContent().finish()
}

fn verify_recovery_data(user: &models::users::Model, input_recovery_data: &str) -> Result<bool, AppHttpError> {
    let recovery_data = user.recovery_data.clone().unwrap();

    let recovery_data: Vec<&str> = recovery_data
        .split(".")
        .collect();

    if let Ok(salt) = argon2::password_hash::Salt::from_b64(recovery_data[0]) {
        let recovery_data_hash = argon2::Argon2::default().hash_password(
            input_recovery_data.as_bytes(),
            salt
        )?
        .to_string();

        let (_, part) = recovery_data_hash.split_at(recovery_data_hash.len() / 2);

        let part = blake3::Hasher::new()
            .update(part.as_bytes())
            .finalize()
            .to_string();

        let hash = argon2::PasswordHash::new(&recovery_data[1])?;

        if !argon2::Argon2::default().verify_password(
            part.as_bytes(),
            &hash
        ).is_ok() {
            return Ok(true);
        }
    }

    Ok(false)
}

async fn set_recovery_data(
    user_context: UserContext,
    db_conn: web::Data<sea_orm::DatabaseConnection>,
    body: web::Form<SetRecoveryDataReqDto>
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    if user_context.is_jwt_verified {
        let user = user_context.user.unwrap();

        if user.recovery_data.is_some() {
            if body.recovery_data.is_none() || !verify_recovery_data(&user, body.recovery_data.to_owned().unwrap().as_str())? {
                return Ok(HttpResponse::Forbidden().finish());
            }
        }

        if let Ok(()) = services::user::Mutation::set_recovery_data(
            &db_conn,
            user,
            &body.salt,
            &body.part
        ).await {
            return Ok(HttpResponse::NoContent().finish());
        }
    }

    Ok(HttpResponse::Forbidden().finish())
}

async fn get_user_session(user_context: UserContext) -> HttpResponse {
    if user_context.is_jwt_verified {
        let mut user = UserSessionRespDto::from(user_context.user.unwrap());

        if let Some(mut phone) = user.phone {
            phone.replace_range(..(phone.len() - 2), "*".repeat(phone.len() - 2).as_str());

            user.phone = Some(phone);
        }

        if let Some(mut email) = user.email {
            let offset = email.find('@');

            email.replace_range(..offset.unwrap(), "*".repeat(offset.unwrap()).as_str());

            user.email = Some(email);
        }

        return HttpResponse::Ok().json(user);
    }

    HttpResponse::Unauthorized().finish()
}

async fn refresh_session(
    req: HttpRequest,
    db_conn: web::Data<sea_orm::DatabaseConnection>,
    jwt_secret: web::Data<&Lazy<(EncodingKey, DecodingKey)>>,
) -> HttpResponse {
    let (_, _, refresh_cookie_name, fgp_cookie_name) = *SESSION_COOKIE_SETTING;

    let auth_data =
        match (req.cookie(fgp_cookie_name), req.cookie(refresh_cookie_name)) {
            (Some(fgp), Some(refresh)) => {
                Some((fgp, refresh))
            }
            _ => None
        };

    if auth_data.is_some() {
        let (fgp, refresh_token) = auth_data.unwrap();

        let refresh_validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);

        if let Ok(TokenData{ claims, header: _ }) = jsonwebtoken::decode::<JwtClaims>(
            refresh_token.value(),
            &jwt_secret.1,
            &refresh_validation
        ) {
            let user_id = Uuid::from_slice(claims.sub.as_bytes()).unwrap();

            if let Ok(user) = services::user::Query::get_user_info_by_id(&db_conn, user_id).await {
                let iat = DateTime::<Utc>::from_naive_utc_and_offset(NaiveDateTime::from_timestamp_opt(claims.iat as i64, 0).unwrap(), Utc);
                let access_exp = iat.add(Duration::minutes(16));

                let token_ctx = common::build_token_context(
                    &user[0].0,
                    &req.headers().clone(),
                    fgp.value(),
                    &iat,
                    &access_exp
                );

                if claims.ctx == Some(token_ctx) {
                    let (access_token, refresh_token, fgp) = build_login_session(&user[0].0, &jwt_secret.0, &req);

                    return HttpResponse::Ok()
                        .cookie(fgp)
                        .cookie(refresh_token)
                        .json(models::login::LoginRespDto{ access_token });
                }
            }
        }
    }

    HttpResponse::Unauthorized().finish()
}

async fn logout(req: HttpRequest) -> HttpResponse {
    let (same_site, is_cookie_secure, refresh_cookie_name, fgp_cookie_name) = *SESSION_COOKIE_SETTING;

    let refresh_cookie =
        if let Some(cookie) = req.cookie(refresh_cookie_name) {
            let mut cookie = cookie;

            cookie.make_removal();
            cookie.set_path("/");
            cookie.set_secure(is_cookie_secure);
            cookie.set_http_only(true);
            cookie.set_same_site(same_site);

            cookie
        } else {
            return HttpResponse::UnprocessableEntity()
                .finish();
        };

    let fgp_cookie =
        if let Some(cookie) = req.cookie(fgp_cookie_name) {
            let mut cookie = cookie;

            cookie.make_removal();
            cookie.set_path("/");
            cookie.set_secure(is_cookie_secure);
            cookie.set_http_only(true);
            cookie.set_same_site(same_site);

            cookie
        } else {
            return HttpResponse::UnprocessableEntity()
                .finish();
        };

    HttpResponse::NoContent()
        .cookie(fgp_cookie)
        .cookie(refresh_cookie)
        .finish()
}

pub fn routes(cfg: &mut web::ServiceConfig) {
    tracing::info!("registering users routes");

    cfg.service(
        web::resource("")
            .route(web::head().to(check_user))
            .route(web::post().to(create_user))
            .route(web::get().to(get_user_info))
    );

    cfg.route("session", web::get().to(get_user_session));
    cfg.route("session", web::delete().to(logout));
    cfg.route("session/refresh", web::post().to(refresh_session));

    cfg.route("recovery-data", web::post().to(set_recovery_data));

    tracing::info!("users routes registered");
}
