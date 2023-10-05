
use sea_orm::prelude::Uuid;
use argon2::{PasswordHasher, PasswordVerifier};
use actix_web::{web, HttpResponse, HttpRequest, cookie::SameSite};

use common::UserContext;
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

async fn create_user(body: web::Json<UserCreateReqDto>, db_conn: web::Data<sea_orm::DatabaseConnection>) -> HttpResponse {
    if let Ok(user_id) = services::user::Mutation::create_user(&db_conn, &body.name, body.phone.to_owned(), body.email.to_owned(), body.password.to_owned()).await {
        return HttpResponse::Ok().json(UserCreateRespDto{ id: user_id });
    }

    HttpResponse::Ok().json(UserCreateRespDto{ id: Uuid::new_v4() })
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
    body: web::Json<SetRecoveryDataReqDto>
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
        return HttpResponse::Ok().json(UserSessionRespDto::from(user_context.user.unwrap()));
    }

    HttpResponse::Unauthorized().finish()
}

async fn logout(req: HttpRequest) -> HttpResponse {
    let refresh_cookie =
        if let Some(cookie) = req.cookie("__Host-Refresh") {
            let mut cookie = cookie;

            cookie.make_removal();
            cookie.set_path("/");
            cookie.set_secure(true);
            cookie.set_http_only(true);
            cookie.set_same_site(SameSite::Strict);

            cookie
        } else {
            return HttpResponse::UnprocessableEntity()
                .finish();
        };

    let fgp_cookie =
        if let Some(cookie) = req.cookie("__Host-Fgp") {
            let mut cookie = cookie;

            cookie.make_removal();
            cookie.set_path("/");
            cookie.set_secure(true);
            cookie.set_http_only(true);
            cookie.set_same_site(SameSite::Strict);

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
    cfg.route("recovery-data", web::post().to(set_recovery_data));

    tracing::info!("users routes registered");
}
