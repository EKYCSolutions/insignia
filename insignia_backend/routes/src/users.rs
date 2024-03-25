
use std::ops::Add;

use actix::Addr;
use once_cell::sync::Lazy;
use actix_session::Session;
use sea_orm::prelude::Uuid;
use argon2::{PasswordHasher, PasswordVerifier};
use actix_web::{web, HttpResponse, HttpRequest};
use jsonwebtoken::{TokenData, EncodingKey, DecodingKey};
use chrono::{DateTime, Duration, FixedOffset, NaiveDateTime, Utc};

use super::oauth::AuthorizeCodeFlowData;
use services::dragonfly::DragonflyService;
use super::extractors::user_context::UserContext;
use common::{JwtClaims, build_login_session, SESSION_COOKIE_SETTING};
use models::{user_info::{UserInfoRespDto, UserSessionRespDto}, http_error::{AppError, AppHttpErrorResponseDto}};

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
    extras_meta: Option<serde_json::Value>,
}

#[derive(serde::Serialize)]
struct UserCreateRespDto {
    id: Uuid,
}

#[derive(serde::Deserialize)]
struct ListUsersReqDto {
    limit: u64,
    offset: u64,
}

#[derive(serde::Serialize)]
struct UserForAdmin {
    id: Uuid,
    name: String,
    phone: Option<String>,
    email: Option<String>,
    password: Option<String>,
    created_at: DateTime<FixedOffset>,
    extras_meta: Option<serde_json::Value>,
    phone_verified_at: Option<DateTime<FixedOffset>>,
    email_verified_at: Option<DateTime<FixedOffset>>,
    webauthn_credentials: Vec<UserWebauthnCredentialForAdmin>,
}

#[derive(serde::Serialize)]
struct UserWebauthnCredentialForAdmin {
    id: i32,
    name: String,
}

impl From<(models::users::Model, Vec<models::users_webauthn_credentials::Model>)> for UserForAdmin {
    fn from((user, user_webauthn_credentials): (models::users::Model, Vec<models::users_webauthn_credentials::Model>)) -> Self {
        Self {
            id: user.id,
            name: user.name,
            created_at: user.created_at,
            extras_meta: user.extras_meta,
            phone: user.phone.map(|p| {
                let mut p = p;

                p.replace_range(6..p.len()-6, "*");

                p
            }),
            email: user.email.map(|em| {
                let mut em = em;

                em.replace_range(..em.find('@').unwrap(), "*");

                em
            }),
            password: user.password.map(|_| "*".repeat(32)),
            phone_verified_at: user.phone_verified_at,
            email_verified_at: user.email_verified_at,
            webauthn_credentials: user_webauthn_credentials
                .into_iter()
                .map(|uwc| UserWebauthnCredentialForAdmin{id: uwc.id, name: uwc.name})
                .collect(),
        }
    }
}

#[derive(serde::Serialize)]
pub struct OauthAuthorizedClientResponse {
    pub id: i32,
    pub oauth_client_id: String,
}

impl From<models::users_oauth_authorized_clients::Model> for OauthAuthorizedClientResponse {
    fn from(value: models::users_oauth_authorized_clients::Model) -> Self {
        Self {
            id: value.id,
            oauth_client_id: value.oauth_client_id.to_string(),
        }
    }
}

async fn check_user(
    query: web::Query<UserQueryDto>,
    db_conn: web::Data<sea_orm::DatabaseConnection>
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let user = services::user::Query::get_existence(&db_conn, &query.identifier)
        .await?;

    if let Some(_) = user {
        return Ok(HttpResponse::NoContent().finish());
    }

    Ok(HttpResponse::NotFound().finish())
}

async fn get_user_info(
    query: web::Query<UserQueryDto>,
    db_conn: web::Data<sea_orm::DatabaseConnection>
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let mut user = services::user::Query::get_user_info(&db_conn, &query.identifier)
        .await?;

    if user.len() > 0 {
        return Ok(HttpResponse::Ok().json(UserInfoRespDto::from(user.pop().unwrap())));
    }

    Ok(HttpResponse::NotFound().finish())
}

async fn create_user(
    session: Session,
    body: web::Json<UserCreateReqDto>,
    db_conn: web::Data<sea_orm::DatabaseConnection>
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let user_id = services::user::Mutation::create_user(
            &db_conn,
            &body.name,
            body.phone.to_owned(),
            body.email.to_owned(),
            body.password.to_owned(),
            body.extras_meta.to_owned()
        )
            .await?;

    if body.password.is_some() {
        return Ok(HttpResponse::NoContent().finish());
    }

    session
        .insert("register", user_id)?;

    Ok(HttpResponse::NoContent().finish())
}

fn verify_recovery_data(user: &models::users::Model, input_recovery_data: &str) -> Result<bool, AppError> {
    let recovery_data = user.recovery_data
        .clone()
        .unwrap();

    let recovery_data: Vec<&str> = recovery_data
        .split(".")
        .collect();

    if let Ok(salt) = argon2::password_hash::Salt::from_b64(recovery_data[0]) {
        let recovery_data_hash = argon2::Argon2::default()
            .hash_password(
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
        let user = user_context.user
            .unwrap();

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
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let (_, _, refresh_cookie_name, fgp_cookie_name) = *SESSION_COOKIE_SETTING;

    if let (Some(fgp), Some(refresh_token)) = (req.cookie(fgp_cookie_name), req.cookie(refresh_cookie_name)) {
        let refresh_validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);

        if let Ok(TokenData{ claims, header: _ }) = jsonwebtoken::decode::<JwtClaims>(
            refresh_token.value(),
            &jwt_secret.1,
            &refresh_validation
        ) {
            let user_id = claims.sub;

            let user = services::user::Query::get_user_info_by_id(&db_conn, user_id)
                .await?;

            let iat = DateTime::<Utc>::from_naive_utc_and_offset(
                NaiveDateTime::from_timestamp_opt(claims.iat as i64, 0)
                        .unwrap(),
                    Utc
                );
            let access_exp = iat.add(Duration::minutes(16));

            let token_ctx = common::build_token_context(
                &user[0].0,
                &req.headers().clone(),
                fgp.value(),
                &iat,
                &access_exp
            );

            if claims.ctx == Some(token_ctx) {
                let (access_token, refresh_token, fgp) = build_login_session(
                    &user[0].0,
                    &jwt_secret.0, &req
                );

                return Ok(HttpResponse::Ok()
                    .cookie(fgp)
                    .cookie(refresh_token)
                    .json(models::login::LoginRespDto{ access_token }));
            }
        }
    }

    Ok(HttpResponse::Unauthorized().finish())
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

pub async fn oauth_consent(
    user_context: UserContext,
    db_conn: web::Data<sea_orm::DatabaseConnection>,
    body: web::Json<models::oauth::UserOauthConsentApproveRequestDto>,
    dragonfly_service: web::Data<Addr<DragonflyService>>,
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    if user_context.is_jwt_verified && user_context.user.is_some() {
        return Ok(HttpResponse::Unauthorized().finish());
    }

    let auth_flow_data = dragonfly_service.send(services::dragonfly::DragonflyCommand::Get(body.request_id.to_owned()))
        .await??;

    if let Some(auth_flow_data) = auth_flow_data {
        let auth_flow_data = serde_json::from_str::<AuthorizeCodeFlowData>(&auth_flow_data)?;

        let user = user_context.user.unwrap();

        let authorized_client = services::user::Query::get_oauth_authorized_client_by_client_id(
            &db_conn,
            auth_flow_data.oauth_client_id,
            user.id
        )
            .await?;

        if authorized_client.is_some() {
            return Ok(HttpResponse::NoContent().finish());
        }

        let oauth_client = services::oauth::Query::get_oauth_client_by_client_id(
            &db_conn,
            auth_flow_data.client_id
        )
            .await?;

        if oauth_client.is_none() {
            return Ok(HttpResponse::Unauthorized().finish());
        }

        let consent = services::user::Mutation::oauth_consent_for_app_to_act_on_behalf_of_user(
            &db_conn,
            user,
            oauth_client.unwrap(),
            body.consents.to_owned(),
        )
            .await?;

        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "oauth_consents": consent.1,
            "oauth_authorized_client": consent.0,
        })));
    }

    Ok(HttpResponse::Unauthorized().finish())
}

pub async fn authorized_clients(
    user_context: UserContext,
    db_conn: web::Data<sea_orm::DatabaseConnection>,
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    if let Some(user) = user_context.user {
        let authorized_clients = services::user::Query::list_oauth_authorized_client(&db_conn, user)
            .await?;

        let mut authorized_clients_resp: Vec<OauthAuthorizedClientResponse> = vec![];

        for c in authorized_clients {
            authorized_clients_resp.push(c.into());
        }

        return Ok(HttpResponse::Ok().json(authorized_clients_resp));
    }

    Ok(HttpResponse::Unauthorized().finish())
}

pub fn routes(cfg: &mut web::ServiceConfig) {
    tracing::info!("registering users routes");

    cfg.service(
        web::resource("")
            .route(web::head().to(check_user))
            .route(web::post().to(create_user))
            .route(web::get().to(get_user_info))
    );

    cfg.route("oauth/authorized-clients", web::get().to(authorized_clients));

    cfg.route("oauth/consent", web::post().to(oauth_consent));

    cfg.route("session", web::get().to(get_user_session));
    cfg.route("session", web::delete().to(logout));
    cfg.route("session/refresh", web::post().to(refresh_session));

    cfg.route("recovery-data", web::post().to(set_recovery_data));

    tracing::info!("users routes registered");
}

async fn remove_user(
    id: web::Path<Uuid>,
    db_conn: web::Data<sea_orm::DatabaseConnection>
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    services::user::Mutation::remove_user(&db_conn, *id)
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

async fn list_users(
    query: web::Query<ListUsersReqDto>,
    db_conn: web::Data<sea_orm::DatabaseConnection>
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let users = services::user::Query::list_users(&db_conn, query.limit, query.offset)
        .await?;

    let users: Vec<UserForAdmin> = users
        .into_iter()
        .map(UserForAdmin::from)
        .collect();

    Ok(HttpResponse::Ok().json(users))
}

pub fn admin_routes(cfg: &mut web::ServiceConfig) {
    tracing::info!("registering users admin routes");

    cfg.route("", web::get().to(list_users));
    cfg.route("/{id}", web::delete().to(remove_user));

    tracing::info!("users admin routes registered");
}
