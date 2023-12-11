
use std::ops::{Add, Sub};

use actix::Addr;
use base64::Engine;
use common::JwtClaims;
use once_cell::sync::Lazy;
use sea_orm::prelude::Uuid;
use sha2::{Sha256, Digest};
use chrono::{Utc, Duration};
use jsonwebtoken::{EncodingKey, DecodingKey};
use actix_web::{web, HttpResponse, HttpRequest, http::header};

use services::dragonfly::DragonflyService;
use models::{http_error::{AppHttpErrorResponseDto, AppError}, oauth::UserOauthConsentResponse};

#[derive(serde::Deserialize)]
pub struct AddDelegableUserPermissionDto {
    name: String,
    label: Option<String>,
    zanzibar_value: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct AddOauthScopeDto {
    name: String,
    label: Option<String>,
    delegable_user_permission_id: i32,
}

#[derive(serde::Deserialize)]
pub struct GetOauthClientQueryDto {
    client_id: String,
}

#[derive(serde::Deserialize, PartialEq)]
#[serde(rename_all(deserialize = "snake_case"))]
pub enum OauthAuthorizeResponseType {
    Code,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all(deserialize = "snake_case"))]
pub enum CodeChallengeMethod {
    S256,
    Blake3,
}

#[derive(serde::Deserialize)]
pub struct OauthAuthorizeRequestDto {
    pub client_id: String,
    pub nonce: String,
    pub state: String,
    pub scope: String,
    pub redirect_uri: String,
    pub response_type: OauthAuthorizeResponseType,
    pub code_challenge: String,
    pub code_challenge_method: CodeChallengeMethod,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct AuthorizeCodeFlowData {
    pub context: String,
    pub client_id: String,
    pub oauth_client_id: i32,
    pub code_challenge: String,
    pub code_challenge_method: CodeChallengeMethod,
    pub nonce: String,
    pub state: String,
    pub request_timestamp: i64,
}

#[derive(serde::Deserialize)]
#[serde(rename_all(deserialize = "snake_case"))]
pub enum TokenGrantType {
    Refresh,
    AuthorizationCode,
    ClientCredentials,
}

#[derive(serde::Deserialize)]
pub struct TokenRequestDto {
    pub client_id: String,
    pub grant_type: TokenGrantType,
    pub code: Option<String>,
    pub nonce: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(serde::Serialize)]
pub struct TokenResponseDto {
    pub expires_in: u64,
    pub token_type: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
}

pub struct GenerateOauthTokenOpts {
    pub scope: Vec<String>,
    pub subject: Option<Uuid>,
    pub audience: Vec<String>,
    pub token_key: Option<String>,
    pub access_token_expiry: u32,
    pub refresh_token_expiry: u32,
}

static AUTH_UI_URL: Lazy<String> = Lazy::new(|| {
    std::env::var("INSIGNIA_AUTH_UI_URL")
        .expect("fail to read INSIGNIA_AUTH_UI_URL")
});

async fn add_delegable_user_permission(
    db_conn: web::Data<sea_orm::DatabaseConnection>,
    body: web::Json<AddDelegableUserPermissionDto>
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let delegable_user_permission = services::oauth::Mutation::add_delegable_user_permission(
        &db_conn,
        body.name.to_owned(),
        body.label.to_owned(),
        body.zanzibar_value.to_owned()
    )
        .await?;

    Ok(HttpResponse::Ok().json(delegable_user_permission))
}

async fn remove_delegable_user_permission(
    id: web::Path<i32>,
    db_conn: web::Data<sea_orm::DatabaseConnection>,
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    services::oauth::Mutation::remove_delegable_user_permission(&db_conn, *id)
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

async fn list_delegable_user_permission(
    db_conn: web::Data<sea_orm::DatabaseConnection>
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let delegable_user_permissions = services::oauth::Query::list_delegable_user_permission(&db_conn)
        .await?;

    Ok(HttpResponse::Ok().json(delegable_user_permissions))
}

async fn add_oauth_scope(
    body: web::Json<AddOauthScopeDto>,
    db_conn: web::Data<sea_orm::DatabaseConnection>,
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let oauth_scope = services::oauth::Mutation::add_oauth_scope(
        &db_conn,
        body.name.to_owned(),
        body.label.to_owned(),
        body.delegable_user_permission_id
    )
        .await?;

    Ok(HttpResponse::Ok().json(oauth_scope))
}

async fn remove_oauth_scope(
    id: web::Path<i32>,
    db_conn: web::Data<sea_orm::DatabaseConnection>,
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    services::oauth::Mutation::remove_oauth_scope(&db_conn, *id)
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

async fn list_oauth_scope(db_conn: web::Data<sea_orm::DatabaseConnection>) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let oauth_scopes = services::oauth::Query::list_oauth_scopes(&db_conn)
        .await?;

    Ok(HttpResponse::Ok().json(oauth_scopes))
}

async fn add_oauth_client(
    body: web::Json<models::oauth::OauthClientMutationDto>,
    db_conn: web::Data<sea_orm::DatabaseConnection>,
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let oauth_client = services::oauth::Mutation::add_oauth_client(&db_conn, &body)
        .await?;

    Ok(HttpResponse::Ok().json(oauth_client))
}

async fn list_oauth_client(db_conn: web::Data<sea_orm::DatabaseConnection>) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let oauth_clients = services::oauth::Query::list_oauth_client(&db_conn)
        .await?;

    Ok(HttpResponse::Ok().json(oauth_clients))
}

async fn get_oauth_client(
    query: web::Query<GetOauthClientQueryDto>,
    db_conn: web::Data<sea_orm::DatabaseConnection>,
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    Ok(HttpResponse::Ok().json(
        services::oauth::Query::get_oauth_client_by_client_id(&db_conn, query.client_id.to_owned())
            .await?
    ))
}

async fn remove_oauth_client(
    id: web::Path<i32>,
    db_conn: web::Data<sea_orm::DatabaseConnection>
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    services::oauth::Mutation::remove_oauth_client(&db_conn, *id)
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

async fn authorize(
    req: HttpRequest,
    body: web::Form<OauthAuthorizeRequestDto>,
    db_conn: web::Data<sea_orm::DatabaseConnection>,
    dragonfly_service: web::Data<Addr<DragonflyService>>,
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let oauth_client = services::oauth::Query::get_oauth_client_by_client_id(
        &db_conn,
        body.client_id.clone()
    )
        .await?;

    if let Some(oauth_client) = oauth_client {
        if body.response_type == OauthAuthorizeResponseType::Code && oauth_client.client_type == "public" {
            let conn_info = req.connection_info();

            let client_ip = conn_info.realip_remote_addr().map_or("", |v| v);

            let user_agent = req.headers().get("User-Agent").map_or("nothing", |v| v.to_str().unwrap());

            let auth_flow_data = AuthorizeCodeFlowData {
                request_timestamp: Utc::now().timestamp(),
                client_id: body.client_id.to_owned(),
                oauth_client_id: oauth_client.id,
                code_challenge: body.code_challenge.to_owned(),
                code_challenge_method: body.code_challenge_method.to_owned(),
                nonce: body.nonce.to_owned(),
                state: body.state.to_owned(),
                context: blake3::hash(format!("{client_ip}{user_agent}").as_bytes()).to_string(),
            };

            let request_id = nanoid::nanoid!(32);

            dragonfly_service.send(services::dragonfly::DragonflyCommand::Set(
                format!("oauth-auth-flow@{request_id}"),
                serde_json::to_string(&auth_flow_data).expect("fail to serialize auth flow data"),
                redis::SetOptions::default().with_expiration(redis::SetExpiry::EX(960))
            ))
                .await??;

            let auth_ui_url = &*AUTH_UI_URL;

            let redirect_url = format!("{auth_ui_url}/oauth/authorize?request_id={request_id}");

            return Ok(HttpResponse::Found()
                .insert_header((header::LOCATION, redirect_url))
                .finish());
        }
    }

    Ok(HttpResponse::BadRequest().finish())
}

async fn token(
    body: web::Form<TokenRequestDto>,
    db_conn: web::Data<sea_orm::DatabaseConnection>,
    dragonfly_service: web::Data<Addr<DragonflyService>>,
    jwt_secret: web::Data<&Lazy<(EncodingKey, DecodingKey)>>
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    match &body.grant_type {
        TokenGrantType::Refresh => todo!(),
        TokenGrantType::ClientCredentials => {
            if body.client_secret.is_some() {
                let oauth_client = services::oauth::Query::get_oauth_client_by_client_id(
                    &db_conn,
                    body.client_id.to_owned()
                )
                    .await?;

                if oauth_client.is_some() && oauth_client.as_ref().unwrap().client_secret == body.client_secret {
                    let oauth_client = oauth_client.unwrap();

                    let access_expiry_2_hour_as_sec = 7200;
                    let refresh_expiry_2_months_as_sec = 525600576;

                    let opts = GenerateOauthTokenOpts {
                        scope: vec![],
                        subject: None,
                        audience: oauth_client.audiences,
                        token_key: None,
                        access_token_expiry: access_expiry_2_hour_as_sec,
                        refresh_token_expiry: refresh_expiry_2_months_as_sec,
                    };

                    let token_resp = generate_oauth_token(opts, &jwt_secret.0)?;

                    return Ok(HttpResponse::Ok().json(token_resp));
                }
            }
        },
        TokenGrantType::AuthorizationCode => {
            if body.code_verifier.is_some() {
                let code = body.code.to_owned().unwrap();

                let consent_response = dragonfly_service.send(services::dragonfly::DragonflyCommand::Get(code))
                    .await??;

                if consent_response.is_none() {
                    return Ok(HttpResponse::Unauthorized().finish());
                }

                let consent_response = serde_json::from_str::<UserOauthConsentResponse>(consent_response.unwrap().as_str())
                    .expect("fail to parse user oauth consent response json");

                let auth_flow_data = dragonfly_service.send(services::dragonfly::DragonflyCommand::Get(consent_response.request_id.clone()))
                    .await??;

                if auth_flow_data.is_none() {
                    return Ok(HttpResponse::Unauthorized().finish());
                }

                let auth_flow_data = auth_flow_data.unwrap();

                let auth_flow_data = serde_json::from_str::<AuthorizeCodeFlowData>(&auth_flow_data)
                    .expect("fail to parse auth flow data json");

                let code_challenge = match auth_flow_data.code_challenge_method {
                    CodeChallengeMethod::S256 => {
                        let mut hasher = Sha256::new();
                        hasher.update(body.code_verifier.as_ref().unwrap());
                        let digest = hasher.finalize();

                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
                    },
                    CodeChallengeMethod::Blake3 => todo!(),
                };

                if code_challenge == auth_flow_data.code_challenge {
                    let access_expiry_16_min_as_sec = 480;
                    let refresh_expiry_4_weeks_as_sec = 2419200;

                    let opts = GenerateOauthTokenOpts {
                        scope: consent_response.scope,
                        subject: Some(consent_response.subject),
                        audience: consent_response.audience,
                        token_key: None,
                        access_token_expiry: access_expiry_16_min_as_sec,
                        refresh_token_expiry: refresh_expiry_4_weeks_as_sec,
                    };

                    let token_resp = generate_oauth_token(opts, &jwt_secret.0)?;

                    dragonfly_service.send(services::dragonfly::DragonflyCommand::Del(consent_response.request_id))
                        .await??;

                    return Ok(HttpResponse::Ok().json(token_resp));
                }
            }
        },
    }

    Ok(HttpResponse::Unauthorized().finish())
}

pub fn routes(cfg: &mut web::ServiceConfig) {
    tracing::info!("registering oauth routes");

    cfg.route("scopes", web::get().to(list_oauth_scope));

    cfg.route("clients", web::get().to(get_oauth_client));

    cfg.route("authorize", web::post().to(authorize));

    cfg.route("token", web::post().to(token));

    tracing::info!("oauth routes registered");
}

pub fn admin_routes(cfg: &mut web::ServiceConfig) {
    tracing::info!("registering oauth admin routes");

    cfg.route("delegable-user-permissions/:id", web::delete().to(remove_delegable_user_permission));
    cfg.route("delegable-user-permissions", web::get().to(list_delegable_user_permission));
    cfg.route("delegable-user-permissions", web::post().to(add_delegable_user_permission));

    cfg.route("scopes", web::get().to(list_oauth_scope));
    cfg.route("scopes", web::post().to(add_oauth_scope));
    cfg.route("scopes/{id}", web::delete().to(remove_oauth_scope));

    cfg.route("clients", web::post().to(add_oauth_client));
    cfg.route("clients", web::get().to(list_oauth_client));
    cfg.route("clients/{id}", web::delete().to(remove_oauth_client));

    tracing::info!("oauth admin routes registered");
}

fn generate_oauth_token(opts: GenerateOauthTokenOpts, jwt_secret: &EncodingKey) -> Result<TokenResponseDto, AppError> {
    let jwt_algo = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);

    let now = Utc::now();

    let expiry = now.add(Duration::seconds(opts.access_token_expiry as i64));

    let access_token_expires_in = expiry.sub(now).to_std().unwrap();

    let access_token = jsonwebtoken::encode(
        &jwt_algo,
        &JwtClaims{
            id: nanoid::nanoid!(32),
            sub: opts.subject.or(Some(Uuid::new_v4())).unwrap(),
            iat: now.timestamp() as usize,
            nbf: now.timestamp() as usize,
            exp: expiry.timestamp() as usize,
            typ: common::JwtType::OauthAccess,
            aud: opts.audience,
            iss: common::OAUTH_ISSUER_URL.to_string(),
            scope: opts.scope,
            ctx: None,
        },
        jwt_secret
    )?;

    let expiry = now.add(Duration::seconds(opts.refresh_token_expiry as i64));

    let refresh_token = jsonwebtoken::encode(
        &jwt_algo,
        &JwtClaims{
            id: nanoid::nanoid!(32),
            sub: opts.subject.or(Some(Uuid::new_v4())).unwrap(),
            iat: now.timestamp() as usize,
            nbf: now.timestamp() as usize,
            exp: expiry.timestamp() as usize,
            typ: common::JwtType::OauthRefresh,
            aud: vec![common::OAUTH_ISSUER_URL.to_string()],
            iss: common::OAUTH_ISSUER_URL.to_string(),
            scope: vec![],
            ctx: None,
        },
        jwt_secret
    )?;

    Ok(TokenResponseDto {
        expires_in: access_token_expires_in.as_secs(),
        token_type: "Bearer".to_string(),
        access_token: access_token,
        refresh_token: Some(refresh_token),
    })
}
