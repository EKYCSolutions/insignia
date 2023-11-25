
use actix_web::{web, HttpResponse};

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

use models::http_error::AppHttpErrorResponseDto;

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

pub fn routes(cfg: &mut web::ServiceConfig) {
    tracing::info!("registering oauth routes");

    cfg.route("scopes", web::get().to(list_oauth_scope));

    cfg.route("clients", web::get().to(get_oauth_client));

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
