
use actix_web::{HttpResponse, web};

use models::http_error::AppHttpErrorResponseDto;

#[derive(serde::Deserialize)]
pub struct AddWebauthnAllowOriginRequestBodyDto {
    origin: String,
}

#[derive(serde::Deserialize)]
pub struct RemoveWebauthnOriginRequestParamDto {
    id: i32,
}

pub async fn list_webauthn_allow_origin(
    db_conn: web::Data<sea_orm::DatabaseConnection>,
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let allowed_origins = services::config::Query::list_webauthn_allow_origin(&db_conn)
        .await?;

    Ok(HttpResponse::Ok().json(allowed_origins))
}

pub async fn add_webauthn_allow_origin(
    body: web::Json<AddWebauthnAllowOriginRequestBodyDto>,
    db_conn: web::Data<sea_orm::DatabaseConnection>
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    services::config::Mutation::add_webauthn_allow_origin(&db_conn, body.origin.to_owned())
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

pub async fn remove_webauthn_allow_origin(
    path_params: web::Path<RemoveWebauthnOriginRequestParamDto>,
    db_conn: web::Data<sea_orm::DatabaseConnection>
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    services::config::Mutation::remove_webauthn_allow_origin(&db_conn, path_params.id)
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

pub fn admin_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(list_webauthn_allow_origin));
    cfg.route("", web::post().to(add_webauthn_allow_origin));
    cfg.route("/{id}", web::delete().to(remove_webauthn_allow_origin));
}
