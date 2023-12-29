
use actix_web::{web, HttpResponse};

use models::http_error::AppHttpErrorResponseDto;

#[derive(serde::Deserialize)]
struct SaveSettingRequestBodyDto {
    integration_callback_url: Option<String>,
    integration_callback_api_key: Option<String>,
}

async fn save_setting(
    db: web::Data<sea_orm::DatabaseConnection>,
    body: web::Json<SaveSettingRequestBodyDto>
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    services::setting::Mutation::save_setting(
        &db,
        body.integration_callback_url.to_owned(),
        body.integration_callback_api_key.to_owned()
    )
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

async fn get_setting(db: web::Data<sea_orm::DatabaseConnection>) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let setting = services::setting::Query::get_setting(&db)
        .await?;

    if let Some(setting) = setting {
        return Ok(HttpResponse::Ok().json(setting));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({})))
}

pub fn admin_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_setting));
    cfg.route("", web::patch().to(save_setting));
}
