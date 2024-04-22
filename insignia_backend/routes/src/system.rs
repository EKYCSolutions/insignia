
use actix::Addr;
use actix_web::{HttpResponse, web};

use services::dragonfly::DragonflyService;
use models::http_error::AppHttpErrorResponseDto;
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

async fn healthz(
    db_conn: web::Data<sea_orm::DatabaseConnection>,
    dragonfly_service: web::Data<Addr<DragonflyService>>,
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let db_select_result = db_conn
        .as_ref()
        .execute(
            Statement::from_string(DatabaseBackend::Postgres, "select count(*) from pg_stat_wal_receiver")
        )
        .await?;

    let redis_set_result = dragonfly_service.send(services::dragonfly::DragonflyCommand::Ping)
        .await??;

    if redis_set_result.is_none() || db_select_result.rows_affected() != 1 {
        return Ok(HttpResponse::ServiceUnavailable()
            .finish());
    }

    Ok(HttpResponse::NoContent().finish())
}

pub fn routes(cfg: &mut web::ServiceConfig) {
    tracing::info!("registering system routes");

    cfg.route("", web::get().to(healthz));

    tracing::info!("system routes registered");
}
