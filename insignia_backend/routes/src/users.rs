
use models::user_info::UserInfoRespDto;
use sea_orm::prelude::Uuid;
use actix_web::{web, HttpResponse};

#[derive(serde::Deserialize)]
struct UserQueryDto {
    identifier: String,
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

pub fn routes(cfg: &mut web::ServiceConfig) {
    tracing::info!("registering users routes");

    cfg.service(
        web::resource("")
            .route(web::head().to(check_user))
            .route(web::post().to(create_user))
            .route(web::get().to(get_user_info))
    );

    tracing::info!("users routes registered");
}
