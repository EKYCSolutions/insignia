
use sea_orm::{EntityTrait, ActiveModelTrait, TryIntoModel};
use actix_web::{web, HttpResponse};
use models::well_known_configs::{Entity as WellKnownConfig, self};

#[derive(serde::Deserialize)]
struct UpdateWellKnownConfigDto {
    apple_app_site_association_ios_app_ids: Vec<String>,
    assetlink_android_package_name: String,
    assetlink_android_sha256_fingerprints: Vec<String>,
}

async fn apple_app_site_association(
    db_conn:  web::Data<sea_orm::DatabaseConnection>
) -> HttpResponse {
    let well_known_config = WellKnownConfig::find()
        .one(db_conn.as_ref())
        .await
        .expect("fail to get well known config")
        .expect("fail to find well known config");

    HttpResponse::Ok()
        .json(serde_json::json!({
            "appclips": {"apps": []},
            "applinks": {
                "details": well_known_config.apple_app_site_association_ios_app_ids
                    .iter()
                    .map(|app_id| {
                        serde_json::json!({
                            "appId": app_id,
                            "paths": ["*"]
                        })
                    })
                    .collect::<Vec<serde_json::Value>>()
            },
            "webcredentials": {
                "apps": well_known_config.apple_app_site_association_ios_app_ids
            }
        }))
}

async fn google_assetlinks(
    db_conn:  web::Data<sea_orm::DatabaseConnection>
) -> HttpResponse {
    let well_known_config = WellKnownConfig::find()
        .one(db_conn.as_ref())
        .await
        .expect("fail to get well known config")
        .expect("fail to find well known config");

    HttpResponse::Ok()
        .json(serde_json::json!([{
            "relation": [
                "delegate_permission/common.handle_all_urls",
                "delegate_permission/common.get_login_creds"
            ],
            "target": {
                "namespace": "android_app",
                "package_name": well_known_config.assetlink_android_package_name,
                "sha256_cert_fingerprints": well_known_config.assetlink_android_sha256_fingerprints
            }
        }, {
            "relation": [
                "delegate_permission/common.handle_all_urls",
                "delegate_permission/common.get_login_creds"
            ],
            "target": {
                "namespace": "web",
                "site": "",
                "sha256_cert_fingerprints": None::<String>,
            }
        }]))
}

async fn get_well_known_config(
    db_conn:  web::Data<sea_orm::DatabaseConnection>
) -> HttpResponse {
    let well_known_config = WellKnownConfig::find()
        .one(db_conn.as_ref())
        .await
        .expect("fail to get well known config");

    if let Some(val) = well_known_config {
        return HttpResponse::Ok()
            .json(val);
    }

    HttpResponse::NotFound()
        .finish()
}

async fn update_well_known_config(
    body: web::Json<UpdateWellKnownConfigDto>,
    db_conn:  web::Data<sea_orm::DatabaseConnection>
) -> HttpResponse {
    let well_known_config = WellKnownConfig::find()
        .one(db_conn.as_ref())
        .await
        .expect("fail to get well known config");

    let mut well_known_config_model = None;

    if let Some(val) = well_known_config {
        well_known_config_model = Some(val.into());
    } else {
        well_known_config_model = Some(well_known_configs::ActiveModel {
            ..Default::default()
        });
    }

    let model = well_known_config_model
        .as_mut()
        .unwrap();

    model.assetlink_android_package_name = sea_orm::ActiveValue::Set(Some(body.assetlink_android_package_name.to_owned()));
    model.assetlink_android_sha256_fingerprints = sea_orm::ActiveValue::Set(body.assetlink_android_sha256_fingerprints.to_owned());
    model.apple_app_site_association_ios_app_ids = sea_orm::ActiveValue::Set(body.apple_app_site_association_ios_app_ids.to_owned());

    let result = model
        .to_owned()
        .save(db_conn.as_ref())
        .await
        .expect("fail to update well known config");

    let result = result
        .try_into_model()
        .expect("fail to convert well known config to model");

    HttpResponse::Ok()
        .json(result)
}

pub fn admin_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_well_known_config));
    cfg.route("", web::patch().to(update_well_known_config));
}

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.route("assetlinks.json", web::get().to(google_assetlinks));
    cfg.route("apple-app-site-association", web::get().to(apple_app_site_association));
}
