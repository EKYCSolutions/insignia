
use once_cell::sync::Lazy;
use actix_web::{web, HttpResponse};
use sea_orm::{EntityTrait, ActiveModelTrait, TryIntoModel};
use models::{well_known_configs::{Entity as WellKnownConfig, self}, http_error::AppHttpErrorResponseDto};
use openidconnect::{
    Scope,
    AuthUrl,
    TokenUrl,
    IssuerUrl,
    UserInfoUrl,
    ResponseTypes,
    JsonWebKeySetUrl,
    PrivateSigningKey,
    EmptyAdditionalProviderMetadata,
    core::{
        CoreClaimName,
        CoreJsonWebKey,
        CoreResponseType,
        CoreProviderMetadata,
        CoreJwsSigningAlgorithm,
        CoreSubjectIdentifierType,
        CoreEdDsaPrivateSigningKey,
    },
};

#[derive(serde::Deserialize)]
struct UpdateWellKnownConfigDto {
    apple_app_site_association_ios_app_ids: Vec<String>,
    assetlink_android_package_name: String,
    assetlink_android_sha256_fingerprints: Vec<String>,
}

async fn apple_app_site_association(
    db_conn:  web::Data<sea_orm::DatabaseConnection>
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let well_known_config = WellKnownConfig::find()
        .one(db_conn.as_ref())
        .await?;

    let app_ids = well_known_config
        .map_or(vec![], |c| c.apple_app_site_association_ios_app_ids);

    Ok(HttpResponse::Ok()
        .json(serde_json::json!({
            "appclips": {"apps": []},
            "applinks": {
                "details": app_ids
                    .iter()
                    .map(|app_id| {
                        serde_json::json!({
                            "appID": app_id,
                            "components": [{
                                "/": "*",
                                "?": "*",
                                "#": "*"
                            }]
                        })
                    })
                    .collect::<Vec<serde_json::Value>>()
            },
            "webcredentials": {
                "apps": app_ids
            }
        })))
}

async fn google_assetlinks(
    db_conn:  web::Data<sea_orm::DatabaseConnection>
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let well_known_config = WellKnownConfig::find()
        .one(db_conn.as_ref())
        .await?;

    let android_package_name = well_known_config
        .as_ref()
        .map_or(None, |c| c.assetlink_android_package_name.to_owned());

    let android_sha256_cert_fingerprints = well_known_config
        .map_or(vec![], |c| c.assetlink_android_sha256_fingerprints);

    Ok(HttpResponse::Ok()
        .json(serde_json::json!([{
            "relation": [
                "delegate_permission/common.handle_all_urls",
                "delegate_permission/common.get_login_creds"
            ],
            "target": {
                "namespace": "android_app",
                "package_name": android_package_name,
                "sha256_cert_fingerprints": android_sha256_cert_fingerprints
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
        }])))
}

async fn get_well_known_config(
    db_conn:  web::Data<sea_orm::DatabaseConnection>
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let well_known_config = WellKnownConfig::find()
        .one(db_conn.as_ref())
        .await?;

    if let Some(val) = well_known_config {
        return Ok(
            HttpResponse::Ok()
                .json(val)
        );
    }

    Ok(
        HttpResponse::NotFound()
        .finish()
    )
}

async fn update_well_known_config(
    body: web::Json<UpdateWellKnownConfigDto>,
    db_conn:  web::Data<sea_orm::DatabaseConnection>
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let well_known_config = WellKnownConfig::find()
        .one(db_conn.as_ref())
        .await?;

    let well_known_config_model =
        if let Some(val) = well_known_config {
            val.into()
        } else {
            well_known_configs::ActiveModel {
                ..Default::default()
            }
        };

    let mut model = well_known_config_model;

    model.assetlink_android_package_name = sea_orm::ActiveValue::Set(Some(body.assetlink_android_package_name.to_owned()));
    model.assetlink_android_sha256_fingerprints = sea_orm::ActiveValue::Set(body.assetlink_android_sha256_fingerprints.to_owned());
    model.apple_app_site_association_ios_app_ids = sea_orm::ActiveValue::Set(body.apple_app_site_association_ios_app_ids.to_owned());

    let result = model
        .to_owned()
        .save(db_conn.as_ref())
        .await?;

    let result = result
        .try_into_model()?;

    Ok(
        HttpResponse::Ok()
            .json(result)
    )
}

static JWK_CONFIG: Lazy<Vec<CoreJsonWebKey>> = Lazy::new(|| {
    vec![
        CoreEdDsaPrivateSigningKey::from_ed25519_pem(
            &std::fs::read_to_string("./jwt-secret.pem").expect("fail to read jwt-secret.pem"),
            None
        )
            .expect("fail to read ed25519 key")
            .as_verification_key()
    ]
});

async fn oidc_discovery(
    db_conn: web::Data<sea_orm::DatabaseConnection>
) -> Result<HttpResponse, AppHttpErrorResponseDto> {
    let issuer_url = &*common::OAUTH_ISSUER_URL;

    let mut scopes_supported = vec![
        Scope::new("openid".to_string()),
        Scope::new("profile".to_string()),
    ];

    let oauth_scopes = services::oauth::Query::list_oauth_scopes(&db_conn)
        .await?;

    for oas in oauth_scopes {
        scopes_supported.push(Scope::new(oas.name));
    }

    let config = CoreProviderMetadata::new(
        IssuerUrl::new(issuer_url.clone()).unwrap(),
        AuthUrl::new(format!("{issuer_url}/oauth/authorize")).unwrap(),
        JsonWebKeySetUrl::new(format!("{issuer_url}/oauth/jwk")).unwrap(),
        vec![
            ResponseTypes::new(vec![CoreResponseType::Code]),
        ],
        vec![CoreSubjectIdentifierType::Pairwise],
        vec![CoreJwsSigningAlgorithm::EdDsaEd25519],
        EmptyAdditionalProviderMetadata{},
    )
        .set_token_endpoint(Some(TokenUrl::new(format!("{issuer_url}/oauth/token")).unwrap()))
        .set_userinfo_endpoint(Some(UserInfoUrl::new(format!("{issuer_url}/oauth/userinfo")).unwrap()))
        .set_scopes_supported(Some(scopes_supported))
        .set_claims_supported(Some(vec![
            CoreClaimName::new("sub".to_string()),
            CoreClaimName::new("aud".to_string()),
            CoreClaimName::new("email".to_string()),
            CoreClaimName::new("email_verified_at".to_string()),
            CoreClaimName::new("phone".to_string()),
            CoreClaimName::new("phone_verified_at".to_string()),
            CoreClaimName::new("exp".to_string()),
            CoreClaimName::new("iat".to_string()),
            CoreClaimName::new("iss".to_string()),
            CoreClaimName::new("username".to_string()),
        ]));

    Ok(HttpResponse::Ok().json(config))
}

async fn jwk_config() -> HttpResponse {
    HttpResponse::Ok()
        .json(&*JWK_CONFIG)
}

pub fn admin_routes(cfg: &mut web::ServiceConfig) {
    tracing::info!("registering well known config admin routes");

    cfg.route("", web::get().to(get_well_known_config));
    cfg.route("", web::patch().to(update_well_known_config));

    tracing::info!("well known config admin registered");
}

pub fn routes(cfg: &mut web::ServiceConfig) {
    tracing::info!("registering well known config routes");

    cfg.route("assetlinks.json", web::get().to(google_assetlinks));
    cfg.route("apple-app-site-association", web::get().to(apple_app_site_association));

    cfg.route("oauth/jwk", web::get().to(jwk_config));
    cfg.route("oauth/openid-configuration", web::get().to(oidc_discovery));

    tracing::info!("well known config routes registered");
}
