
use std::{pin::Pin, str::FromStr};

use futures_util::Future;
use once_cell::sync::Lazy;
use sea_orm::prelude::Uuid;
use chrono::{DateTime, Utc, NaiveDateTime};
use jsonwebtoken::{EncodingKey, DecodingKey, TokenData};
use actix_web::{http::{Error, header::HeaderMap}, FromRequest};

use models::users;

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum JwtType {
    Login,
    Refresh,
    OauthAccess,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct JwtClaims {
    pub id: String,
    pub iat: usize,
    pub nbf: usize,
    pub exp: usize,
    pub aud: String,
    pub iss: String,
    pub sub: String,
    pub typ: JwtType,
    pub ctx: Option<String>,
    pub scope: Option<String>
}

pub struct UserContext {
    pub is_jwt_verified: bool,
    pub user: Option<users::Model>,
}

impl FromRequest for UserContext {
    type Error = Error;

    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload
    ) -> Self::Future {
        if let Some(fgp) = req.cookie("fgp") {
            if let Some(token_value) = req.headers().get("authorization") {
                if token_value.to_str().unwrap().contains("Bearer ") {
                    let token_value = token_value.to_str().unwrap().split("Bearer ").collect::<Vec<&str>>()[1];

                    let key =
                        req
                        .app_data::<actix_web::web::Data<&Lazy<(EncodingKey, DecodingKey)>>>()
                        .expect("fail to get jwt secret key for user context");

                    if let Ok(TokenData{ claims, header: _ }) = jsonwebtoken::decode::<JwtClaims>(
                        token_value,
                        &key.1,
                        &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA)
                    ) {
                        let db_conn = req.app_data::<actix_web::web::Data<sea_orm::DatabaseConnection>>().unwrap().clone();

                        let headers = req.headers().clone();

                        return Box::pin(async move {
                            let user = services::user::Query::get_user_info_by_id(
                                &db_conn,
                                Uuid::from_str(&claims.sub).unwrap()
                            ).await.unwrap();

                            let token_ctx = build_token_context(
                                &user[0].0,
                                &headers,
                                fgp.value(),
                                &DateTime::<Utc>::from_naive_utc_and_offset(NaiveDateTime::from_timestamp_opt(claims.iat as i64, 0).unwrap(), Utc),
                                &DateTime::<Utc>::from_naive_utc_and_offset(NaiveDateTime::from_timestamp_opt(claims.exp as i64, 0).unwrap(), Utc)
                            );

                            Ok(UserContext {
                                user: Some(user[0].0.to_owned()),
                                is_jwt_verified: claims.typ == JwtType::Login && claims.ctx.unwrap() == token_ctx,
                            })
                        });
                    }
                }
            }
        }

        Box::pin(async move {
            Ok(UserContext { user: None, is_jwt_verified: false })
        })
    }
}

pub fn build_token_context(
    user: &users::Model,
    headers: &HeaderMap,
    fgp: &str,
    t_iat: &DateTime<Utc>,
    t_exp: &DateTime<Utc>
) -> String {
    let user_agent = headers.get("User-Agent").map_or("abcdefgh", |v| v.to_str().unwrap());

    let random_num = t_iat.timestamp() + t_exp.timestamp();

    blake3::Hasher::new()
    .update(fgp.as_bytes())
    .update(user_agent.as_bytes())
    .update(random_num.to_string().as_bytes())
    .update(user.session_data.clone().as_bytes())
    .finalize()
    .to_string()
}
