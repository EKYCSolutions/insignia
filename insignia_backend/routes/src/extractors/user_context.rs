
use std::{pin::Pin, str::FromStr};

use futures_util::Future;
use once_cell::sync::Lazy;
use sea_orm::prelude::Uuid;
use actix_web::{FromRequest, http::Error};
use chrono::{DateTime, Utc, NaiveDateTime};
use jsonwebtoken::{EncodingKey, DecodingKey, TokenData};

use models::{users, users_webauthn_credentials};
use common::{JwtClaims, build_token_context, JwtType, SESSION_COOKIE_SETTING};

pub struct UserContext {
    pub is_jwt_verified: bool,
    pub user: Option<users::Model>,
    pub webauthn_credentials: Vec<users_webauthn_credentials::Model>,
}

impl FromRequest for UserContext {
    type Error = Error;

    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload
    ) -> Self::Future {
        let (_, _, _, fgp_cookie_name) = *SESSION_COOKIE_SETTING;

        let auth_data =
            match (req.cookie(fgp_cookie_name), req.headers().get("authorization")) {
                (Some(fgp), Some(token_value)) => {
                    let token_value = token_value.to_str().unwrap().replace("Bearer ", "");

                    let key =
                        req
                        .app_data::<actix_web::web::Data<&Lazy<(EncodingKey, DecodingKey)>>>()
                        .expect("fail to get jwt secret key for user context");

                    if let Ok(TokenData{ claims, header: _ }) = jsonwebtoken::decode::<JwtClaims>(
                        &token_value,
                        &key.1,
                        &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA)
                    ) {
                        Some((fgp, claims))
                    } else {
                        None
                    }
                }
                _ => None,
            };

        if auth_data.is_some() {
            let (fgp, claims) = auth_data.unwrap();

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
                    webauthn_credentials: user[0].1.to_owned(),
                    is_jwt_verified: claims.typ == JwtType::Login && claims.ctx.unwrap() == token_ctx,
                })
            });
        }

        Box::pin(async move {
            Ok(UserContext { user: None, webauthn_credentials: vec![], is_jwt_verified: false })
        })
    }
}
