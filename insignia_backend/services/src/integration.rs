use std::collections::HashMap;
use std::str::FromStr;

use chrono::DateTime;
use sea_orm::{prelude::Uuid, DatabaseConnection};
use tonic::{Request, Response, Status};

mod insignia_grpc {
    pub mod dev {
        pub mod insigniaoss {
            pub mod r#type {
                tonic::include_proto!("dev.insigniaoss.r#type");
            }

            pub mod service {
                pub mod v0 {
                    tonic::include_proto!("dev.insigniaoss.service.v0");
                }
            }
        }
    }
}

pub const INSIGINAOSS_INTEGRATION_V0_DESCRIPTOR: &[u8] =
    tonic::include_file_descriptor_set!("insignia_integration_service_descriptor");

pub use insignia_grpc::dev::insigniaoss;

pub struct IntegrationService {
    pub db_conn: DatabaseConnection,
    pub jwt_encoding_key: jsonwebtoken::EncodingKey,
    pub jwt_decoding_key: jsonwebtoken::DecodingKey,
}

#[tonic::async_trait]
impl insigniaoss::service::v0::integration_service_server::IntegrationService for IntegrationService {
    async fn get_user_info(
        &self,
        request: Request<insigniaoss::service::v0::GetUserInfoReq>,
    ) -> Result<Response<insigniaoss::r#type::User>, Status> {
        let req_args: insigniaoss::service::v0::GetUserInfoReq = request.into_inner();

        if let Ok(user_id) = Uuid::from_str(req_args.user_id.as_str()) {
            if let Ok(user) = super::user::Query::get_user_info_by_id(&self.db_conn, user_id).await
            {
                if user.len() > 0 {
                    let user = user[0].0.to_owned();

                    return Ok(Response::new(insigniaoss::r#type::User {
                        id: user.id.to_string(),
                        name: user.name,
                        email: user.email,
                        phone: user.phone,
                        extras_meta: user.extras_meta.map_or(HashMap::new(), |d| {
                            HashMap::from_iter(
                                d.as_object()
                                    .unwrap()
                                    .iter()
                                    .map(|(k, v)| (k.clone(), v.to_string())),
                            )
                        }),
                    }));
                }
            }
        }

        Err(Status::not_found(""))
    }

    async fn validate_user_context(
        &self,
        request: Request<insigniaoss::service::v0::ValidateUserContextReq>,
    ) -> Result<Response<insigniaoss::service::v0::UserContext>, Status> {
        let req_args: insigniaoss::service::v0::ValidateUserContextReq = request.into_inner();

        let (_, _, _, fgp_cookie_name) = *common::SESSION_COOKIE_SETTING;

        let decode_access_token = jsonwebtoken::decode::<common::JwtClaims>(
            req_args.access_token.as_str(),
            &self.jwt_decoding_key,
            &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA),
        );

        let get_fgp_cookie = req_args.req_headers.get("cookie").and_then(|cookies| {
            cookies
                .split(';')
                .find(|cookie| cookie.split('=').next().unwrap() == fgp_cookie_name)
                .and_then(|cookie| cookie.split('=').nth(1))
        });

        match (decode_access_token, get_fgp_cookie) {
            (Ok(jsonwebtoken::TokenData { claims, header: _ }), Some(fgp)) => {
                if let Ok(user) =
                    super::user::Query::get_user_info_by_id(&self.db_conn, claims.sub).await
                {
                    let mut header_value = awc::http::header::HeaderMap::new();

                    for (k, v) in req_args.req_headers.iter() {
                        header_value.append(
                            awc::http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                            awc::http::header::HeaderValue::from_str(v).unwrap(),
                        );
                    }

                    let token_ctx = common::build_token_context(
                        &user[0].0,
                        &header_value,
                        fgp,
                        &DateTime::from_timestamp(claims.iat as i64, 0).unwrap(),
                        &DateTime::from_timestamp(claims.exp as i64, 0).unwrap(),
                    );

                    let user = user[0].0.to_owned();

                    Ok(Response::new(insigniaoss::service::v0::UserContext {
                        user: Some(insigniaoss::r#type::User {
                            id: user.id.to_string(),
                            name: user.name,
                            email: user.email,
                            phone: user.phone,
                            extras_meta: user.extras_meta.map_or(HashMap::new(), |d| {
                                HashMap::from_iter(
                                    d.as_object()
                                        .unwrap()
                                        .iter()
                                        .map(|(k, v)| (k.clone(), v.to_string())),
                                )
                            }),
                        }),
                        is_session_valid: claims.typ == common::JwtType::Login
                            && claims.ctx.unwrap() == token_ctx,
                    }))
                } else {
                    Err(Status::unauthenticated(""))
                }
            }

            _ => Err(Status::unauthenticated("")),
        }
    }
}
