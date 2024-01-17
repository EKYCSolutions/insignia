
use std::str::FromStr;
use std::collections::HashMap;

use tonic::{Request, Response, Status};
use sea_orm::{prelude::Uuid, DatabaseConnection};

mod insignia_grpc {
    pub mod dev {
        pub mod insigniaoss {
            pub mod r#type {
                include!("../../grpc/dev.insigniaoss.r#type.rs");
            }

            pub mod service {
                pub mod v0 {
                    include!("../../grpc/dev.insigniaoss.service.v0.rs");
                }
            }
        }
    }
}

pub const INSIGINAOSS_INTEGRATION_V0_DESCRIPTOR: &[u8] = include_bytes!("../../grpc/insigniaoss-integration-v0-descriptor.bin");

use insignia_grpc::dev::insigniaoss::{r#type, service};

pub use service::v0::integration_service_server::IntegrationServiceServer;

pub struct IntegrationService {
    pub db_conn: DatabaseConnection,
}

#[tonic::async_trait]
impl service::v0::integration_service_server::IntegrationService for IntegrationService {
    async fn get_user_info(&self, request: Request<service::v0::GetUserInfoReq>) -> Result<Response<r#type::User>, Status> {
        let req_args: service::v0::GetUserInfoReq = request.into_inner();

        if let Ok(user_id) = Uuid::from_str(req_args.user_id.as_str()) {
            if let Ok(user) = super::user::Query::get_user_info_by_id(&self.db_conn, user_id).await {
                if user.len() > 0 {
                    let user = user[0].0.to_owned();

                    return Ok(Response::new(r#type::User {
                        id: user.id.to_string(),
                        name: user.name,
                        email: user.email,
                        phone: user.phone,
                        extras_meta: user.extras_meta.map_or(
                            HashMap::new(),
                            |d| HashMap::from_iter(
                                d
                                    .as_object()
                                    .unwrap()
                                    .iter()
                                    .map(|(k, v)| {
                                        (k.clone(), v.to_string())
                                    })
                            )
                        ),
                    }));
                }
            }
        }

        Err(Status::not_found(""))
    }

    async fn validate_user_context(&self, _request: Request<service::v0::ValidateUserContextReq>) -> Result<Response<service::v0::UserContext>, Status> {
        todo!()
    }
}
