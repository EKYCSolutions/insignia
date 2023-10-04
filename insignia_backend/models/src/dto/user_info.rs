
use sea_orm::prelude::{DateTimeWithTimeZone, Uuid};

use crate::{users, users_webauthn_credentials};

#[derive(serde::Serialize)]
pub struct WebauthnCredentialRespDto {
    pub id: i32,
}

#[derive(serde::Serialize)]
pub struct UserInfoRespDto {
    pub id: Uuid,
    pub created_at: DateTimeWithTimeZone,
    pub webauthn_credentials: Vec<WebauthnCredentialRespDto>,
}

#[derive(serde::Serialize)]
pub struct UserSessionRespDto {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTimeWithTimeZone,
}

impl From<(users::Model, Vec<users_webauthn_credentials::Model>)> for UserInfoRespDto {
    fn from((u, w_creds): (users::Model, Vec<users_webauthn_credentials::Model>)) -> Self {
        UserInfoRespDto {
            id: u.id,
            created_at: u.created_at,
            webauthn_credentials:
                w_creds
                .iter()
                .map(|w_cred| {
                    WebauthnCredentialRespDto {
                        id: w_cred.id,
                    }
                })
                .collect()
        }
    }
}

impl From<users::Model> for UserSessionRespDto {
    fn from(u: users::Model) -> Self {
        UserSessionRespDto {
            id: u.id,
            name: u.name,
            created_at: u.created_at,
        }
    }
}
