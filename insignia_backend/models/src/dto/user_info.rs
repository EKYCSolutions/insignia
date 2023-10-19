
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
    pub is_has_password: bool,
    pub is_phone_verified: bool,
    pub is_email_verified: bool,
    pub webauthn_credentials: Vec<WebauthnCredentialRespDto>,
}

#[derive(serde::Serialize)]
pub struct UserSessionRespDto {
    pub id: Uuid,
    pub name: String,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub is_has_password: bool,
    pub email_verified_at: Option<DateTimeWithTimeZone>,
    pub phone_verified_at: Option<DateTimeWithTimeZone>,
    pub created_at: DateTimeWithTimeZone,
}

impl From<(users::Model, Vec<users_webauthn_credentials::Model>)> for UserInfoRespDto {
    fn from((u, w_creds): (users::Model, Vec<users_webauthn_credentials::Model>)) -> Self {
        UserInfoRespDto {
            id: u.id,
            created_at: u.created_at,
            is_has_password: u.password.is_some(),
            is_email_verified: u.email_verified_at.is_some(),
            is_phone_verified: u.phone_verified_at.is_some(),
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
            phone: u.phone,
            email: u.email,
            email_verified_at: u.email_verified_at,
            phone_verified_at: u.phone_verified_at,
            is_has_password: u.password.is_some(),
            created_at: u.created_at,
        }
    }
}
