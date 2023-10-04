
use webauthn_rs::prelude::Passkey;
use models::{users_webauthn_credentials::{Entity as UserWebauthnCredential, self}, users};
use sea_orm::{DbErr, EntityTrait, DatabaseConnection, QueryFilter, QuerySelect, ColumnTrait, prelude::{Uuid, DateTimeWithTimeZone}, ActiveModelTrait, TransactionTrait};

pub struct Query;

pub struct Mutation;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct UserWebauthnCredData {
    pub id: i32,
    pub name: String,
    pub user_id: Uuid,
    pub credential_id: String,
    pub credential_data: serde_json::Value,
    pub created_at: DateTimeWithTimeZone,
}

impl From<users_webauthn_credentials::Model> for UserWebauthnCredData {
    fn from(value: users_webauthn_credentials::Model) -> Self {
        UserWebauthnCredData {
            id: value.id,
            name: value.name,
            user_id: value.user_id,
            credential_id: value.credential_id,
            created_at: value.created_at,
            credential_data: serde_json::from_value::<sea_orm::JsonValue>(value.credential_data).unwrap(),
        }
    }
}

impl Into<users_webauthn_credentials::Model> for UserWebauthnCredData {
    fn into(self) -> users_webauthn_credentials::Model {
        users_webauthn_credentials::Model {
            id: self.id,
            name: self.name,
            user_id: self.user_id,
            credential_id: self.credential_id,
            created_at: self.created_at,
            credential_data: serde_json::to_value(self.credential_data).unwrap(),
        }
    }
}

impl Query {
    pub async fn list_user_webauthn_cred(db: &DatabaseConnection, user_id: Uuid) -> Result<Vec<users_webauthn_credentials::Model>, DbErr> {
        UserWebauthnCredential::find()
        .filter(users_webauthn_credentials::Column::UserId.eq(user_id))
        .all(db)
        .await
    }
}

impl Mutation {
    pub async fn save_webauthn_credential(db: &DatabaseConnection, user_id: Uuid, passkey: Passkey, name: String) -> Result<users_webauthn_credentials::Model, DbErr> {
        users_webauthn_credentials::ActiveModel {
            user_id: sea_orm::ActiveValue::Set(user_id),
            name: sea_orm::ActiveValue::Set(name),
            credential_id: sea_orm::ActiveValue::Set(passkey.cred_id().to_string()),
            credential_data: sea_orm::ActiveValue::Set(serde_json::to_value(passkey).unwrap()),
            ..Default::default()
        }
        .insert(db)
        .await
    }

    pub async fn update_webauthn_credentials_counter(db: &DatabaseConnection, creds: Vec<(UserWebauthnCredData, Passkey)>) -> Result<bool, DbErr> {
        let res =
            db.transaction::<_, (), DbErr>(|txn: &sea_orm::DatabaseTransaction| {
                Box::pin(async move {
                    let updates =
                        creds
                        .iter()
                        .map(|(cred, psk)| {
                            let cred = users_webauthn_credentials::ActiveModel {
                                id: sea_orm::ActiveValue::Unchanged(cred.id),
                                name: sea_orm::ActiveValue::Unchanged(cred.name.clone()),
                                user_id: sea_orm::ActiveValue::Unchanged(cred.user_id),
                                credential_id: sea_orm::ActiveValue::Unchanged(cred.credential_id.clone()),
                                created_at: sea_orm::ActiveValue::Unchanged(cred.created_at),
                                credential_data: sea_orm::ActiveValue::Set(serde_json::to_value(psk).unwrap()),
                            };

                            cred.update(txn)
                        });

                    futures::future::join_all(updates).await;

                    Ok(())
                })
            }).await;

        if let Ok(_) = res {
            return Ok(true);
        }

        Ok(false)
    }
}
