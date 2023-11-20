
use models::webauthn_allow_origins;
use sea_orm::{DbErr, DatabaseConnection, ActiveModelTrait, EntityTrait, IntoActiveModel};

pub struct Query;

pub struct Mutation;

impl Query {
    pub async fn list_webauthn_allow_origin(db: &DatabaseConnection) -> Result<Vec<webauthn_allow_origins::Model>, DbErr> {
        let res = webauthn_allow_origins::Entity::find()
            .all(db)
            .await?;

        Ok(res)
    }
}

impl Mutation {
    pub async fn add_webauthn_allow_origin(db: &DatabaseConnection, origin: String) -> Result<(), DbErr> {
        let webauthn_allow_origin = webauthn_allow_origins::ActiveModel {
            origin: sea_orm::ActiveValue::Set(origin),
            ..Default::default()
        };

        webauthn_allow_origin
            .insert(db)
            .await?;

        Ok(())
    }

    pub async fn remove_webauthn_allow_origin(db: &DatabaseConnection, id: i32) -> Result<(), DbErr> {
        let webauthn_allow_origin = webauthn_allow_origins::Entity::find_by_id(id)
            .one(db)
            .await?;

        if let Some(webauthn_allow_origin) = webauthn_allow_origin {
            let active_model = webauthn_allow_origin.into_active_model();

            active_model
                .delete(db)
                .await?;
        }

        Ok(())
    }
}
