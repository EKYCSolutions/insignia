
use sea_orm::{DbErr, DatabaseConnection, EntityTrait, ActiveModelTrait, TryIntoModel, IntoActiveModel};

use models::{self, settings::{Entity as Setting, self}};

pub struct Query;

pub struct Mutation;

impl Query {
    pub async fn get_setting(db: &DatabaseConnection) -> Result<Option<settings::Model>, DbErr> {
        Ok(Setting::find_by_id(1)
            .one(db)
            .await?)
    }
}

impl Mutation {
    pub async fn save_setting(db: &DatabaseConnection, webhook_receiver_url: Option<String>, webhook_receiver_api_key: Option<String>) -> Result<settings::Model, DbErr> {
        let setting = Setting::find_by_id(1)
            .one(db)
            .await?;

        if let Some(setting) = setting {
            let mut setting = setting
                .into_active_model();

            setting.webhook_receiver_url = sea_orm::ActiveValue::Set(webhook_receiver_url);
            setting.webhook_receiver_api_key = sea_orm::ActiveValue::Set(webhook_receiver_api_key);

            return Ok(setting
                .save(db)
                .await?
                .try_into_model()?);
        }

        let setting = settings::ActiveModel {
            webhook_receiver_url: sea_orm::ActiveValue::Set(webhook_receiver_url),
            webhook_receiver_api_key: sea_orm::ActiveValue::Set(webhook_receiver_api_key),
            ..Default::default()
        };

        Ok(setting
            .save(db)
            .await?
            .try_into_model()?)
    }
}
