
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
    pub async fn save_setting(db: &DatabaseConnection, integration_callback_url: Option<String>, integration_callback_api_key: Option<String>) -> Result<settings::Model, DbErr> {
        let setting = Setting::find_by_id(1)
            .one(db)
            .await?;

        if let Some(setting) = setting {
            let mut setting = setting
                .into_active_model();

            setting.integration_callback_url = sea_orm::ActiveValue::Set(integration_callback_url);
            setting.integration_callback_api_key = sea_orm::ActiveValue::Set(integration_callback_api_key);

            return Ok(setting
                .save(db)
                .await?
                .try_into_model()?);
        }

        let setting = settings::ActiveModel {
            integration_callback_url: sea_orm::ActiveValue::Set(integration_callback_url),
            integration_callback_api_key: sea_orm::ActiveValue::Set(integration_callback_api_key),
            ..Default::default()
        };

        Ok(setting
            .save(db)
            .await?
            .try_into_model()?)
    }
}
