pub use sea_orm_migration::prelude::*;

mod m20220101_000001_create_table;
mod m20231003_163108_add_webauthn_cred_to_users;
mod m20231004_040957_add_phone_email_password_to_users;
mod m20231117_181909_add_wellknown_config_table;
mod m20231120_132715_add_webauthn_allow_origins;
mod m20231125_020513_add_users_permissions_model;
mod m20231125_020825_add_oauth_scopes_model;
mod m20231125_021216_add_oauth_client_model;
mod m20231125_021604_add_users_oauth_consents_model;
mod m20231126_092614_add_user_oauth_authorized_client_model;
mod m20231229_043646_add_app_settings_model_and_add_extras_meta_to_users;
mod m20231229_064648_add_webhook_on_user_successful_register_trigger;
mod m20240213_072533_add_phone_email_verified_hook;
mod m20240726_180448_periodically_remove_unsuccessful_register_user;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20220101_000001_create_table::Migration),
            Box::new(m20231003_163108_add_webauthn_cred_to_users::Migration),
            Box::new(m20231004_040957_add_phone_email_password_to_users::Migration),
            Box::new(m20231117_181909_add_wellknown_config_table::Migration),
            Box::new(m20231120_132715_add_webauthn_allow_origins::Migration),
            Box::new(m20231125_020513_add_users_permissions_model::Migration),
            Box::new(m20231125_020825_add_oauth_scopes_model::Migration),
            Box::new(m20231125_021216_add_oauth_client_model::Migration),
            Box::new(m20231125_021604_add_users_oauth_consents_model::Migration),
            Box::new(m20231126_092614_add_user_oauth_authorized_client_model::Migration),
            Box::new(m20231229_043646_add_app_settings_model_and_add_extras_meta_to_users::Migration),
            Box::new(m20231229_064648_add_webhook_on_user_successful_register_trigger::Migration),
            Box::new(m20240213_072533_add_phone_email_verified_hook::Migration),
            Box::new(m20240726_180448_periodically_remove_unsuccessful_register_user::Migration),
        ]
    }
}
