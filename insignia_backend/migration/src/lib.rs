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
        ]
    }
}
