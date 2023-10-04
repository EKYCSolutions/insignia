pub use sea_orm_migration::prelude::*;

mod m20220101_000001_create_table;
mod m20231003_163108_add_webauthn_cred_to_users;
mod m20231004_040957_add_phone_email_password_to_users;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20220101_000001_create_table::Migration),
            Box::new(m20231003_163108_add_webauthn_cred_to_users::Migration),
            Box::new(m20231004_040957_add_phone_email_password_to_users::Migration),
        ]
    }
}
