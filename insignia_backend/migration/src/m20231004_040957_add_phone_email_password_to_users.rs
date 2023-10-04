use sea_orm_migration::prelude::*;

use crate::m20220101_000001_create_table::User;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .add_column(
                        ColumnDef::new(Alias::new("password"))
                            .text()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("phone"))
                            .text()
                            .unique_key()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("email"))
                            .text()
                            .unique_key()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("phone_verified_at"))
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("email_verified_at"))
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("twofa_enabled_at"))
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .drop_column(Alias::new("password"))
                    .drop_column(Alias::new("phone"))
                    .drop_column(Alias::new("email"))
                    .drop_column(Alias::new("phone_verified_at"))
                    .drop_column(Alias::new("email_verified_at"))
                    .drop_column(Alias::new("twofa_enabled_at"))
                    .to_owned(),
            )
            .await
    }
}
