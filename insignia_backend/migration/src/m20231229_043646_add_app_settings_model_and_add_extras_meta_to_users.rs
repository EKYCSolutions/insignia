use sea_orm_migration::prelude::*;

use crate::m20220101_000001_create_table::User;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Setting::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Setting::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Setting::IntegrationCallbackUrl).string().null())
                    .col(ColumnDef::new(Setting::IntegrationCallbackApiKey).string().null())
                    .col(ColumnDef::new(Setting::CreatedAt).timestamp_with_time_zone().default(Expr::current_timestamp()).not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .add_column(
                        ColumnDef::new(Alias::new("extras_meta"))
                            .json_binary()
                            .null()
                            .default(Expr::val("{}").cast_as(Alias::new("jsonb")))
                    )
                    .to_owned()
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Setting::Table).to_owned())
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .drop_column(Alias::new("extras_meta"))
                    .to_owned()
            )
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
#[iden(rename = "settings")]
enum Setting {
    Table,
    Id,
    IntegrationCallbackUrl,
    IntegrationCallbackApiKey,
    CreatedAt,
}
