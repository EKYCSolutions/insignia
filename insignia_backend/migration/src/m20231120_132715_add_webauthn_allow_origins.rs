use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(WebauthnAllowOrigin::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(WebauthnAllowOrigin::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(WebauthnAllowOrigin::Origin).string().unique_key().not_null())
                    .col(ColumnDef::new(WebauthnAllowOrigin::CreatedAt).timestamp_with_time_zone().default(Expr::current_timestamp()).not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(WebauthnAllowOrigin::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
#[iden(rename = "webauthn_allow_origins")]
enum WebauthnAllowOrigin {
    Table,
    Id,
    Origin,
    CreatedAt,
}
