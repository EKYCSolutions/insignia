use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(WellKnownConfig::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(WellKnownConfig::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(WellKnownConfig::IOSAppIds).array(ColumnType::String(Some(64))).not_null())
                    .col(ColumnDef::new(WellKnownConfig::AndroidPackageName).string().null())
                    .col(ColumnDef::new(WellKnownConfig::AndroidSha256Fingerprints).array(ColumnType::Text).not_null())
                    .col(ColumnDef::new(WellKnownConfig::OpenidIssuerUrl).string().null())
                    .col(ColumnDef::new(WellKnownConfig::OpenidAuthorizeUrl).string().null())
                    .col(ColumnDef::new(WellKnownConfig::OpenidJwkUrl).string().null())
                    .col(ColumnDef::new(WellKnownConfig::OpenidTokenEndpoint).string().null())
                    .col(ColumnDef::new(WellKnownConfig::OpenidUserInfoEndpoint).string().null())
                    .col(ColumnDef::new(WellKnownConfig::CreatedAt).timestamp_with_time_zone().default(Expr::current_timestamp()).not_null())
                    .col(ColumnDef::new(WellKnownConfig::UpdatedAt).timestamp_with_time_zone().default(Expr::current_timestamp()).not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(WellKnownConfig::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
#[iden(rename = "well_known_configs")]
enum WellKnownConfig {
    Table,
    Id,
    IOSAppIds,
    AndroidPackageName,
    AndroidSha256Fingerprints,
    OpenidIssuerUrl,
    OpenidAuthorizeUrl,
    OpenidJwkUrl,
    OpenidTokenEndpoint,
    OpenidUserInfoEndpoint,
    CreatedAt,
    UpdatedAt,
}
