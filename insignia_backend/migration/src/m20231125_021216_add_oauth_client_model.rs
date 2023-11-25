use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(OauthClient::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(OauthClient::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(OauthClient::Name).string().not_null())
                    .col(ColumnDef::new(OauthClient::Label).string().null())
                    .col(ColumnDef::new(OauthClient::ClientId).string().not_null())
                    .col(ColumnDef::new(OauthClient::ClientSecret).string().null())
                    .col(ColumnDef::new(OauthClient::AuthnFlow).string().null())
                    .col(ColumnDef::new(OauthClient::ClientType).string().not_null())
                    .col(ColumnDef::new(OauthClient::Audiences).array(ColumnType::String(Some(64))).not_null())
                    .col(ColumnDef::new(OauthClient::RedirectUris).array(ColumnType::String(Some(128))).not_null())
                    .col(ColumnDef::new(OauthClient::CreatedAt).timestamp_with_time_zone().default(Expr::current_timestamp()).not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(OauthClient::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
#[iden(rename = "oauth_clients")]
pub enum OauthClient {
    Table,
    Id,
    Name,
    Label,
    ClientId,
    ClientSecret,
    AuthnFlow,
    ClientType,
    Audiences,
    RedirectUris,
    CreatedAt,
}
