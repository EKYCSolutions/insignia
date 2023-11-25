use sea_orm_migration::prelude::*;

use crate::{m20231125_020825_add_oauth_scopes_model::OauthScope, m20231125_021216_add_oauth_client_model::OauthClient};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UserOauthConstent::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserOauthConstent::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(UserOauthConstent::OauthScopeId).integer().not_null())
                    .col(ColumnDef::new(UserOauthConstent::OauthClientId).integer().not_null())
                    .col(ColumnDef::new(UserOauthConstent::CreatedAt).timestamp_with_time_zone().default(Expr::current_timestamp()).not_null())
                    .foreign_key(
                        ForeignKey::create()
                        .on_delete(ForeignKeyAction::Cascade)
                        .from(UserOauthConstent::Table, UserOauthConstent::OauthScopeId)
                        .to(OauthScope::Table, OauthScope::Id)
                    )
                    .foreign_key(
                        ForeignKey::create()
                        .on_delete(ForeignKeyAction::Cascade)
                        .from(UserOauthConstent::Table, UserOauthConstent::OauthClientId)
                        .to(OauthClient::Table, OauthClient::Id)
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserOauthConstent::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
#[iden(rename = "users_oauth_consents")]
enum UserOauthConstent {
    Table,
    Id,
    OauthScopeId,
    OauthClientId,
    CreatedAt,
}
