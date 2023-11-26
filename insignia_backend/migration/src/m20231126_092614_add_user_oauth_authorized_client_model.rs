use sea_orm_migration::prelude::*;

use crate::{m20231125_021216_add_oauth_client_model::OauthClient, m20231125_021604_add_users_oauth_consents_model::UserOauthConstent, m20220101_000001_create_table::User};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UserOauthAuthorizedClient::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserOauthAuthorizedClient::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(UserOauthAuthorizedClient::TokenKey).string().unique_key().not_null())
                    .col(ColumnDef::new(UserOauthAuthorizedClient::UserId).uuid().not_null())
                    .col(ColumnDef::new(UserOauthAuthorizedClient::OauthClientId).integer().not_null())
                    .col(ColumnDef::new(UserOauthAuthorizedClient::CreatedAt).timestamp_with_time_zone().default(Expr::current_timestamp()).not_null())
                    .foreign_key(
                        ForeignKey::create()
                        .on_delete(ForeignKeyAction::Cascade)
                        .from(UserOauthAuthorizedClient::Table, UserOauthAuthorizedClient::UserId)
                        .to(User::Table, User::Id)
                    )
                    .foreign_key(
                        ForeignKey::create()
                        .on_delete(ForeignKeyAction::Cascade)
                        .from(UserOauthAuthorizedClient::Table, UserOauthAuthorizedClient::OauthClientId)
                        .to(OauthClient::Table, OauthClient::Id)
                    )
                    .index(
                        Index::create()
                        .unique()
                        .col(UserOauthAuthorizedClient::UserId)
                        .col(UserOauthAuthorizedClient::OauthClientId)
                    )
                    .to_owned(),
            )
            .await
            .unwrap();

        manager
            .alter_table(
                Table::alter()
                    .table(UserOauthConstent::Table)
                    .drop_foreign_key(Alias::new("users_oauth_consents_user_id_fkey"))
                    .drop_foreign_key(Alias::new("users_oauth_consents_oauth_client_id_fkey"))
                    .modify_column(ColumnDef::new(UserOauthConstent::UserId).null())
                    .modify_column(ColumnDef::new(UserOauthConstent::OauthClientId).null())
                    .add_column(ColumnDef::new(Alias::new("user_oauth_authorized_client_id")).integer().not_null())
                    .add_foreign_key(
                        &TableForeignKey::new()
                            .name("users_oauth_consents_user_oauth_authorized_client_id_fkey")
                            .from_tbl(UserOauthConstent::Table)
                            .from_col(Alias::new("user_oauth_authorized_client_id"))
                            .to_tbl(UserOauthAuthorizedClient::Table)
                            .to_col(UserOauthAuthorizedClient::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                    )
                    .to_owned()
            )
            .await
            .unwrap();

        manager.create_index(
            Index::create()
                .table(UserOauthConstent::Table)
                .unique()
                .col(UserOauthConstent::OauthScopeId)
                .col(Alias::new("user_oauth_authorized_client_id"))
                .to_owned()
        )
            .await
            .unwrap();

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .table(UserOauthConstent::Table)
                    .name("users_oauth_consents_oauth_scope_id_user_oauth_authorized_c_idx")
                    .to_owned()
            )
            .await
            .unwrap();

        manager
            .alter_table(
                Table::alter()
                .table(UserOauthConstent::Table)
                .drop_column(Alias::new("user_oauth_authorized_client_id"))
                .modify_column(ColumnDef::new(UserOauthConstent::UserId).not_null())
                .modify_column(ColumnDef::new(UserOauthConstent::OauthClientId).not_null())
                .add_foreign_key(
                    &TableForeignKey::new()
                        .name("users_oauth_consents_user_id_fkey")
                        .from_tbl(UserOauthConstent::Table)
                        .from_col(UserOauthConstent::UserId)
                        .to_tbl(User::Table)
                        .to_col(User::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                )
                .add_foreign_key(
                    &TableForeignKey::new()
                        .name("users_oauth_consents_oauth_client_id_fkey")
                        .from_tbl(UserOauthConstent::Table)
                        .from_col(UserOauthConstent::OauthClientId)
                        .to_tbl(OauthClient::Table)
                        .to_col(OauthClient::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                )
                .to_owned()
            )
            .await
            .unwrap();

        manager
            .drop_table(Table::drop().table(UserOauthAuthorizedClient::Table).to_owned())
            .await
            .unwrap();

        Ok(())
    }
}

#[derive(Iden)]
#[iden(rename = "users_oauth_authorized_clients")]
enum UserOauthAuthorizedClient {
    Table,
    Id,
    UserId,
    OauthClientId,
    TokenKey,
    CreatedAt,
}
