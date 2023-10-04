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
                    .table(UserWebauthnCredential::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserWebauthnCredential::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(UserWebauthnCredential::Name).string().not_null())
                    .col(ColumnDef::new(UserWebauthnCredential::CredentialId).string().not_null())
                    .col(ColumnDef::new(UserWebauthnCredential::CredentialData).json_binary().not_null())
                    .col(ColumnDef::new(UserWebauthnCredential::CreatedAt).timestamp_with_time_zone().default(Expr::current_timestamp()).not_null())
                    .col(ColumnDef::new(UserWebauthnCredential::UserId).uuid().not_null())
                    .foreign_key(
                        ForeignKey::create()
                        .on_delete(ForeignKeyAction::Cascade)
                        .from(UserWebauthnCredential::Table, UserWebauthnCredential::UserId)
                        .to(User::Table, User::Id)
                    )
                    .to_owned(),
            )
            .await?;

        manager.create_index(
            sea_query::Index::create()
            .table(UserWebauthnCredential::Table)
            .col(UserWebauthnCredential::CredentialId)
            .unique()
            .to_owned()
        ).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserWebauthnCredential::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
#[iden(rename = "users_webauthn_credentials")]
enum UserWebauthnCredential {
    Table,
    Id,
    UserId,
    Name,
    CredentialId,
    CredentialData,
    CreatedAt,
}
