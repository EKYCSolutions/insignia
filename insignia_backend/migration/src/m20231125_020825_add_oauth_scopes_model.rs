use sea_orm_migration::prelude::*;

use crate::m20231125_020513_add_users_permissions_model::DelegableUserPermission;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(OauthScope::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(OauthScope::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(OauthScope::Name).string().not_null())
                    .col(ColumnDef::new(OauthScope::Label).string().null())
                    .col(ColumnDef::new(OauthScope::CreatedAt).timestamp_with_time_zone().default(Expr::current_timestamp()).not_null())
                    .col(ColumnDef::new(OauthScope::DelegableUserPermissionId).integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                        .on_delete(ForeignKeyAction::Cascade)
                        .from(OauthScope::Table, OauthScope::DelegableUserPermissionId)
                        .to(DelegableUserPermission::Table, DelegableUserPermission::Id)
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(OauthScope::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
#[iden(rename = "oauth_scopes")]
pub enum OauthScope {
    Table,
    Id,
    Name,
    Label,
    DelegableUserPermissionId,
    CreatedAt,
}
